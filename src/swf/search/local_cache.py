"""SPEC v0.3 §12 + §29.4 local cache.

HMAC-keyed result-bundle cache. Cache entries record the *origin* path
the results came from (per §5: a cache replaying a public result must
disclose that). The router consults `policy.cache.allowed_origin_paths`
before returning a hit so a tightened policy can't silently replay a
result that came in under a looser one.

Storage: SQLite at `~/.local/share/swf/search_cache.db`. The HMAC secret
lives at `~/.config/swf/cache_secret.bin` mode 0600, generated on first
use. Persistent — distinct from the per-process secret in `query.py`,
because cache lookups need cross-process stability.
"""
from __future__ import annotations

import contextlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .query import hmac_query
from .response import (
    DeliveryPath,
    OriginPath,
    SearchAttempt,
    SearchResult,
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)

# §12.3 default TTLs in hours.
DEFAULT_TTL_HOURS: dict[OriginPath, int] = {
    OriginPath.LOCAL_INDREX: 168,
    OriginPath.LAN_FRIEND_DCNET: 24,
    OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER: 24,
    OriginPath.SELF_PUBLIC_EGRESS: 12,
}
DEFAULT_FALLBACK_TTL_HOURS = 24


_CREATE = """
CREATE TABLE IF NOT EXISTS cache_entries (
    query_hmac          TEXT PRIMARY KEY,
    schema              TEXT NOT NULL,
    normalized_query_len INTEGER NOT NULL,
    created_ms          INTEGER NOT NULL,
    expires_ms          INTEGER NOT NULL,
    delivery_path_when_cached TEXT NOT NULL,
    origin_paths_json   TEXT NOT NULL,
    dominant_origin_path TEXT NOT NULL,
    privacy_level_when_cached TEXT NOT NULL,
    results_json        TEXT NOT NULL,
    warnings_json       TEXT NOT NULL DEFAULT '[]'
)
"""


def db_path() -> Path:
    """Cache DB. Sibling of community.db. Parent dir is mode 0700."""
    from ..paths import ensure_dir, state_dir
    env = os.environ.get("SWF_CACHE_DB")
    if env:
        p = Path(env)
        ensure_dir(p.parent)
    else:
        p = state_dir() / "search_cache.db"
    return p


def secret_path() -> Path:
    """HMAC secret file. Parent dir is mode 0700; file itself is 0600."""
    from ..paths import config_dir, ensure_dir
    env = os.environ.get("SWF_CACHE_SECRET_FILE")
    if env:
        p = Path(env)
        ensure_dir(p.parent)
    else:
        p = config_dir() / "cache_secret.bin"
    return p


def _load_or_create_secret() -> bytes:
    """Persistent HMAC key. Generated on first use; mode 0600.

    Red-team #5: ensure mode 0600 even on the read path (a stale
    world-readable file from a backup or older code path is silently
    repaired). #6: avoid the TOCTOU on first run by using O_EXCL — only
    one process wins the create; the rest read what's there.
    """
    p = secret_path()
    if p.exists():
        # Repair permissions if the file ended up world-readable.
        try:
            mode = p.stat().st_mode & 0o777
            if mode & 0o077:
                os.chmod(p, 0o600)
        except OSError:
            pass
        return p.read_bytes()
    # First-run create. O_EXCL guarantees only one process writes the
    # canonical secret; everyone else falls through to the read path.
    secret = secrets.token_bytes(32)
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, secret)
        finally:
            os.close(fd)
    except FileExistsError:
        # Another process won the race; just read their version.
        pass
    except OSError:
        # Filesystem refused (read-only fs, EACCES). Fall through to
        # whatever read returns; if the file isn't there, we'll surface
        # the error to the caller.
        pass
    return p.read_bytes()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=2.0)
    conn.row_factory = sqlite3.Row
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE)
    return conn


def query_hmac_for(normalized_query: str) -> str:
    """Wraps `query.hmac_query` with the persistent cache secret."""
    return hmac_query(normalized_query, secret=_load_or_create_secret())


@dataclass
class CacheResultSet:
    """Internal wrapper passed up to the router."""
    results: list[SearchResult]
    origin_paths: list[OriginPath]
    dominant_origin_path: OriginPath | None
    privacy_level_when_cached: str | None
    warnings: list[str]
    attempt: SearchAttempt


def lookup(
    normalized_query: str,
    *,
    allowed_origin_paths: tuple[OriginPath, ...] | list[OriginPath],
) -> CacheResultSet:
    """Check the cache. If a non-expired entry exists AND its origin
    intersects `allowed_origin_paths`, return its results. Otherwise an
    empty result-set with a `miss`/`expired`/`origin_not_allowed` reason."""
    started_ms = int(time.time() * 1000)

    def _attempt(*, status: str, reason: str = "", count: int = 0) -> SearchAttempt:
        c = int(time.time() * 1000)
        return SearchAttempt(
            path=DeliveryPath.LOCAL_CACHE,
            status=status, started_ms=started_ms, completed_ms=c,
            duration_ms=c - started_ms, reason=reason,
            results_count=count, network_used=False,
            public_egress_used=False,
        )

    if not normalized_query:
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss", reason="empty_query"))

    qh = query_hmac_for(normalized_query)
    try:
        conn = _connect()
    except sqlite3.OperationalError as e:
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="error", reason=f"open: {e}"))

    try:
        row = conn.execute(
            "SELECT * FROM cache_entries WHERE query_hmac=?", (qh,)
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss", reason="not_in_cache"))

    now = int(time.time() * 1000)
    if row["expires_ms"] <= now:
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss", reason="expired"))

    try:
        cached_origins = [OriginPath(p) for p in json.loads(row["origin_paths_json"])]
    except (ValueError, json.JSONDecodeError):
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss", reason="malformed_entry"))

    # Strict subset check (red-team finding #2). The previous logic accepted
    # any entry whose origin set INTERSECTED the policy's allow-list, then
    # returned every cached result regardless of origin. That meant a
    # tightened policy could replay public-tainted entries that a looser
    # earlier policy stored. Refuse the entry unless every cached origin is
    # explicitly allowed.
    allowed = set(allowed_origin_paths)
    if not set(cached_origins).issubset(allowed):
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss",
                                       reason="origin_not_allowed_by_policy"))

    try:
        results_raw = json.loads(row["results_json"])
        warnings = json.loads(row["warnings_json"] or "[]")
    except json.JSONDecodeError as e:
        return CacheResultSet([], [], None, None, [],
                              _attempt(status="miss", reason=f"malformed_results: {e}"))

    rebuilt: list[SearchResult] = []
    for r in results_raw:
        try:
            res = _rebuild_result(r)
        except (KeyError, ValueError):
            continue  # one bad row shouldn't poison the whole entry
        # Belt-and-suspenders: even after the issubset check above, drop
        # any per-result whose origin somehow falls outside the allow-list
        # (would only happen if the cache row stored result-level origins
        # that disagree with its own origin_paths field).
        if res.origin_path not in allowed:
            continue
        rebuilt.append(res)

    return CacheResultSet(
        results=rebuilt,
        origin_paths=cached_origins,
        dominant_origin_path=OriginPath(row["dominant_origin_path"]),
        privacy_level_when_cached=row["privacy_level_when_cached"],
        warnings=warnings,
        attempt=_attempt(status="ok", count=len(rebuilt)),
    )


def store(
    normalized_query: str,
    *,
    delivery_path: DeliveryPath,
    origin_paths: list[OriginPath],
    dominant_origin_path: OriginPath,
    privacy_level: str,
    results: list[SearchResult],
    warnings: list[str] | None = None,
    ttl_hours: int | None = None,
) -> None:
    """Cache a result bundle. The router calls this after a non-cache route
    succeeds. TTL defaults to §12.3's per-origin schedule unless explicit."""
    if not normalized_query or not results:
        return
    qh = query_hmac_for(normalized_query)
    if ttl_hours is None:
        # Red-team pass-3 finding B: when origin_paths is a mixed set
        # (e.g. [LOCAL_INDREX, LAN_FRIEND_DCNET]), use the SHORTEST
        # per-origin TTL. Otherwise the friend rows persist past
        # their natural 24h lifetime under the indrex-dominant 168h
        # bucket. No mixed-origin route ships today, but the cache
        # contract is the same as Phase 4+ will use.
        per_origin = [
            DEFAULT_TTL_HOURS.get(p, DEFAULT_FALLBACK_TTL_HOURS)
            for p in (origin_paths or [dominant_origin_path])
        ]
        ttl_hours = min(per_origin) if per_origin else DEFAULT_FALLBACK_TTL_HOURS
    now_ms = int(time.time() * 1000)
    expires = now_ms + ttl_hours * 3600 * 1000
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return  # cache is best-effort
    try:
        conn.execute(
            """INSERT OR REPLACE INTO cache_entries
                (query_hmac, schema, normalized_query_len, created_ms,
                 expires_ms, delivery_path_when_cached, origin_paths_json,
                 dominant_origin_path, privacy_level_when_cached,
                 results_json, warnings_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                qh, "swf.cache_entry.v1",
                len(normalized_query),
                now_ms, expires,
                delivery_path.value,
                json.dumps([p.value for p in origin_paths]),
                dominant_origin_path.value,
                privacy_level,
                json.dumps([_serialize_result(r) for r in results]),
                json.dumps(warnings or []),
            ),
        )
        conn.commit()
    finally:
        conn.close()


# Pass-3 finding A: reputation is local-only and MUST NOT persist to
# the cache. Pass-4 finding #3 hardened the strip from a denylist to
# an explicit allowlist so future additions to `_Provider` (e.g.
# `last_clicked_ms`, `provider_trust_pin`, anonymous receipt counters)
# can't silently land on disk. Anything not in this allowlist is
# dropped before json.dumps.
_PROVIDER_PERSIST_FIELDS = ("provider_pubkey", "provider_label")
_FRESHNESS_PERSIST_FIELDS = (
    "fetched_at_ms", "indexed_at_ms", "served_at_ms", "staleness_days",
)
_VERIFICATION_PERSIST_FIELDS = (
    "verified_slice", "content_hash", "merkle_root", "inclusion_proof",
    "sigchain_head", "dsse_attestation", "verification_status",
)
_RECEIPT_PERSIST_FIELDS = (
    "receipt_eligible", "service_proof_hash", "receipt_challenge",
)
_SAFETY_PERSIST_FIELDS = (
    "html_sanitized", "url_validated", "share_scope",
)


def _allowlist(d: dict, fields: tuple[str, ...]) -> dict:
    """Return a fresh dict containing only `fields` from `d`. Missing
    fields are simply absent (callers tolerate that; rebuild fills in
    the dataclass defaults)."""
    return {k: d[k] for k in fields if k in d}


def _serialize_result(r: SearchResult) -> dict:
    return {
        "result_id": r.result_id,
        "canonical_url": r.canonical_url,
        "display_url": r.display_url,
        "title": r.title,
        "snippet": r.snippet,
        "score": r.score,
        "rank": r.rank,
        "delivery_path": r.delivery_path.value,
        "origin_path": r.origin_path.value,
        "source": r.source,
        "provider": _allowlist(r.provider.__dict__, _PROVIDER_PERSIST_FIELDS),
        "freshness": _allowlist(r.freshness.__dict__, _FRESHNESS_PERSIST_FIELDS),
        "verification": _allowlist(r.verification.__dict__,
                                   _VERIFICATION_PERSIST_FIELDS),
        "receipt": _allowlist(r.receipt.__dict__, _RECEIPT_PERSIST_FIELDS),
        "safety": _allowlist(r.safety.__dict__, _SAFETY_PERSIST_FIELDS),
    }


def _rebuild_result(d: dict) -> SearchResult:
    return SearchResult(
        result_id=d.get("result_id") or f"res_{uuid.uuid4().hex[:24]}",
        canonical_url=d["canonical_url"],
        display_url=d.get("display_url", d["canonical_url"]),
        title=d.get("title", ""),
        snippet=d.get("snippet", ""),
        score=float(d.get("score", 0.0)),
        rank=int(d.get("rank", 0)),
        # On cache replay, delivery_path becomes LOCAL_CACHE (this is the
        # current request's delivery), but origin_path keeps the original.
        delivery_path=DeliveryPath.LOCAL_CACHE,
        origin_path=OriginPath(d["origin_path"]),
        source=d.get("source", ""),
        provider=_Provider(**d.get("provider", {})),
        freshness=_Freshness(**d.get("freshness", {})),
        verification=_Verification(**d.get("verification", {})),
        receipt=_Receipt(**d.get("receipt", {})),
        safety=_Safety(**d.get("safety", {})),
    )


def vacuum_expired() -> int:
    """Drop expired entries + truncate WAL. Cheap; safe to call from a
    cron-style hook. Resource audit F3 + F4: WAL checkpoint runs after
    the DELETE so the on-disk file doesn't grow unbounded between
    SQLite's automatic checkpoints (which can be skipped under
    long-running readers)."""
    now = int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return 0
    try:
        cur = conn.execute("DELETE FROM cache_entries WHERE expires_ms <= ?", (now,))
        conn.commit()
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return cur.rowcount
    finally:
        conn.close()
