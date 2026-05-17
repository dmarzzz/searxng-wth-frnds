"""SPEC v0.3 §13 + §29.5 local indrex search.

Reads the existing `pages` FTS5 virtual table written by
`swf.web.index` (and indirectly by every fetch path) and the
sidecar `pages_meta` carrying §13.1's `share_scope` /
`sensitivity_label`. Returns a list of `SearchResult` carrying §11.4
metadata, with bm25 normalized into a `[0, 1]` score where higher = better.

This module DOES NOT enforce friend-responder filtering. The local user
is allowed to search their own archive regardless of share_scope. The
friend route in a later phase will use `friend_search()` which adds the
restrictive WHERE clause.
"""
from __future__ import annotations

import contextlib
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..indrex import db_path as indrex_db_path
from ..indrex import open_read
from . import migration
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


@dataclass
class IndrexResultSet:
    """Internal result-set wrapper passed up to the router."""
    results: list[SearchResult]
    attempt: SearchAttempt


def build_safe_fts_query(q: str) -> str:
    """§13.4. Conservative FTS5 MATCH — AND-join whitespace tokens, quote
    each to neutralize boolean / NEAR / prefix / column syntax. Does not
    expose advanced FTS5 features by default."""
    tokens = [t for t in (q or "").split() if t]
    if not tokens:
        return '""'
    # Strip embedded double-quotes so the wrapper isn't broken by user
    # input. Tokens are then phrase-quoted and AND-joined.
    safe = []
    for t in tokens:
        # Drop FTS5 prefix/operator chars that survive even inside a phrase
        # quote (FTS5 treats `"foo*"` as a phrase ending in `*` by default,
        # which is fine — but we don't want the user to opt into prefix
        # search by accident). We strip a final `*` and any leading `^`/`-`
        # which mean "must" / "must not" outside phrases.
        cleaned = t.replace('"', "").lstrip("^-").rstrip("*")
        if cleaned:
            safe.append(f'"{cleaned}"')
    if not safe:
        return '""'
    return " AND ".join(safe)


def _bm25_to_score(rank: float) -> float:
    """SQLite FTS5 bm25() returns *negative* numbers — lower is better.
    Map onto (0, 1] with `1 / (1 + |rank|)` so 1.0 = perfect, asymptotic
    toward 0 as relevance falls. This matches §11.4's `score: 0.82`-style
    examples and §14.1's score thresholds."""
    return 1.0 / (1.0 + abs(rank))


_PAGES_SQL = """
SELECT
    p.url                                  AS url,
    p.title                                AS title,
    snippet(pages, 2, '«', '»', '…', 20)   AS snippet,
    p.fetched_at                           AS fetched_at,
    bm25(pages)                            AS rank,
    COALESCE(m.share_scope,       'private')        AS share_scope,
    COALESCE(m.sensitivity_label, 'unknown')        AS sensitivity_label,
    COALESCE(m.source_type,       'user_fetched')   AS source_type,
    m.content_hash                          AS content_hash,
    m.fetched_at_ms                         AS fetched_at_ms,
    m.deleted_at_ms                         AS deleted_at_ms,
    pc.content_cid                          AS content_cid
FROM pages p
LEFT JOIN pages_meta m ON m.url = p.url
LEFT JOIN page_cids  pc ON pc.url = p.url
WHERE pages MATCH :q
  AND (m.deleted_at_ms IS NULL)
ORDER BY rank
LIMIT :lim
"""


def _host_of(url: str) -> str:
    """Best-effort host extract for §11.4 display_url."""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


def _display_url(url: str) -> str:
    h = _host_of(url)
    if not h:
        return url
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        return f"{h}{path}".rstrip("/")
    except Exception:
        return h


def search(
    q: str,
    *,
    top_k: int = 10,
    db: Path | str | None = None,
) -> IndrexResultSet:
    """Search the LOCAL_INDREX. Always returns an IndrexResultSet (with
    an empty `results` list on miss / error) plus a SearchAttempt
    annotated with timing and reason."""
    started_ms = int(time.time() * 1000)

    def _attempt(*, status: str, reason: str = "", count: int = 0) -> SearchAttempt:
        completed = int(time.time() * 1000)
        return SearchAttempt(
            path=DeliveryPath.LOCAL_INDREX,
            status=status,
            started_ms=started_ms,
            completed_ms=completed,
            duration_ms=completed - started_ms,
            reason=reason,
            results_count=count,
            network_used=False,
            public_egress_used=False,
        )

    q = (q or "").strip()
    if not q:
        return IndrexResultSet([], _attempt(status="empty_query"))

    db_p = Path(db) if db else indrex_db_path()
    if not db_p.exists():
        return IndrexResultSet([], _attempt(status="no_indrex", reason="db_missing"))

    # Bootstrap the pages_meta sidecar exactly once per (process, db_path).
    # Doing this on every search call would race with swf.web.index's
    # writer for the same DB and burn time on a redundant CREATE TABLE
    # IF NOT EXISTS — see architecture review §8.
    try:
        _ensure_meta_table_writable_once(db_p)
    except sqlite3.OperationalError as e:
        return IndrexResultSet([], _attempt(status="error", reason=f"meta: {e}"))

    try:
        conn = open_read(db_p)
    except sqlite3.OperationalError as e:
        return IndrexResultSet([], _attempt(status="error", reason=f"open: {e}"))

    match = build_safe_fts_query(q)
    lim = max(1, min(top_k, 50))
    try:
        rows = conn.execute(_PAGES_SQL, {"q": match, "lim": lim}).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        return IndrexResultSet([], _attempt(status="error", reason=f"query: {e}"))
    finally:
        with contextlib.suppress(Exception):
            conn.close()

    out: list[SearchResult] = []
    for i, row in enumerate(rows):
        url = row["url"] or ""
        if not url:
            continue
        score = _bm25_to_score(row["rank"])
        # §11.4 freshness.fetched_at_ms — populated when the writer
        # (swf.web or a manual import path) called set_meta with
        # an integer ms-epoch. The string `pages.fetched_at` ISO8601 is
        # left untouched; consumers that want it can parse it themselves.
        # §11.4 verification.content_hash — prefer the explicit
        # `pages_meta.content_hash` (SHA-256 of cleaned content per
        # §13.1) when set; fall back to the legacy `page_cids.content_cid`
        # sidecar so existing rows still surface a hash.
        meta_content_hash = row["content_hash"]
        sr = SearchResult(
            result_id=f"res_{uuid.uuid4().hex[:24]}",
            canonical_url=url,
            display_url=_display_url(url),
            title=(row["title"] or url)[:200],
            snippet=(row["snippet"] or "")[:400],
            score=round(score, 4),
            rank=i + 1,
            delivery_path=DeliveryPath.LOCAL_INDREX,
            origin_path=OriginPath.LOCAL_INDREX,
            source="local_pages",
            provider=_Provider(),  # local archive has no peer provider
            freshness=_Freshness(
                fetched_at_ms=row["fetched_at_ms"],
            ),
            verification=_Verification(
                content_hash=(meta_content_hash
                              if meta_content_hash
                              else (row["content_cid"] if row["content_cid"] else None)),
                verification_status="local_trust",
            ),
            receipt=_Receipt(receipt_eligible=False),
            safety=_Safety(
                html_sanitized=True,
                url_validated=True,
                share_scope=row["share_scope"] or "private",
            ),
        )
        out.append(sr)

    return IndrexResultSet(
        results=out,
        attempt=_attempt(status="ok", count=len(out)),
    )


_meta_bootstrap_lock = threading.Lock()
_meta_bootstrap_done: set[str] = set()


def _ensure_meta_table_writable_once(db_p: Path) -> None:
    """Same as _ensure_meta_table_writable but caches the result per
    (process, db_path) so we only take the write lock on the first call.
    A search-call hot path can safely fast-return."""
    key = str(db_p.resolve())
    # Fast path: no lock needed once we've done it.
    if key in _meta_bootstrap_done:
        return
    with _meta_bootstrap_lock:
        if key in _meta_bootstrap_done:
            return
        _ensure_meta_table_writable(db_p)
        _meta_bootstrap_done.add(key)


def _ensure_meta_table_writable(db_p: Path) -> None:
    """Open the indrex DB read-write, create `pages_meta` if missing,
    close. Cheap (idempotent). Direct callers exist for tests and for
    boot-time bootstrap — production code paths should use the cached
    `_ensure_meta_table_writable_once`."""
    conn = sqlite3.connect(str(db_p), timeout=2.0)
    try:
        with contextlib.suppress(sqlite3.DatabaseError):
            conn.execute("PRAGMA journal_mode=WAL")
        migration.ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()
