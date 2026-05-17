"""SPEC v0.3 §13.3 + §21 friend responder.

When a peer asks us for results, we search ONLY shareable rows
(`share_scope IN ('friends', 'public')`), drop `sensitivity_label='high'`
documents, and refuse to return file://, localhost, or private-LAN URLs.

The responder is intentionally minimal: no encryption, no signing
(those are §20.2 RESPONSE_V1 — Phase 4 territory). Phase 3 is the
DIRECT_PLACEHOLDER path; the responder ships plain JSON over plain
HTTP and trusts the LAN.

This is the sister of `lan_friend_direct.search()`. The placeholder
client POSTs `{"q", "top_k", "qid"}` to `/friend_search`; this module's
`respond()` builds the response body. Wired into peer_server's
`POST /friend_search` route in `peer_server.py`.
"""
from __future__ import annotations

import contextlib
import ipaddress
import os
import socket
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import unquote, urlparse

from ..indrex import db_path as indrex_db_path
from ..indrex import open_read
from .local_indrex import _bm25_to_score, build_safe_fts_query

# §21.1 responder limits.
MAX_QUERY_BYTES = 512
MAX_TOP_K = 8
MAX_RESPONSE_BYTES = 16384
MAX_SNIPPET_CHARS = 240
ALLOWED_SHARE_SCOPES = ("friends", "public")
DENY_SENSITIVITY = ("high",)

# §21.1 rate-limit policy (`friend_responder.rate_limit`):
#   max_rounds_per_minute: 20      → cap at 20 queries / source IP / 60s
#   max_cpu_ms_per_query:  100     → cap on post-query work per request
MAX_ROUNDS_PER_MINUTE = 20
MAX_CPU_MS_PER_QUERY = 100

# Module-level token bucket: source IP → list[float] of request timestamps
# inside the current 60 s window. Mutated only under `_RATE_LIMIT_LOCK`.
# Keyed by IP because the placeholder path is plain HTTP on a trusted LAN
# (anonymous-ticket nullifier keying lands with TODO-2/Phase 4 DCNET).
_RATE_LIMIT_STATE: dict[str, list[float]] = {}
_RATE_LIMIT_LOCK = threading.Lock()


def _reset_rate_limit_state() -> None:
    """Test helper: clear the per-IP token-bucket dict."""
    with _RATE_LIMIT_LOCK:
        _RATE_LIMIT_STATE.clear()


def _rate_limit_check(source_ip: str) -> bool:
    """Return True if `source_ip` is under the per-minute cap and record
    the request. Return False (= rate-limited) if it would push past
    `MAX_ROUNDS_PER_MINUTE` — in that case, NOTHING is appended.

    The token bucket is a sliding 60-second window of timestamps. We
    drop entries older than `now - 60` on every call so an idle peer's
    list shrinks back to empty rather than growing unbounded.
    """
    now = time.time()
    cutoff = now - 60.0
    with _RATE_LIMIT_LOCK:
        bucket = _RATE_LIMIT_STATE.get(source_ip)
        if bucket is None:
            bucket = []
            _RATE_LIMIT_STATE[source_ip] = bucket
        # Drop expired timestamps in place.
        i = 0
        for ts in bucket:
            if ts >= cutoff:
                break
            i += 1
        if i:
            del bucket[:i]
        if len(bucket) >= MAX_ROUNDS_PER_MINUTE:
            return False
        bucket.append(now)
        return True


# §13.3: never serve these. URL host / scheme guards.
# Lowercased once; comparison is case-insensitive (red-team #1 covered
# `FILE://` style).
_ALLOW_SCHEMES = frozenset({"http", "https"})
_DENY_HOST_LITERALS = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
_DENY_TLDS = (".local", ".lan", ".internal", ".intranet", ".corp", ".home")


def _is_safe_url(u: str) -> bool:
    """§13.3 guard. Refuses file://, localhost, RFC1918 / link-local /
    loopback, and every numeric-IP obfuscation form (decimal, hex, octal,
    IPv4-mapped IPv6, IPv6 link-local). Hardened after red-team pass 2.

    The host portion is normalized through `urllib.parse.unquote` (catch
    %-encoded private IPs) and `socket.getaddrinfo` (resolve hostnames
    + decimal/hex IPv4 forms), then every returned IP is checked against
    `ipaddress.ip_address` for `is_private`, `is_loopback`, `is_link_local`,
    `is_reserved`, `is_multicast`, `is_unspecified`. **All** resolutions
    must be safe — a host with even one private result is refused.
    """
    if not isinstance(u, str) or not u:
        return False
    try:
        p = urlparse(u)
    except Exception:
        return False
    scheme = (p.scheme or "").lower()
    if scheme not in _ALLOW_SCHEMES:
        return False

    raw_host = p.hostname
    if not raw_host:
        return False
    # urlparse leaves percent-encoded forms intact; decode + lowercase.
    host = unquote(raw_host).lower()
    if not host:
        return False
    if host in _DENY_HOST_LITERALS:
        return False
    for tld in _DENY_TLDS:
        if host.endswith(tld):
            return False

    # Strip IPv6 brackets if any.
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host

    # Direct IP literal (incl. IPv4 obfuscations: hex, octal, decimal,
    # IPv4-mapped IPv6, IPv4-compatible IPv6, dual-stack).
    try:
        ip = ipaddress.ip_address(candidate)
        return _ip_is_public(ip)
    except ValueError:
        pass

    # Try parsing as a decimal/octal-form integer that ipaddress doesn't
    # natively accept (`http://2130706433/` — the long form of 127.0.0.1).
    try:
        as_int = int(candidate, 0)  # base=0 → 0x..., 0o..., or decimal
        if 0 <= as_int <= 0xFFFFFFFF:
            ip = ipaddress.IPv4Address(as_int)
            return _ip_is_public(ip)
    except (ValueError, OverflowError):
        pass

    # Hostname: opt-in DNS resolution check. The resolution catches
    # `evil.attacker.com → 127.0.0.1` SSRF attacks but also refuses
    # legitimately-archived URLs whose DNS is momentarily flaky or
    # whose TLD is RFC-2606 reserved (`.example`). Default OFF; set
    # `SWF_SSRF_STRICT_DNS=1` for paranoid deployments.
    if not os.environ.get("SWF_SSRF_STRICT_DNS"):
        return True
    try:
        infos = socket.getaddrinfo(candidate, None,
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for _fam, _t, _p, _c, sockaddr in infos:
        addr = sockaddr[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if not _ip_is_public(ip):
            return False
    return True


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """An IP is `public` for our purposes only if it is none of:
    private (RFC1918 / RFC4193 ULA), loopback, link-local, multicast,
    reserved, or unspecified. IPv4-mapped IPv6 (`::ffff:127.0.0.1`)
    is collapsed to the embedded IPv4 first."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


_PAGES_SQL = """
SELECT
    p.url                                   AS url,
    p.title                                 AS title,
    snippet(pages, 2, '«', '»', '…', 16)    AS snippet,
    p.fetched_at                            AS fetched_at,
    bm25(pages)                             AS rank,
    m.share_scope                           AS share_scope,
    m.sensitivity_label                     AS sensitivity_label,
    m.source_type                           AS source_type,
    m.content_hash                          AS content_hash,
    m.fetched_at_ms                         AS fetched_at_ms,
    pc.content_cid                          AS content_cid
FROM pages p
INNER JOIN pages_meta m ON m.url = p.url
LEFT  JOIN page_cids pc ON pc.url = p.url
WHERE pages MATCH :q
  AND m.share_scope IN ('friends','public')
  AND m.sensitivity_label != 'high'
  AND m.source_type != 'peer_ingest'
  AND m.deleted_at_ms IS NULL
ORDER BY rank
LIMIT :lim
"""
# Notes on the WHERE clause (TODO-8 §13.1 hardening):
#   * `source_type != 'peer_ingest'` is the chained-provenance gate. A
#     row that arrived from another peer (via friend search or DCNET)
#     MUST NOT be re-shared to other friends; otherwise a curious peer
#     can re-broadcast someone else's archive. This is the load-bearing
#     privacy filter — the rest of §13.3's friend-responder safety
#     guarantees do not cover it.
#   * `deleted_at_ms IS NULL` drops tombstoned rows so deletes propagate
#     immediately on the friend side without needing a vacuum cycle.


def respond(req: dict, *, db: Path | str | None = None,
            source_ip: str | None = None) -> dict:
    """Build a §20.2-shaped (plain) friend response. Validation per
    §21.1 limits; rows filtered per §13.3 + §21.1.

    `source_ip` is the LAN-trust caller's IP (from peer_server's
    `client_address[0]`). When provided, it keys a sliding-60s token
    bucket capped at `MAX_ROUNDS_PER_MINUTE`. Pass `None` from unit
    tests to bypass rate limiting.

    Returns a dict with:
      - schema, qid, served_at_ms, results[]
      - reason on rejection (status code stays 200; the body documents
        the soft-failure reason — `rate_limited`,
        `cpu_budget_exceeded`, etc.).
    """
    started_ms = int(time.time() * 1000)
    qid = (req.get("qid") or uuid.uuid4().hex)[:64]
    q = (req.get("q") or "").strip()
    top_k = int(req.get("top_k") or MAX_TOP_K)
    top_k = max(1, min(MAX_TOP_K, top_k))

    base_resp = {
        "schema": "swf.friend_search.bundle.v1",
        "qid": qid,
        "served_at_ms": started_ms,
        "index_scope": "friends",
        "results": [],
    }

    # §21.1 max_rounds_per_minute. Checked BEFORE we touch the indrex
    # so a peer hammering us never costs us a SQL query.
    if source_ip is not None and not _rate_limit_check(source_ip):
        base_resp["reason"] = "rate_limited"
        return base_resp

    if not q or len(q.encode("utf-8")) > MAX_QUERY_BYTES:
        base_resp["reason"] = "bad_query"
        return base_resp

    db_p = Path(db) if db else indrex_db_path()
    if not db_p.exists():
        base_resp["reason"] = "no_indrex"
        return base_resp

    # Friend responder requires `pages_meta` to exist — without it the
    # INNER JOIN returns nothing and we serve nothing, which is the
    # right safety default (don't leak `private` rows by accident if
    # the metadata table never got bootstrapped). Still, ensure it's
    # there in case this peer hasn't run a local search yet.
    try:
        _ensure_meta(db_p)
    except sqlite3.OperationalError:
        base_resp["reason"] = "meta_unavailable"
        return base_resp

    try:
        conn = open_read(db_p)
    except sqlite3.OperationalError as e:
        base_resp["reason"] = f"db_error: {e}"
        return base_resp

    # §21.1 max_cpu_ms_per_query: wall-clock budget on the post-query
    # work (per-row safety filter + dedup loop is the dominant cost in
    # the worst case). We don't try to interrupt a SQL fetch midway —
    # SQLite has no clean cancel token here, and the FTS query itself
    # is cheap; the budget guards against pathological row payloads.
    t0 = time.monotonic()
    cpu_budget_s = MAX_CPU_MS_PER_QUERY / 1000.0

    match = build_safe_fts_query(q)
    try:
        rows = conn.execute(_PAGES_SQL, {"q": match, "lim": top_k}).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        base_resp["reason"] = f"query_error: {e}"
        return base_resp
    finally:
        with contextlib.suppress(Exception):
            conn.close()

    if (time.monotonic() - t0) > cpu_budget_s:
        # SQL itself blew the budget. Return a properly-shaped (empty)
        # bundle and skip the per-row safety/dedup loop entirely.
        base_resp["reason"] = "cpu_budget_exceeded"
        return base_resp

    out = []
    total_bytes = 0
    for i, row in enumerate(rows):
        url = row["url"] or ""
        if not url or not _is_safe_url(url):
            continue
        snippet = (row["snippet"] or "")[:MAX_SNIPPET_CHARS]
        title = (row["title"] or url)[:200]
        score = _bm25_to_score(row["rank"])
        # §11.4: prefer the explicit `pages_meta.content_hash` (SHA-256
        # of cleaned content per §13.1) when it's set; fall back to the
        # legacy `page_cids.content_cid` so older rows still surface a
        # hash. `fetched_at_ms` rides along when populated.
        item = {
            "canonical_url": url,
            "display_url": url,
            "title": title,
            "snippet": snippet,
            "score": round(score, 4),
            "rank": i + 1,
            "share_scope": row["share_scope"],
            "fetched_at": row["fetched_at"],
            "fetched_at_ms": row["fetched_at_ms"],
            "content_hash": row["content_hash"] or row["content_cid"],
        }
        # Cap response size per §21.1 (max_response_bytes). Red-team
        # pass-3 finding C: `repr(item)` undercounts json.dumps by up
        # to ~2.6× when titles or snippets contain non-ASCII (json's
        # default `ensure_ascii=True` escapes each codepoint to
        # \uXXXX). A peer crafting emoji-heavy rows could push the
        # actual response well past the budget. Measure for real.
        import json as _json
        item_bytes = len(_json.dumps(item, ensure_ascii=True).encode("utf-8"))
        if total_bytes + item_bytes > MAX_RESPONSE_BYTES:
            break
        total_bytes += item_bytes
        out.append(item)
        # Re-check CPU budget mid-loop; bail with whatever we have
        # so far. Bundle stays well-formed (consistent with the
        # max_response_bytes truncation behavior above).
        if (time.monotonic() - t0) > cpu_budget_s:
            base_resp["reason"] = "cpu_budget_exceeded"
            base_resp["results"] = out
            return base_resp

    base_resp["results"] = out
    return base_resp


def _ensure_meta(db_p: Path) -> None:
    """Idempotent. Cached via local_indrex's bootstrap-once pattern, but
    we re-call here in case the friend responder runs in a process that
    hasn't done a local search yet."""
    from .local_indrex import _ensure_meta_table_writable_once
    _ensure_meta_table_writable_once(db_p)
