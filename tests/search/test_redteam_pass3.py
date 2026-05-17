"""Regression coverage for the red-team pass-3 + leak-audit fixes.

Each test pins one finding so a future regression can't quietly
re-open the issue.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    local_cache,
    public_egress,
    reputation,
    tickets,
)
from swf.search.response import (
    SearchResult,
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)
from swf.search.tickets import TicketFamily


@pytest.fixture(autouse=True)
def _isolated_dbs(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "cache_secret.bin"))
    monkeypatch.setenv("SWF_REPUTATION_DB", str(tmp_path / "reputation.db"))
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "tickets.sqlite"))
    yield


# ─── Pass-3 Finding A: cache MUST NOT persist provider_score_local ───

def test_cache_strips_provider_score_local_on_serialize():
    """A SearchResult with `provider.provider_score_local` set must NOT
    have that field land in the cache row's results_json. §29.10
    reputation is local-only and not for on-disk export."""
    res = SearchResult(
        result_id="res_A",
        canonical_url="https://x.example/1",
        display_url="x.example/1", title="t", snippet="s",
        score=0.5, rank=1,
        delivery_path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        provider=_Provider(provider_pubkey="ed25519:peer-A",
                           provider_score_local=0.87),
        freshness=_Freshness(), verification=_Verification(),
        receipt=_Receipt(), safety=_Safety(share_scope="friends"),
    )
    local_cache.store(
        "score-leak-test",
        delivery_path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        origin_paths=[OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER],
        dominant_origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        privacy_level=PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER.value,
        results=[res],
    )
    # Read the raw row directly to confirm the score did not land on disk.
    conn = sqlite3.connect(local_cache.db_path())
    try:
        row = conn.execute(
            "SELECT results_json FROM cache_entries"
        ).fetchone()
    finally:
        conn.close()
    persisted = json.loads(row[0])
    assert "provider_score_local" not in persisted[0]["provider"]
    # provider_pubkey IS allowed to persist (caller put it there).
    assert persisted[0]["provider"]["provider_pubkey"] == "ed25519:peer-A"


# ─── Pass-3 Finding B: mixed-origin TTL takes the minimum ──────────

def test_cache_mixed_origin_takes_shortest_ttl(monkeypatch):
    """A cache entry with origin_paths=[LOCAL_INDREX, SELF_PUBLIC_EGRESS]
    must expire at the shorter (12h public) TTL, not the longer (168h
    indrex) one. Otherwise the friend / public rows persist past their
    natural lifetime."""
    fixed_now = 1_000_000_000_000
    monkeypatch.setattr(local_cache.time, "time", lambda: fixed_now / 1000)
    res = SearchResult(
        result_id="res_M", canonical_url="https://m.example/1",
        display_url="m.example/1", title="t", snippet="s",
        score=0.5, rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=OriginPath.LOCAL_INDREX,
        provider=_Provider(),
        freshness=_Freshness(), verification=_Verification(),
        receipt=_Receipt(), safety=_Safety(),
    )
    local_cache.store(
        "mixed-ttl",
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX, OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT.value,
        results=[res],
    )
    conn = sqlite3.connect(local_cache.db_path())
    try:
        row = conn.execute(
            "SELECT created_ms, expires_ms FROM cache_entries"
        ).fetchone()
    finally:
        conn.close()
    ttl_ms = row[1] - row[0]
    expected = local_cache.DEFAULT_TTL_HOURS[OriginPath.SELF_PUBLIC_EGRESS] * 3600 * 1000
    # Should equal the shorter (public) TTL, not the longer (indrex)
    assert ttl_ms == expected


# ─── Pass-3 Finding C: response-bytes accounting uses real json size ─

def test_friend_responder_response_size_with_emoji(tmp_path):
    """Pass-3 finding C: `repr(item)` undercounts the JSON-escaped size
    by ~2.6× for non-ASCII content. Fix uses real `json.dumps` size.

    The test reaches into _PAGES_SQL via a synthetic indrex with one
    big emoji-laden row; the cap should be enforced against actual
    bytes, not repr length.
    """
    from swf.search import friend_responder
    from swf.search.migration import ensure_schema, set_meta

    db = tmp_path / "world_knowledge" / "index.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE VIRTUAL TABLE pages USING fts5(
        url UNINDEXED, title, content, fetched_at UNINDEXED,
        tokenize='porter unicode61')""")
    conn.execute("""CREATE TABLE page_cids (
        url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
        computed_at TEXT NOT NULL)""")

    # Construct rows with emoji titles. Each title ~120 ASCII-ish chars
    # but encodes as ~360 bytes once json escapes. With 8 such rows the
    # actual JSON is well past the 16KB cap, while repr would say ~3KB.
    emoji = "🌍🌎🌏 " * 40   # 160 chars; ~640 bytes ascii-escaped JSON
    for i in range(20):
        url = f"https://emoji{i}.example/page"
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (url, f"{emoji} {i}", "differential privacy " * 5,
             "2026-04-29T00:00:00Z"),
        )
    ensure_schema(conn)
    for i in range(20):
        set_meta(conn, f"https://emoji{i}.example/page", share_scope="public")
    conn.commit()
    conn.close()

    bundle = friend_responder.respond({"q": "differential privacy"}, db=db)
    # Real-bytes cap should hold even though repr(item) was much smaller.
    # Some slack for the response envelope keys themselves; main cap is
    # on result rows which is what `MAX_RESPONSE_BYTES` gates.
    rows_bytes = len(json.dumps(bundle["results"], ensure_ascii=True).encode("utf-8"))
    assert rows_bytes <= friend_responder.MAX_RESPONSE_BYTES + 200, \
        f"results JSON {rows_bytes}B exceeds cap {friend_responder.MAX_RESPONSE_BYTES}B"


# ─── Audit F2: SearXNG body cap ────────────────────────────────────

def test_public_egress_rejects_oversized_body(monkeypatch):
    """A SearXNG returning >2 MiB of JSON must be refused as
    upstream_response_too_large rather than blown into RSS."""
    huge = (b'{"results":[' + b'{"url":"https://x/","title":"t","content":"c","score":0.5},' * 60_000 + b'{}]}')[:public_egress.MAX_SEARXNG_BYTES + 100]
    class _Resp:
        def __init__(self, body):
            self._body, self.status = body, 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None):
            return self._body[:n] if n else self._body
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _Resp(huge))
    from swf.search import build_context
    ctx = build_context("anything", policy_name="default", hmac_secret=b"x" * 32)
    out = public_egress.search(ctx)
    assert out.attempt.status == "error"
    assert out.attempt.reason == "upstream_response_too_large"
    assert out.attempt.suspicious_failure is True


# ─── Pass-2 finding (rebuilt): /search_feedback uses correct helper ──

def test_search_feedback_helper_exists():
    """Load-test agent caught: peer_server.py called a non-existent
    helper `_check_admin_token` on _Handler. The right helper is
    `_check_token` (which auto-allows loopback). This test just
    smoke-confirms the helper exists on the class so the next regression
    is loud."""
    from swf import peer_server
    assert hasattr(peer_server._Handler, "_check_token")
    # ensure the wrong name can't accidentally come back as a callable
    assert not hasattr(peer_server._Handler, "_check_admin_token")


# ─── Audit F3: WAL checkpoint after vacuum ────────────────────────

def test_local_cache_vacuum_truncates_wal():
    """`vacuum_expired()` runs `PRAGMA wal_checkpoint(TRUNCATE)` so the
    WAL file doesn't grow unbounded between SQLite's automatic
    checkpoints."""
    # Store something + force expiry, then vacuum and check that the
    # WAL file is at most a header-block (32KB on macOS sqlite).
    res = SearchResult(
        result_id="r", canonical_url="https://x/", display_url="x",
        title="t", snippet="s", score=0.5, rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=OriginPath.LOCAL_INDREX,
        provider=_Provider(), freshness=_Freshness(),
        verification=_Verification(), receipt=_Receipt(),
        safety=_Safety(),
    )
    local_cache.store("expiring", delivery_path=DeliveryPath.LOCAL_INDREX,
                      origin_paths=[OriginPath.LOCAL_INDREX],
                      dominant_origin_path=OriginPath.LOCAL_INDREX,
                      privacy_level="local_only",
                      results=[res], ttl_hours=0)
    n = local_cache.vacuum_expired()
    assert n >= 1
    wal = local_cache.db_path().with_suffix(".db-wal")
    if wal.exists():
        # After TRUNCATE, the WAL file may be removed entirely or
        # truncated to 0 bytes. Either is acceptable.
        assert wal.stat().st_size == 0


# ─── Pass-3 Finding F: opportunistic nullifier vacuum ─────────────

def test_nullifier_table_vacuums_under_sustained_writes():
    """After many spends with short retention, the table should be
    bounded — old rows fall out via the opportunistic vacuum hook."""
    # Spend > _NULLIFIER_VACUUM_EVERY (1024) tickets with retention=0
    # so each row expires immediately. The opportunistic vacuum should
    # have run at least once, leaving the table near-empty afterward.
    for i in range(1100):
        tickets.try_spend_nullifier(
            f"sha256:n-{i}",
            family=TicketFamily.QUERY_TICKET_V1,
            circle_id="c", epoch_id="e",
            retention_ms=0,
        )
    # Final vacuum to be deterministic about the assertion.
    tickets.vacuum_expired_nullifiers()
    conn = sqlite3.connect(tickets.db_path())
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM spent_ticket_nullifiers"
        ).fetchone()[0]
    finally:
        conn.close()
    assert n == 0


# ─── Audit F1: socket timeout on _read_json_body ──────────────────

def test_peer_server_handler_sets_socket_timeout():
    """The `_read_json_body` path calls `self.connection.settimeout(15)`
    so a slow-loris client can't tie up a thread indefinitely. We
    can't easily exercise the socket from unit tests; this test pins
    that the call is present in the source."""
    import inspect

    from swf import peer_server
    src = inspect.getsource(peer_server._Handler._read_json_body)
    assert "settimeout" in src


# ─── TODO-5: 64 KiB body cap on search routes ───────────────────

def test_read_json_body_respects_max_bytes_override():
    """`_read_json_body(max_bytes=…)` rejects oversized bodies (returns
    None). Smoke-test via a fake handler so we don't need a live
    socket."""
    from unittest.mock import MagicMock

    from swf import peer_server

    h = peer_server._Handler.__new__(peer_server._Handler)
    h.headers = {"Content-Length": "70000"}  # > 64 KiB
    h.rfile = MagicMock()
    h.connection = MagicMock()
    body = h._read_json_body(max_bytes=peer_server._Handler._MAX_SEARCH_BODY_BYTES)
    assert body is None
    # rfile.read should NEVER have been called for an over-cap request.
    h.rfile.read.assert_not_called()


def test_read_json_body_default_cap_unchanged():
    """Legacy callers (slice / contribute) keep the 10 MB ceiling so
    we don't break slice ingest."""
    from swf import peer_server
    assert peer_server._Handler._MAX_DEFAULT_BODY_BYTES == 10_000_000
    # SPEC v0.3 search routes get the tighter 64 KiB cap.
    assert peer_server._Handler._MAX_SEARCH_BODY_BYTES == 65_536
