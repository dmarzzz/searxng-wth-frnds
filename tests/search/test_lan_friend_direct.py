"""Phase 3 LAN_FRIEND_DIRECT_PLACEHOLDER tests.

Covers the client-side fan-out (lan_friend_direct.search) and the
responder (friend_responder.respond). The two halves talk to each
other in real e2e but the unit tests substitute one for the other.
"""
from __future__ import annotations

import io
import json
import sqlite3
import urllib.error
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    build_context,
    friend_responder,
    lan_friend_direct,
)
from swf.search.friend_responder import (
    MAX_ROUNDS_PER_MINUTE,
    _is_safe_url,
    _reset_rate_limit_state,
    respond,
)
from swf.search.lan_friend_direct import search

# ────────────────────────────────────────────────────────────────────
#  Friend responder (server side)
# ────────────────────────────────────────────────────────────────────

@pytest.fixture
def indrex_with_meta(tmp_path: Path):
    """A populated indrex DB with explicit share_scope on each row."""
    db = tmp_path / "world_knowledge" / "index.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content, fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    rows = [
        ("https://public.example/dp", "Differential privacy survey",
         "differential privacy bounds tutorial"),
        ("https://friends.example/dp", "DP follow-up",
         "differential privacy noise mechanism"),
        ("https://private.example/dp", "Private notes on DP",
         "differential privacy thoughts"),
        ("https://hi-sense.example/dp", "Sensitive DP analysis",
         "differential privacy redacted"),
        ("file:///home/user/dp.txt", "Local file leak",
         "differential privacy local file"),
        ("https://localhost.example/dp", "Localhost-host result",
         "differential privacy localhost"),
        ("http://192.168.1.10/dp", "Private LAN host result",
         "differential privacy private lan"),
    ]
    for u, t, c in rows:
        conn.execute("INSERT INTO pages(url, title, content, fetched_at) "
                     "VALUES(?,?,?,?)", (u, t, c, "2026-04-01T00:00:00Z"))
    from swf.search.migration import ensure_schema, set_meta
    ensure_schema(conn)
    # Explicit metadata per row
    set_meta(conn, "https://public.example/dp", share_scope="public")
    set_meta(conn, "https://friends.example/dp", share_scope="friends")
    set_meta(conn, "https://private.example/dp", share_scope="private")
    set_meta(conn, "https://hi-sense.example/dp",
             share_scope="public", sensitivity_label="high")
    set_meta(conn, "file:///home/user/dp.txt", share_scope="public")
    set_meta(conn, "https://localhost.example/dp", share_scope="public")
    set_meta(conn, "http://192.168.1.10/dp", share_scope="public")
    conn.commit()
    conn.close()
    return db


def test_responder_only_returns_friends_or_public(indrex_with_meta):
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_meta)
    urls = {r["canonical_url"] for r in bundle["results"]}
    assert "https://public.example/dp" in urls
    assert "https://friends.example/dp" in urls
    # share_scope=private must NOT leak
    assert "https://private.example/dp" not in urls


def test_responder_drops_high_sensitivity_rows(indrex_with_meta):
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_meta)
    urls = {r["canonical_url"] for r in bundle["results"]}
    assert "https://hi-sense.example/dp" not in urls


def test_responder_drops_unsafe_urls(indrex_with_meta):
    """§13.3: file://, RFC1918 URLs must not be served."""
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_meta)
    urls = {r["canonical_url"] for r in bundle["results"]}
    assert not any(u.startswith("file://") for u in urls)
    assert not any(u.startswith("http://192.168.") for u in urls)
    # `localhost.example` is a normal subdomain — public, NOT loopback —
    # so the responder should serve it. Loopback hosts (`localhost`,
    # `127.0.0.1`) are blocked but never appear in the test fixture.


def test_responder_caps_top_k(indrex_with_meta):
    bundle = respond({"q": "differential privacy", "top_k": 999},
                     db=indrex_with_meta)
    # MAX_TOP_K is 8; cap applied even if caller asks for more.
    assert len(bundle["results"]) <= 8


def test_responder_rejects_empty_query():
    bundle = respond({"q": "", "top_k": 5})
    assert bundle["results"] == []
    assert bundle["reason"] == "bad_query"


def test_responder_rejects_oversized_query():
    big = "a " * 1000  # >> 512 bytes
    bundle = respond({"q": big, "top_k": 5})
    assert bundle["results"] == []
    assert bundle["reason"] == "bad_query"


# ── TODO-8 §13.1 schema extensions: chained provenance + tombstones ──


@pytest.fixture
def indrex_with_provenance(tmp_path: Path):
    """Indrex DB exercising the four §13.1 extension columns:
       - source_type='peer_ingest' must NOT be re-shared
       - deleted_at_ms set must NOT be served
       - content_hash + fetched_at_ms ride along when set
    """
    db = tmp_path / "world_knowledge" / "index.db"
    db.parent.mkdir(parents=True)
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content, fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    rows = [
        ("https://own.example/dp",        "Own DP",     "differential privacy own"),
        ("https://peer-ingest.example/dp", "Peer DP",   "differential privacy ingested"),
        ("https://tombstoned.example/dp", "Deleted DP", "differential privacy deleted"),
    ]
    for u, t, c in rows:
        conn.execute("INSERT INTO pages(url, title, content, fetched_at) "
                     "VALUES(?,?,?,?)", (u, t, c, "2026-04-01T00:00:00Z"))
    from swf.search.migration import ensure_schema, set_meta
    ensure_schema(conn)
    # Own row — fetched by us, OK to re-share.
    set_meta(conn, "https://own.example/dp",
             share_scope="public",
             source_type="user_fetched",
             content_hash="sha256:OWN",
             fetched_at_ms=1_700_000_000_000)
    # Peer-ingest row — DO NOT re-share (chained provenance attack).
    set_meta(conn, "https://peer-ingest.example/dp",
             share_scope="public",
             source_type="peer_ingest",
             content_hash="sha256:PEER",
             fetched_at_ms=1_700_000_001_000)
    # Tombstoned row — must not surface even though share_scope=public.
    set_meta(conn, "https://tombstoned.example/dp",
             share_scope="public",
             source_type="user_fetched",
             deleted_at_ms=1_700_000_002_000)
    conn.commit()
    conn.close()
    return db


def test_responder_drops_peer_ingest_rows(indrex_with_provenance):
    """Load-bearing chained-provenance gate (TODO-8 §13.1).

    A row whose `source_type='peer_ingest'` came from another peer; if
    we re-shared it, a curious peer could re-broadcast someone else's
    archive through us. The friend responder MUST refuse these even
    when share_scope is 'friends' or 'public'.
    """
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_provenance)
    urls = {r["canonical_url"] for r in bundle["results"]}
    assert "https://own.example/dp" in urls
    # The peer-ingest row had share_scope=public — but provenance trumps.
    assert "https://peer-ingest.example/dp" not in urls


def test_responder_drops_tombstoned_rows(indrex_with_provenance):
    """A row with `deleted_at_ms IS NOT NULL` is tombstoned and must
    never be served, even with share_scope=public."""
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_provenance)
    urls = {r["canonical_url"] for r in bundle["results"]}
    assert "https://tombstoned.example/dp" not in urls


def test_responder_propagates_content_hash_and_fetched_at_ms(indrex_with_provenance):
    """When the writer set §13.1 `content_hash` / `fetched_at_ms`, the
    friend bundle includes them so peers can verify freshness +
    integrity downstream (§11.4 freshness + verification blocks)."""
    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_provenance)
    by_url = {r["canonical_url"]: r for r in bundle["results"]}
    own = by_url["https://own.example/dp"]
    assert own["content_hash"] == "sha256:OWN"
    assert own["fetched_at_ms"] == 1_700_000_000_000


def test_is_safe_url_blocks_private_ips():
    assert _is_safe_url("https://example.com/x") is True
    assert _is_safe_url("http://localhost/x") is False
    assert _is_safe_url("http://127.0.0.1/x") is False
    assert _is_safe_url("http://10.0.0.5/x") is False
    assert _is_safe_url("http://192.168.1.1/x") is False
    assert _is_safe_url("http://172.16.0.1/x") is False
    assert _is_safe_url("http://172.31.0.1/x") is False
    assert _is_safe_url("http://172.32.0.1/x") is True   # outside the 16-31 range
    assert _is_safe_url("file:///etc/passwd") is False
    assert _is_safe_url("javascript:alert(1)") is False
    assert _is_safe_url("https://router.local/x") is False


# ────────────────────────────────────────────────────────────────────
#  Direct-placeholder client (fan-out side)
# ────────────────────────────────────────────────────────────────────

def _ctx(query: str = "differential privacy"):
    return build_context(query, policy_name="dev_placeholder_friends",
                         hmac_secret=b"x" * 32)


class _FakePeerResp:
    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *_): return self._body


def _peer_bundle(rows):
    return json.dumps({
        "schema": "swf.friend_search.bundle.v1",
        "results": rows,
    }).encode("utf-8")


def test_search_aggregates_responses_from_multiple_peers(monkeypatch):
    bundles = [
        _peer_bundle([
            {"canonical_url": "https://a.example/1", "title": "A1",
             "snippet": "snip", "score": 0.9,
             "share_scope": "friends",
             "provider_pubkey": "ed25519:peer-A"},
        ]),
        _peer_bundle([
            {"canonical_url": "https://b.example/1", "title": "B1",
             "snippet": "snip", "score": 0.8,
             "share_scope": "public"},
        ]),
    ]
    calls = iter(bundles)
    monkeypatch.setattr(lan_friend_direct.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakePeerResp(next(calls)))
    out = search(_ctx(),
                 peers=["http://peer-a:7777", "http://peer-b:7777"])
    assert out.attempt.status == "ok"
    assert out.privacy_level == PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER
    assert out.friend_query_visible is True
    urls = [r.canonical_url for r in out.results]
    assert "https://a.example/1" in urls
    assert "https://b.example/1" in urls
    # Re-ranked by score desc — peer-A's 0.9 ranks above peer-B's 0.8.
    assert out.results[0].canonical_url == "https://a.example/1"
    assert out.results[0].rank == 1


def test_search_dedupes_same_url_across_peers(monkeypatch):
    body = _peer_bundle([
        {"canonical_url": "https://shared.example/x", "title": "T",
         "snippet": "s", "score": 0.7, "share_scope": "friends"},
    ])
    monkeypatch.setattr(lan_friend_direct.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakePeerResp(body))
    out = search(_ctx(),
                 peers=["http://peer-a:7777", "http://peer-b:7777"])
    # Only one row in merged set despite both peers returning it.
    assert len(out.results) == 1


def test_no_peers_returns_unavailable(monkeypatch):
    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])
    out = search(_ctx())
    assert out.attempt.status == "unavailable"
    assert out.attempt.reason == "no_peers_online"
    assert out.results == []


def test_all_peers_error_marks_suspicious(monkeypatch):
    def _raise(req, timeout=None):
        raise urllib.error.URLError("[Errno 61] Connection refused")
    monkeypatch.setattr(lan_friend_direct.urllib.request, "urlopen", _raise)
    out = search(_ctx(),
                 peers=["http://peer-a:7777", "http://peer-b:7777"])
    assert out.attempt.suspicious_failure is True
    assert out.attempt.status == "unavailable"


def test_partial_peer_error_does_not_block_route(monkeypatch):
    """One peer returns, another throws. Route should still succeed."""
    good = _peer_bundle([
        {"canonical_url": "https://good.example/1", "title": "G1",
         "snippet": "s", "score": 0.5, "share_scope": "public"},
    ])
    state = {"call": 0}
    def _urlopen(req, timeout=None):
        state["call"] += 1
        if state["call"] == 1:
            return _FakePeerResp(good)
        raise urllib.error.URLError("peer down")
    monkeypatch.setattr(lan_friend_direct.urllib.request, "urlopen", _urlopen)
    out = search(_ctx(),
                 peers=["http://good:7777", "http://bad:7777"])
    assert out.attempt.status == "ok"
    assert len(out.results) == 1
    assert out.extras["peers_responded"] == 1
    assert out.extras["peers_errored"] == 1
    assert out.attempt.suspicious_failure is False  # not all errored


# ────────────────────────────────────────────────────────────────────
#  TODO-9 — §21.1 friend responder rate limiting
# ────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=False)
def _clear_rate_limit():
    """Reset the module-level token bucket before/after each test that
    exercises the rate limiter — so cross-test ordering can't taint
    state."""
    _reset_rate_limit_state()
    yield
    _reset_rate_limit_state()


def test_responder_rate_limit_blocks_21st_call_from_same_ip(
    indrex_with_meta, _clear_rate_limit
):
    """§21.1: 20 queries/min cap. The 21st call from the same source IP
    short-circuits with `reason='rate_limited'` and zero results."""
    ip = "192.0.2.10"
    for _ in range(MAX_ROUNDS_PER_MINUTE):
        bundle = respond({"q": "differential privacy", "top_k": 8},
                         db=indrex_with_meta, source_ip=ip)
        assert bundle.get("reason") != "rate_limited"

    blocked = respond({"q": "differential privacy", "top_k": 8},
                      db=indrex_with_meta, source_ip=ip)
    assert blocked["reason"] == "rate_limited"
    assert blocked["results"] == []
    # Bundle stays well-shaped so the client doesn't crash on parse.
    assert blocked["schema"] == "swf.friend_search.bundle.v1"
    assert "qid" in blocked
    assert "served_at_ms" in blocked


def test_responder_rate_limit_buckets_per_source_ip(
    indrex_with_meta, _clear_rate_limit
):
    """Two distinct source IPs each get their own 20-call budget; the
    bucket is keyed per-IP."""
    ip_a = "192.0.2.10"
    ip_b = "192.0.2.11"
    # Burn IP A's full 20 — the 21st should rate-limit IP A.
    for _ in range(MAX_ROUNDS_PER_MINUTE):
        respond({"q": "differential privacy", "top_k": 8},
                db=indrex_with_meta, source_ip=ip_a)
    blocked_a = respond({"q": "differential privacy", "top_k": 8},
                        db=indrex_with_meta, source_ip=ip_a)
    assert blocked_a["reason"] == "rate_limited"

    # IP B's first call must still go through.
    fresh_b = respond({"q": "differential privacy", "top_k": 8},
                      db=indrex_with_meta, source_ip=ip_b)
    assert fresh_b.get("reason") != "rate_limited"


def test_responder_rate_limit_window_slides_after_60s(
    indrex_with_meta, _clear_rate_limit, monkeypatch
):
    """§21.1: window is sliding. After 60+ seconds elapse, the old
    timestamps drop out and the budget resets."""
    ip = "192.0.2.10"
    fake_now = {"t": 1_000_000.0}
    monkeypatch.setattr(friend_responder.time, "time",
                        lambda: fake_now["t"])
    for _ in range(MAX_ROUNDS_PER_MINUTE):
        respond({"q": "differential privacy", "top_k": 8},
                db=indrex_with_meta, source_ip=ip)
    blocked = respond({"q": "differential privacy", "top_k": 8},
                      db=indrex_with_meta, source_ip=ip)
    assert blocked["reason"] == "rate_limited"

    # Slide 61 seconds forward — every prior timestamp is older than
    # the 60s cutoff, so the bucket should flush and accept again.
    fake_now["t"] += 61.0
    after = respond({"q": "differential privacy", "top_k": 8},
                    db=indrex_with_meta, source_ip=ip)
    assert after.get("reason") != "rate_limited"


def test_responder_cpu_budget_returns_well_shaped_bundle(
    indrex_with_meta, _clear_rate_limit, monkeypatch
):
    """§21.1 max_cpu_ms_per_query: when the wall-clock budget is blown
    we short-circuit BEFORE the per-row safety/dedup loop, return a
    properly-shaped bundle, and don't crash."""
    # Force every monotonic() reading after the first to be far in the
    # future. The first call (`t0 = time.monotonic()`) returns 0; every
    # subsequent call returns 999, blowing the 0.1s budget immediately.
    state = {"calls": 0}
    def _fake_monotonic():
        state["calls"] += 1
        return 0.0 if state["calls"] == 1 else 999.0
    monkeypatch.setattr(friend_responder.time, "monotonic", _fake_monotonic)

    bundle = respond({"q": "differential privacy", "top_k": 8},
                     db=indrex_with_meta, source_ip=None)
    assert bundle["reason"] == "cpu_budget_exceeded"
    assert isinstance(bundle["results"], list)
    assert bundle["schema"] == "swf.friend_search.bundle.v1"
    assert "qid" in bundle
    assert "served_at_ms" in bundle
    assert "index_scope" in bundle


def test_responder_no_source_ip_skips_rate_limit(
    indrex_with_meta, _clear_rate_limit
):
    """When `source_ip=None` (the unit-test path), the rate limiter
    must be bypassed entirely so existing test fixtures keep working."""
    for _ in range(MAX_ROUNDS_PER_MINUTE + 5):
        bundle = respond({"q": "differential privacy", "top_k": 8},
                         db=indrex_with_meta, source_ip=None)
        assert bundle.get("reason") != "rate_limited"
