"""Phase 1 router orchestration tests."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf.search import (
    BUILT_IN_POLICIES,
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchResponse,
    Status,
    web_search,
)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch):
    """Per-test indrex DB + cache DB + cache secret; never touches the
    real ~/world_knowledge or ~/.local/share/swf directories."""
    # Indrex (read by local_indrex via swf.indrex.db_path).
    wk = tmp_path / "world_knowledge"
    wk.mkdir(parents=True)
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(wk))
    # Cache (read by local_cache).
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "search_cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "secret.bin"))
    # Lookup of HMAC for raw queries: pin a stable secret so tests are
    # deterministic across processes.
    monkeypatch.setenv("SWF_QUERY_HMAC_SECRET", "x" * 32)
    yield


def _seed_indrex(monkeypatch_path_helper):
    """Build an indrex db inside RA_WORLD_KNOWLEDGE_DIR with two pages."""
    import os
    root = Path(os.environ["RA_WORLD_KNOWLEDGE_DIR"])
    db = root / "index.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content,
              fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    rows = [
        ("https://example.com/dp1",
         "Differential privacy I", "differential privacy bounds tutorial"),
        ("https://docs.example.org/dp2",
         "Differential privacy II", "differential privacy noise mechanism"),
        ("https://arxiv.org/abs/dp3",
         "Differential privacy III", "lower bounds on differential privacy queries"),
    ]
    for u, t, c in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (u, t, c, "2026-04-01T00:00:00Z"),
        )
    conn.commit()
    conn.close()
    return db


# ─── happy paths ───────────────────────────────────────────────────────

def test_router_returns_local_indrex_when_results_sufficient():
    _seed_indrex(None)
    resp = web_search("differential privacy", policy_name="default")
    assert isinstance(resp, SearchResponse)
    assert resp.status == Status.OK
    assert resp.delivery_path == DeliveryPath.LOCAL_INDREX
    assert resp.origin_paths == [OriginPath.LOCAL_INDREX]
    assert resp.privacy_level == PrivacyLevel.LOCAL_ONLY
    assert resp.network_used_this_request is False
    assert resp.public_egress_used_this_request is False
    assert len(resp.results) >= 3


def test_router_caches_local_indrex_then_replays_from_cache():
    _seed_indrex(None)
    a = web_search("differential privacy", policy_name="default")
    assert a.delivery_path == DeliveryPath.LOCAL_INDREX

    # Second hit: even though LOCAL_INDREX would still work, the cache is
    # checked first per route_order. Sufficient cache hit short-circuits.
    b = web_search("differential privacy", policy_name="default")
    assert b.delivery_path == DeliveryPath.LOCAL_CACHE
    assert b.origin_paths == [OriginPath.LOCAL_INDREX]
    assert b.privacy_level == PrivacyLevel.LOCAL_REPLAY
    assert b.network_used_this_request is False


def test_router_no_results_when_indrex_empty():
    # Don't seed: empty indrex. Default policy walks LOCAL_CACHE,
    # LOCAL_INDREX, LAN_FRIEND_DCNET (gated behind SWF_ENABLE_DCNET —
    # silently skipped when unset), SELF_PUBLIC_EGRESS (errors
    # because SearXNG isn't running here).
    # Pass confirm_public_egress=True so the SELF_PUBLIC_EGRESS gate
    # doesn't short-circuit the walk under default policy (issue #89).
    resp = web_search("nothing here", policy_name="default",
                      confirm_public_egress=True)
    assert resp.status == Status.NO_RESULTS
    assert resp.delivery_path == DeliveryPath.NO_RESULT
    paths = {a.path for a in resp.attempts}
    assert DeliveryPath.LOCAL_CACHE in paths
    assert DeliveryPath.LOCAL_INDREX in paths
    assert DeliveryPath.SELF_PUBLIC_EGRESS in paths


def test_router_local_only_policy_skips_friend_and_public_routes():
    _seed_indrex(None)
    resp = web_search("differential privacy", policy_name="local_only")
    paths_in_attempts = {a.path for a in resp.attempts}
    # local_only's route_order is just [LOCAL_CACHE, LOCAL_INDREX] — no
    # friend / public attempts should be emitted.
    assert DeliveryPath.LAN_FRIEND_DCNET not in paths_in_attempts
    assert DeliveryPath.SELF_PUBLIC_EGRESS not in paths_in_attempts


def test_router_unknown_policy_returns_error():
    resp = web_search("anything", policy_name="not_a_policy")
    assert resp.status == Status.ERROR
    assert "unknown_policy" in resp.debug.get("reason", "")


def test_router_empty_query_returns_error():
    resp = web_search("   ", policy_name="default")
    assert resp.status == Status.ERROR


def test_router_response_is_json_serializable():
    _seed_indrex(None)
    resp = web_search("differential privacy", policy_name="default")
    j = resp.to_json()
    assert j["status"] == "ok"
    assert j["delivery_path"] == "LOCAL_INDREX"
    assert j["origin_paths"] == ["LOCAL_INDREX"]
    assert j["privacy_level"] == "local_only"
    assert "query_hmac" in j["debug"]
    assert all(isinstance(r["score"], float) for r in j["results"])


def test_router_request_id_passes_through():
    _seed_indrex(None)
    resp = web_search("differential privacy", policy_name="default",
                      request_id="req_test_xxxx")
    assert resp.request_id == "req_test_xxxx"


# ─── Phase 2/3 router wiring ──────────────────────────────────────────

def test_router_calls_public_egress_when_indrex_empty(monkeypatch):
    """`default` policy with no LOCAL_INDREX content must reach
    SELF_PUBLIC_EGRESS, given the route_order."""
    import json as _json

    from swf.search import public_egress

    class _Resp:
        def __init__(self, body): self._body, self.status = body, 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, *_): return self._body

    def _urlopen(req, timeout=None):
        return _Resp(_json.dumps({"results": [
            {"url": "https://a.example/r1", "title": "T1",
             "content": "snippet", "score": 0.7, "engines": ["duckduckgo"]},
            {"url": "https://b.example/r2", "title": "T2",
             "content": "snippet", "score": 0.7, "engines": ["brave"]},
            {"url": "https://c.example/r3", "title": "T3",
             "content": "snippet", "score": 0.6, "engines": ["duckduckgo"]},
        ]}).encode("utf-8"))
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    # Default policy now requires explicit confirm_public_egress (#89).
    resp = web_search("decentralized search", policy_name="default",
                      confirm_public_egress=True)
    assert resp.delivery_path == DeliveryPath.SELF_PUBLIC_EGRESS
    assert resp.public_egress_used_this_request is True
    assert resp.network_used_this_request is True
    assert resp.privacy_level.value == "public_from_self"


def test_router_blocks_public_egress_in_local_only(monkeypatch):
    """local_only policy must NEVER call public_egress, even if SearXNG
    is reachable. The route just isn't in route_order."""
    from swf.search import public_egress
    calls = {"n": 0}
    def _urlopen(req, timeout=None):
        calls["n"] += 1
        raise AssertionError("public_egress must not be called under local_only")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("anything", policy_name="local_only")
    assert calls["n"] == 0
    assert resp.delivery_path == DeliveryPath.NO_RESULT


def test_router_confirmation_required_on_confirm_mode(monkeypatch):
    """`dev_placeholder_friends` has public_egress.mode=confirm. When
    earlier routes don't satisfy, the router must return
    status=confirmation_required, NOT silently call SearXNG."""
    from swf.search import lan_friend_direct, public_egress
    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])
    blocked = {"called": False}
    def _urlopen(req, timeout=None):
        blocked["called"] = True
        raise AssertionError("must not reach public egress without confirmation")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("anything", policy_name="dev_placeholder_friends")
    assert resp.status.value == "confirmation_required"
    assert resp.debug["proposed_path"] == "SELF_PUBLIC_EGRESS"
    assert blocked["called"] is False


def test_router_confirms_and_proceeds_with_explicit_flag(monkeypatch):
    """After confirmation_required, retrying with confirm_public_egress
    should let the router proceed to SELF_PUBLIC_EGRESS."""
    import json as _json

    from swf.search import lan_friend_direct, public_egress

    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])

    class _Resp:
        def __init__(self, body): self._body, self.status = body, 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, *_): return self._body
    def _urlopen(req, timeout=None):
        # Distinct hosts so sufficiency's min_unique_hosts=2 passes.
        return _Resp(_json.dumps({"results": [
            {"url": f"https://host{i}.example/{i}", "title": f"T{i}",
             "content": "s", "score": 0.5, "engines": ["duckduckgo"]}
            for i in range(3)
        ]}).encode("utf-8"))
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _urlopen)

    resp = web_search("anything", policy_name="dev_placeholder_friends",
                      confirm_public_egress=True)
    assert resp.status == Status.OK
    assert resp.delivery_path == DeliveryPath.SELF_PUBLIC_EGRESS


def test_router_lan_friend_direct_in_dev_policy(monkeypatch):
    """dev_placeholder_friends policy hits LAN_FRIEND_DIRECT_PLACEHOLDER
    when peers respond. Privacy must be not_anonymous_placeholder."""
    import json as _json

    from swf.search import lan_friend_direct

    class _Resp:
        def __init__(self, body): self._body, self.status = body, 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, *_): return self._body

    monkeypatch.setattr(
        lan_friend_direct, "_peer_urls",
        lambda: ["http://peer-a:7777", "http://peer-b:7777"],
    )
    rows = _json.dumps({"results": [
        {"canonical_url": f"https://host{i}.example/{i}",
         "title": f"P{i}", "snippet": "s", "score": 0.6,
         "share_scope": "friends"}
        for i in range(4)
    ]}).encode("utf-8")
    monkeypatch.setattr(
        lan_friend_direct.urllib.request, "urlopen",
        lambda req, timeout=None: _Resp(rows),
    )
    resp = web_search("anything",
                      policy_name="dev_placeholder_friends",
                      confirm_public_egress=True)
    # dev_placeholder_friends route_order puts DIRECT_PLACEHOLDER before
    # SELF_PUBLIC_EGRESS — placeholder wins on a sufficient hit.
    assert resp.delivery_path == DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER
    assert resp.privacy_level.value == "not_anonymous_placeholder"
    assert resp.friend_query_visible is True
