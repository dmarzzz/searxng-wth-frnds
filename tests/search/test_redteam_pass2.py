"""Regression coverage for the red-team pass-2 fixes.

Each test pins one finding so a future regression can't quietly
re-open the issue. Findings tracked: agent-1 #1-#4 (URL safety,
SearXNG-trusted URLs, reputation race, router confirmation order),
agent-2 F1-F8 (type confusion, origin_paths consistency, empty policy
block, confirm-bool strictness, concurrency).
"""
from __future__ import annotations

import json
import threading
import urllib.error
from pathlib import Path

import pytest

from swf.search import (
    BUILT_IN_POLICIES,
    DeliveryPath,
    InvariantError,
    OriginPath,
    PolicyError,
    PrivacyLevel,
    SearchPolicy,
    SearchResponse,
    Status,
    lan_friend_direct,
    public_egress,
    reputation,
)
from swf.search.friend_responder import _is_safe_url
from swf.search.router import web_search

# ─── Agent-1 #1: SSRF / private-IP bypasses in `_is_safe_url` ────────

@pytest.mark.parametrize("u", [
    "http://[::1]/",                          # IPv6 loopback literal
    "http://[fe80::1]/",                      # IPv6 link-local literal
    "http://[::ffff:127.0.0.1]/",             # IPv4-mapped IPv6 → loopback
    "http://%31%32%37.0.0.1/",                # %-encoded 127.0.0.1
    "http://2130706433/",                     # decimal long-form 127.0.0.1
    "http://0x7f000001/",                     # hex 127.0.0.1
    "http://localhost/",                      # named loopback
    "http://10.0.0.5/",                       # RFC1918
    "http://192.168.1.1/",                    # RFC1918
    "http://172.16.0.1/",                     # RFC1918
    "http://172.31.0.1/",                     # RFC1918 upper
    "http://169.254.169.254/",                # link-local (cloud meta)
    "file:///etc/passwd",                     # file scheme
    "FILE:///etc/passwd",                     # case-variant scheme
    "javascript:alert(1)",                    # javascript scheme
    "data:text/html,<script>",                # data scheme
    "http://router.local/",                   # .local TLD
    "http://nas.lan/",                        # .lan TLD
    "http://printer.internal/",               # .internal TLD
])
def test_is_safe_url_blocks_obfuscated_private_addresses(u):
    assert _is_safe_url(u) is False, f"_is_safe_url should reject {u!r}"


@pytest.mark.parametrize("u", [
    "https://example.com/path",
    "http://news.example.org/article",
    "https://docs.python.org/3/",
])
def test_is_safe_url_accepts_normal_https_urls(u):
    assert _is_safe_url(u) is True


def test_is_safe_url_rejects_non_string():
    assert _is_safe_url(None) is False
    assert _is_safe_url(123) is False
    assert _is_safe_url("") is False


# ─── Agent-1 #2: SearXNG-supplied URL trust ─────────────────────────

class _FakeResp:
    def __init__(self, body): self._body, self.status = body, 200
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def read(self, *_): return self._body


def _ctx():
    from swf.search import build_context
    return build_context("decentralized search",
                         policy_name="default", hmac_secret=b"x" * 32)


def test_public_egress_drops_javascript_url(monkeypatch):
    body = json.dumps({"results": [
        {"url": "javascript:alert(1)", "title": "evil",
         "content": "x", "score": 0.9, "engines": ["duckduckgo"]},
        {"url": "https://example.com/ok", "title": "ok",
         "content": "x", "score": 0.6, "engines": ["duckduckgo"]},
    ]}).encode("utf-8")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    out = public_egress.search(_ctx())
    urls = [r.canonical_url for r in out.results]
    assert "javascript:alert(1)" not in urls
    assert "https://example.com/ok" in urls


def test_public_egress_drops_file_url(monkeypatch):
    body = json.dumps({"results": [
        {"url": "file:///etc/passwd", "title": "leak",
         "content": "x", "score": 0.9},
    ]}).encode("utf-8")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    out = public_egress.search(_ctx())
    assert out.results == []


def test_public_egress_drops_localhost_url(monkeypatch):
    body = json.dumps({"results": [
        {"url": "http://localhost:8080/admin", "title": "ssrf",
         "content": "x", "score": 0.9},
    ]}).encode("utf-8")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen",
                        lambda req, timeout=None: _FakeResp(body))
    out = public_egress.search(_ctx())
    assert out.results == []


# ─── Agent-1 #3 / Agent-2 F8: reputation race ───────────────────────

def test_reputation_bump_concurrent_no_lost_updates(tmp_path, monkeypatch):
    """50 concurrent +0.020 bumps from baseline 0.5 should land near
    the cap, not 20-deltas-short. BEGIN IMMEDIATE serializes the
    read-modify-write."""
    monkeypatch.setenv("SWF_REPUTATION_DB", str(tmp_path / "rep.db"))
    pubkey = "ed25519:concurrent-victim"
    threads = []
    errors: list[Exception] = []
    def _go():
        try:
            reputation.bump(pubkey, "open")
        except Exception as e:  # noqa: BLE001
            errors.append(e)
    for _ in range(50):
        t = threading.Thread(target=_go)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    score = reputation.score_for(pubkey)
    # Baseline 0.5 + 50*0.020 = 1.5 → capped at MAX_SCORE 0.95.
    # Even with mild contention loss, we should be very near MAX_SCORE
    # (well above the lost-update floor of ~0.93 the agent observed).
    assert score >= 0.94, f"reputation race lost too many updates: {score}"


# ─── Agent-1 #4: router confirmation order ──────────────────────────

def test_policy_rejects_self_public_egress_before_private():
    """Custom YAML that puts SELF_PUBLIC_EGRESS first must fail at
    parse time — §15 requires private routes to run first."""
    with pytest.raises(PolicyError, match="SELF_PUBLIC_EGRESS appears before"):
        SearchPolicy.parse("inverted", {
            "route_order": ["SELF_PUBLIC_EGRESS", "LOCAL_INDREX"],
            "allow": {
                "local_indrex": True,
                "self_public_egress": True,
            },
            "public_egress": {"mode": "allow"},
            "cache": {"allowed_origin_paths": ["LOCAL_INDREX"]},
        })


def test_policy_accepts_egress_only_when_no_private_routes():
    """A degenerate policy with ONLY SELF_PUBLIC_EGRESS in the order
    is allowed — there are no private routes to run first."""
    p = SearchPolicy.parse("egress_only", {
        "route_order": ["SELF_PUBLIC_EGRESS"],
        "allow": {
            "local_indrex": False, "local_cache": False,
            "self_public_egress": True,
        },
        "public_egress": {"mode": "allow"},
        "cache": {"allow_result_cache": False, "allowed_origin_paths": []},
    })
    assert p.route_order == (DeliveryPath.SELF_PUBLIC_EGRESS,)


# ─── Agent-2 F5: §29.2 origin_paths consistency ─────────────────────

def test_invariant_public_used_requires_origin_in_paths():
    """If `public_egress_used_this_request=true`, the response's
    origin_paths must include SELF_PUBLIC_EGRESS (audit trail)."""
    with pytest.raises(InvariantError, match="origin_paths does not contain"):
        SearchResponse.make(
            schema="swf.search_response.v1",
            status=Status.NO_RESULTS,
            request_id="req_test",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.NO_RESULT,
            origin_paths=[OriginPath.NO_RESULT],
            dominant_origin_path=OriginPath.NO_RESULT,
            privacy_level=PrivacyLevel.NONE,
            network_used_this_request=True,
            public_egress_used_this_request=True,  # but no SELF_PUBLIC_EGRESS in origins
        )


def test_router_no_results_includes_egress_origin_when_attempted(monkeypatch):
    """Live-fuzz F5 reproducer: when SELF_PUBLIC_EGRESS was attempted
    (and the request actually egressed), origin_paths must list it
    even though delivery_path is NO_RESULT."""
    # Force a SearXNG timeout so the route is attempted, network is
    # used, but no results come back — drives the NO_RESULT path.
    def _raise(req, timeout=None):
        raise TimeoutError("upstream timed out")
    monkeypatch.setattr(public_egress.urllib.request, "urlopen", _raise)
    monkeypatch.setattr(lan_friend_direct, "_peer_urls", lambda: [])

    # Default policy now requires explicit confirm_public_egress (#89);
    # this test is about the F5 audit-trail consistency on the egress
    # path, so we pass the confirm flag to actually exercise that path.
    resp = web_search("xyz unknown topic", policy_name="default",
                      confirm_public_egress=True)
    # Public-egress flag was set; origin_paths must therefore contain
    # SELF_PUBLIC_EGRESS so the audit trail is consistent.
    if resp.public_egress_used_this_request:
        assert OriginPath.SELF_PUBLIC_EGRESS in resp.origin_paths
    # … but we should still have made the attempt
    paths = {a.path for a in resp.attempts}
    assert DeliveryPath.SELF_PUBLIC_EGRESS in paths


# ─── Agent-2 F6: empty policy block on unknown policy ───────────────

def test_unknown_policy_returns_filled_policy_block():
    """An unknown policy still returns a §11.1-shaped `policy` block
    so clients can render it uniformly. Live-fuzz F6 reproducer."""
    resp = web_search("anything", policy_name="not_a_known_policy")
    assert resp.status == Status.ERROR
    assert resp.policy["requested"] == "not_a_known_policy"
    assert resp.policy["effective"] == "default"
    assert resp.policy["routing_goal"] == "balanced"


def test_empty_query_returns_filled_policy_block():
    resp = web_search("   ", policy_name="default")
    assert resp.status == Status.ERROR
    assert resp.policy["requested"] == "default"
    assert resp.policy["effective"] == "default"
    assert "routing_goal" in resp.policy
