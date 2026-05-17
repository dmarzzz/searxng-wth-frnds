"""Phase 4 — LAN_FRIEND_DCNET interface stub.

Pins the contract:
  - default-off: handler is registered but `is_enabled()` returns False
    until `SWF_ENABLE_DCNET=1`.
  - the null transport never claims anonymity.
  - the §29.2 invariant 5 enforces the privacy contract — even a
    misbehaving transport that tries to label as anonymous without
    `min_anonymity_set_met` is rejected at construction.
  - a real transport with `transport_kind="dcnet_real"` AND
    `min_anonymity_set_met=True` AND results→ does land the anonymous
    label (the path future PR #N will exercise once a real DC-net
    library is wired).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchResult,
    Status,
    build_context,
    lan_friend_dcnet,
    web_search,
)
from swf.search.lan_friend_dcnet import (
    ActiveCircle,
    FriendSearchOutcome,
    FriendSearchTransport,
    PeerDiscoveryResult,
    _NullTransport,
    get_transport,
    reset_transport,
    set_transport,
)
from swf.search.response import (
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)


@pytest.fixture(autouse=True)
def _reset_transport():
    """Each test starts with the null transport. Tests that swap it
    via `set_transport(...)` are reset here on teardown."""
    reset_transport()
    yield
    reset_transport()


# ─── default-off behavior ─────────────────────────────────────────

def test_handler_disabled_without_env_flag(monkeypatch):
    """SWF_ENABLE_DCNET unset → is_enabled returns False, regardless
    of policy.allow.lan_friend_dcnet. Default-off is the contract."""
    monkeypatch.delenv("SWF_ENABLE_DCNET", raising=False)
    from swf.search import BUILT_IN_POLICIES
    p = BUILT_IN_POLICIES["default"]
    assert p.allow.lan_friend_dcnet is True
    assert lan_friend_dcnet._is_enabled(p) is False


def test_handler_disabled_without_policy_allow(monkeypatch):
    """Even with the env flag set, a policy that disallows DCNET
    keeps the handler disabled. Two-key lock."""
    monkeypatch.setenv("SWF_ENABLE_DCNET", "1")
    from swf.search import BUILT_IN_POLICIES
    local_only = BUILT_IN_POLICIES["local_only"]
    assert local_only.allow.lan_friend_dcnet is False
    assert lan_friend_dcnet._is_enabled(local_only) is False


def test_handler_enabled_with_both_keys(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_DCNET", "1")
    from swf.search import BUILT_IN_POLICIES
    p = BUILT_IN_POLICIES["default"]
    assert lan_friend_dcnet._is_enabled(p) is True


@pytest.mark.parametrize("v", ["1", "true", "TRUE", "yes", "ON"])
def test_env_flag_accepts_truthy_strings(monkeypatch, v):
    monkeypatch.setenv("SWF_ENABLE_DCNET", v)
    assert lan_friend_dcnet._flag_enabled() is True


@pytest.mark.parametrize("v", ["0", "false", "no", "off", "", "  "])
def test_env_flag_rejects_falsy_strings(monkeypatch, v):
    monkeypatch.setenv("SWF_ENABLE_DCNET", v)
    assert lan_friend_dcnet._flag_enabled() is False


# ─── null transport (the default) never claims anonymity ──────────

def test_null_transport_reports_disabled_circle():
    """The default transport must NEVER claim anonymity is met."""
    t = get_transport()
    assert isinstance(t, _NullTransport)
    circle = t.active_circle()
    assert circle.transport_kind == "disabled"
    assert circle.min_anonymity_set_met is False
    assert circle.requester_anonymity_claim == "none"


def test_null_transport_search_returns_empty():
    t = get_transport()
    ctx = build_context("anything", policy_name="default",
                        hmac_secret=b"x" * 32)
    out = t.search(ctx)
    assert out.results == []
    assert "dev_no_crypto" in out.reason


# ─── handler under the null transport — never anonymity-claim ─────

def test_handler_with_null_transport_never_claims_anonymity(monkeypatch):
    """Even with SWF_ENABLE_DCNET=1, the null transport keeps the
    privacy_level=None path. The handler MUST NOT label this as
    anonymous — that would be a §29.2 invariant violation."""
    monkeypatch.setenv("SWF_ENABLE_DCNET", "1")
    ctx = build_context("anything", policy_name="default",
                        hmac_secret=b"x" * 32)
    out = lan_friend_dcnet.search(ctx)
    assert out.privacy_level is None
    assert out.results == []
    assert out.attempt.status == "unavailable"
    assert out.attempt.reason.startswith(("dev_no_crypto", "anonymity_set_not_met"))


# ─── real-transport path: the privacy contract ──────────────────

class _FakeRealTransport:
    """A simulated `transport_kind=dcnet_real` with met anonymity.
    Used to verify the handler's success path will work once a real
    library is plugged in."""
    name = "fake_real"
    privacy_level = "anonymous_within_lan_circle_query_visible"

    def __init__(self, results=()):
        self._results = tuple(results)

    def discover_peers(self) -> PeerDiscoveryResult:
        return PeerDiscoveryResult(peers=("p1", "p2", "p3"), epoch_id="e0")

    def active_circle(self) -> ActiveCircle:
        return ActiveCircle(
            epoch_id="e0",
            active_peer_count=3,
            min_anonymity_set_met=True,
            membership_fixed_for_round=True,
            requester_anonymity_claim="anonymous_within_lan_circle_query_visible",
            transport_kind="dcnet_real",
        )

    def search(self, ctx) -> FriendSearchOutcome:
        return FriendSearchOutcome(results=list(self._results))


def _result(url: str = "https://x.example/1") -> SearchResult:
    return SearchResult(
        result_id="r", canonical_url=url, display_url="x", title="t",
        snippet="s", score=0.7, rank=1,
        delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
        origin_path=OriginPath.LAN_FRIEND_DCNET,
        provider=_Provider(),
        freshness=_Freshness(), verification=_Verification(),
        receipt=_Receipt(), safety=_Safety(share_scope="friends"),
    )


def test_real_transport_with_results_claims_anonymity():
    """The handler labels with §6 anonymity ONLY when transport says
    it's `dcnet_real` AND anonymity met AND there are results."""
    set_transport(_FakeRealTransport(results=[_result()]))
    ctx = build_context("q", policy_name="default", hmac_secret=b"x" * 32)
    out = lan_friend_dcnet.search(ctx)
    assert out.privacy_level == PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE
    assert out.network_used is True
    assert out.friend_query_visible is True
    assert out.attempt.status == "ok"
    assert "circle" in out.extras


def test_real_transport_with_zero_results_still_no_claim():
    """A real transport with met anonymity but zero results doesn't
    claim DCNET delivery — there's nothing to deliver. Falls
    through to the next route."""
    set_transport(_FakeRealTransport(results=[]))
    ctx = build_context("q", policy_name="default", hmac_secret=b"x" * 32)
    out = lan_friend_dcnet.search(ctx)
    assert out.privacy_level is None
    assert out.results == []


# ─── Phase-4 stub doesn't break existing tests under SWF_ENABLE_DCNET=1 ─

def test_dcnet_route_emits_attempt_when_enabled(monkeypatch):
    """With the env flag set, the router runs the handler, and the
    response carries a DCNET attempt (status=unavailable under null
    transport). No invariant violation."""
    monkeypatch.setenv("SWF_ENABLE_DCNET", "1")
    resp = web_search("anything new", policy_name="default")
    paths = {a.path for a in resp.attempts}
    # DCNET attempt present
    assert DeliveryPath.LAN_FRIEND_DCNET in paths
    # The DCNET attempt is unavailable (null transport)
    dcnet_attempts = [a for a in resp.attempts
                      if a.path == DeliveryPath.LAN_FRIEND_DCNET]
    assert len(dcnet_attempts) == 1
    assert dcnet_attempts[0].status == "unavailable"


def test_dcnet_route_skipped_silently_when_disabled(monkeypatch):
    """With the env flag UNSET, the handler is_enabled=False and the
    router silently skips. No DCNET attempt appears."""
    monkeypatch.delenv("SWF_ENABLE_DCNET", raising=False)
    resp = web_search("anything new", policy_name="default")
    paths = {a.path for a in resp.attempts}
    assert DeliveryPath.LAN_FRIEND_DCNET not in paths


# ─── Protocol conformance ───────────────────────────────────────

def test_null_transport_satisfies_protocol():
    """`FriendSearchTransport` is `runtime_checkable`, so isinstance
    works at runtime. Pin both built-ins satisfy it."""
    assert isinstance(_NullTransport(), FriendSearchTransport)
    assert isinstance(_FakeRealTransport(), FriendSearchTransport)


# ─── §29.2 invariant 5 still bites a misbehaving transport ─────

def test_invariant_blocks_misbehaving_transport():
    """If a future transport tries to claim anonymity with the wrong
    privacy_level, `SearchResponse.make()` rejects it. Verifies the
    invariant chain is the load-bearing safety net even if the
    handler itself were rewritten."""
    from swf.search.response import InvariantError, SearchResponse
    with pytest.raises(InvariantError):
        SearchResponse.make(
            status=Status.OK, request_id="req_x",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
            origin_paths=[OriginPath.LAN_FRIEND_DCNET],
            dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
            privacy_level=PrivacyLevel.LOCAL_ONLY,  # WRONG label
            network_used_this_request=True,
            public_egress_used_this_request=False,
        )
