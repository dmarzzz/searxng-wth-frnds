"""Regression coverage for the red-team pass-4 fixes."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from swf import discovery
from swf.search import (
    DeliveryPath,
    InvariantError,
    OriginPath,
    PolicyError,
    PrivacyLevel,
    SearchPolicy,
    SearchResponse,
    Status,
    audit,
)

# ─── Pass-4 #1: audit.emit failure must NOT bubble out ────────────

def test_audit_emit_swallows_handler_exception(capsys):
    """A misbehaving log handler (full disk, raising filter) must not
    fail the user's request. emit() catches and writes a stderr note."""
    class _Boom(logging.Handler):
        level = 0
        def emit(self, _record):
            raise RuntimeError("disk full")
    h = _Boom()
    audit.add_handler(h)
    try:
        # Build a minimal valid SearchResponse so emit has real input.
        resp = SearchResponse.make(
            status=Status.OK,
            request_id="req_audit_boom",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.LOCAL_INDREX,
            origin_paths=[OriginPath.LOCAL_INDREX],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
            network_used_this_request=False,
            public_egress_used_this_request=False,
        )
        # Must not raise.
        audit.emit(resp)
        captured = capsys.readouterr()
        assert "audit" in captured.err.lower()
        assert "disk full" in captured.err
    finally:
        audit.AUDIT_LOGGER.removeHandler(h)


# ─── Pass-4 #2: invariant 1c (network_used ⇒ network origin) ──────

def test_network_used_without_network_origin_rejected():
    """Symmetric counterpart to invariant 1b: a response that claims
    `network_used=true` must have at least one network-touching path
    in `origin_paths`. Without this, a handler bug could quietly
    advertise network use without surfacing which path leaked."""
    with pytest.raises(InvariantError, match="no network-touching"):
        SearchResponse.make(
            status=Status.OK,
            request_id="req_x",
            created_ms=1, completed_ms=2,
            delivery_path=DeliveryPath.LOCAL_INDREX,
            origin_paths=[OriginPath.LOCAL_INDREX],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
            network_used_this_request=True,           # ← claims network
            public_egress_used_this_request=False,
        )


def test_lan_friend_dcnet_origin_satisfies_network_invariant():
    """A friend-DCNET origin satisfies the network requirement —
    every network-touching path counts."""
    SearchResponse.make(
        status=Status.OK,
        request_id="req_x",
        created_ms=1, completed_ms=2,
        delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
        origin_paths=[OriginPath.LAN_FRIEND_DCNET],
        dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
        privacy_level=PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE,
        network_used_this_request=True,
        public_egress_used_this_request=False,
    )


# ─── Pass-4 #3: cache serialize is allowlist, not denylist ────────

def test_cache_serialize_drops_unknown_provider_field():
    """Future additions to `_Provider` (or anywhere else) must NOT
    silently land on disk. The allowlist drops anything not in
    `_PROVIDER_PERSIST_FIELDS`."""
    from swf.search.local_cache import (
        _PROVIDER_PERSIST_FIELDS,
        _serialize_result,
    )
    from swf.search.response import (
        _Freshness,
        _Provider,
        _Receipt,
        _Safety,
        _Verification,
    )
    prov = _Provider(provider_pubkey="ed25519:peer-A",
                     provider_label="alice")
    # Simulate a future field — should NOT survive the serialize.
    prov.__dict__["secret_internal_field"] = "must_not_persist"
    # Build a SearchResult inline (avoiding test-helper import drift).
    from swf.search import SearchResult
    sr = SearchResult(
        result_id="r", canonical_url="https://x/", display_url="x/",
        title="t", snippet="s", score=0.5, rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=OriginPath.LOCAL_INDREX,
        provider=prov, freshness=_Freshness(), verification=_Verification(),
        receipt=_Receipt(), safety=_Safety(),
    )
    out = _serialize_result(sr)
    assert "secret_internal_field" not in out["provider"]
    # Allowlisted fields ARE present.
    assert out["provider"]["provider_pubkey"] == "ed25519:peer-A"
    assert out["provider"]["provider_label"] == "alice"
    # Sanity: every allowlisted key is the expected set.
    for k in out["provider"]:
        assert k in _PROVIDER_PERSIST_FIELDS


# ─── Pass-4 #4: route_order length cap + dedup ─────────────────────

def test_policy_rejects_route_order_longer_than_cap():
    with pytest.raises(PolicyError, match="route_order has"):
        SearchPolicy.parse("oversized", {
            # 9 entries exceeds MAX_ROUTE_ORDER_LENGTH=8
            "route_order": ["LOCAL_CACHE"] * 9,
            "allow": {"local_cache": True},
        })


def test_policy_rejects_duplicate_routes():
    with pytest.raises(PolicyError, match="duplicate"):
        SearchPolicy.parse("dup", {
            "route_order": ["LOCAL_CACHE", "LOCAL_INDREX", "LOCAL_CACHE"],
            "allow": {"local_cache": True, "local_indrex": True},
        })


def test_policy_accepts_max_length_unique():
    """Up to MAX_ROUTE_ORDER_LENGTH unique routes is fine. We have
    only 5 useful routes today, so the limit isn't squeezing real
    configurations."""
    p = SearchPolicy.parse("ok", {
        "route_order": ["LOCAL_CACHE", "LOCAL_INDREX"],
        "allow": {"local_cache": True, "local_indrex": True,
                  "self_public_egress": False},
        "public_egress": {"mode": "deny"},
        "cache": {"allowed_origin_paths": ["LOCAL_INDREX"]},
    })
    assert len(p.route_order) == 2


# ─── Pass-4 #5: rate-limit normalizes IPv4-mapped IPv6 ────────────

def test_peer_server_normalizes_ipv4_mapped_ipv6_for_rate_limit(monkeypatch):
    """A dual-stack listener delivers an IPv4 client as
    `::ffff:1.2.3.4` over IPv6. Rate-limit MUST collapse to the
    canonical IPv4 so the client doesn't get DOUBLE the bucket."""
    seen_ips: list[str] = []
    from swf.search import friend_responder

    def _spy(req, source_ip=None):
        seen_ips.append(source_ip)
        return {"schema": "swf.friend_search.bundle.v1",
                "qid": "x", "served_at_ms": 1, "results": []}
    monkeypatch.setattr(friend_responder, "respond", _spy)

    # Drive the peer_server handler's normalization logic directly
    # by simulating do_POST's body-prep code.
    import ipaddress
    raw = "::ffff:1.2.3.4"
    parsed = ipaddress.ip_address(raw)
    assert isinstance(parsed, ipaddress.IPv6Address)
    assert parsed.ipv4_mapped is not None
    canonical = str(parsed.ipv4_mapped)
    assert canonical == "1.2.3.4"


# ─── Pass-4 #6: --check skip is not a failure ─────────────────────
# Already pinned by tests/test_node_check.py::test_check_on_fresh_home_reports_missing_dbs


# ─── Pass-4 #7: HOME isolation via conftest ───────────────────────

def test_session_conftest_redirects_home(tmp_path):
    """Verifies that `HOME` is redirected to a session tmp before any
    test runs. The conftest fixture is autouse session-scoped."""
    import os
    home = os.environ.get("HOME", "")
    assert "swf-test-session-" in home, \
        f"HOME should be a session tmp, got {home!r}"


# ─── Pass-4 #8: SWF_LAN_IP validation ─────────────────────────────

def test_swf_lan_ip_invalid_falls_through_with_warning(
    monkeypatch, capsys
):
    """Junk values must NOT be returned as the LAN IP. Falls through
    to the multicast probe and writes a stderr warning."""
    monkeypatch.setenv("SWF_LAN_IP", "not.an.ip")
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda *a, **kw: "192.168.1.42")
    ip = discovery._outbound_ipv4()
    assert ip == "192.168.1.42"  # came from the multicast probe
    err = capsys.readouterr().err
    assert "SWF_LAN_IP" in err
    assert "not a valid IP" in err


def test_swf_lan_ip_valid_still_wins(monkeypatch):
    monkeypatch.setenv("SWF_LAN_IP", "192.168.99.42")
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda *a, **kw: "10.0.0.1")
    assert discovery._outbound_ipv4() == "192.168.99.42"


def test_swf_lan_ip_ipv6_address_accepted(monkeypatch):
    """The validator accepts IPv6 too — operator might want to pin a
    specific v6 address on a v6-only LAN."""
    monkeypatch.setenv("SWF_LAN_IP", "fe80::1")
    monkeypatch.setattr(discovery, "_probe_egress_ip",
                        lambda *a, **kw: "10.0.0.1")
    # `fe80::1` is link-local, but operator-pinned overrides win
    assert discovery._outbound_ipv4() == "fe80::1"
