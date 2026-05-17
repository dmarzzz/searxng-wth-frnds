"""SPEC v0.3 §29.2 invariant tests."""
from __future__ import annotations

import pytest

from swf.search import (
    DeliveryPath,
    InvariantError,
    OriginPath,
    PrivacyLevel,
    SearchResponse,
    Status,
)


def _base(**overrides):
    """Minimum-viable kwargs; tests override what they're checking."""
    args = dict(
        status=Status.OK,
        request_id="req_test_0001",
        created_ms=1, completed_ms=2,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_ONLY,
        network_used_this_request=False,
        public_egress_used_this_request=False,
    )
    args.update(overrides)
    return args


# ─── happy paths ───────────────────────────────────────────────────────

def test_local_indrex_response_is_valid():
    r = SearchResponse.make(**_base())
    assert r.delivery_path == DeliveryPath.LOCAL_INDREX
    assert r.privacy_level == PrivacyLevel.LOCAL_ONLY


def test_local_cache_with_local_origin():
    r = SearchResponse.make(**_base(
        delivery_path=DeliveryPath.LOCAL_CACHE,
        privacy_level=PrivacyLevel.LOCAL_REPLAY,
    ))
    assert r.delivery_path == DeliveryPath.LOCAL_CACHE


def test_self_public_egress_with_flag_set():
    r = SearchResponse.make(**_base(
        delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.PUBLIC_FROM_SELF,
        network_used_this_request=True,
        public_egress_used_this_request=True,
    ))
    assert r.public_egress_used_this_request


def test_lan_friend_dcnet_with_correct_privacy_level():
    r = SearchResponse.make(**_base(
        delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
        origin_paths=[OriginPath.LAN_FRIEND_DCNET],
        dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
        privacy_level=PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE,
        network_used_this_request=True,
    ))
    assert r.privacy_level == PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE


def test_cache_replay_of_public_result_is_valid():
    """§5 example: cached public result must label privacy_level
    LOCAL_REPLAY_OF_PUBLIC_RESULT."""
    r = SearchResponse.make(**_base(
        delivery_path=DeliveryPath.LOCAL_CACHE,
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT,
        network_used_this_request=False,
        public_egress_used_this_request=False,
    ))
    assert r.delivery_path == DeliveryPath.LOCAL_CACHE


# ─── §29.2 invariant violations ────────────────────────────────────────

def test_self_public_egress_without_flag_rejected():
    with pytest.raises(InvariantError, match="public_egress_used_this_request"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
            origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
            dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
            privacy_level=PrivacyLevel.PUBLIC_FROM_SELF,
            network_used_this_request=True,
            public_egress_used_this_request=False,  # ← violation
        ))


def test_local_cache_without_origins_rejected():
    with pytest.raises(InvariantError, match="LOCAL_CACHE delivery requires non-empty"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LOCAL_CACHE,
            origin_paths=[],
            dominant_origin_path=OriginPath.LOCAL_CACHE,  # also wrong but caught first
            privacy_level=PrivacyLevel.LOCAL_REPLAY,
        ))


def test_local_only_with_public_origin_rejected():
    with pytest.raises(InvariantError, match="non-local origins"):
        SearchResponse.make(**_base(
            origin_paths=[OriginPath.LOCAL_INDREX, OriginPath.SELF_PUBLIC_EGRESS],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
        ))


def test_local_only_with_lan_friend_origin_rejected():
    """Red-team #4: LAN friend route is non-local; local_only must not
    accept it as an origin."""
    with pytest.raises(InvariantError, match="non-local origins"):
        SearchResponse.make(**_base(
            origin_paths=[OriginPath.LOCAL_INDREX, OriginPath.LAN_FRIEND_DCNET],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
        ))


def test_local_only_with_network_used_rejected():
    """Two related invariants now fire here. Pass-4 finding #2 added
    a symmetric check (`network_used=true` requires a network-touching
    origin); the local_only-specific rejection ALSO still fires.
    Either error message is acceptable — both protect the privacy
    invariant from different angles."""
    with pytest.raises(InvariantError,
                       match=r"forbids network_used|no network-touching"):
        SearchResponse.make(**_base(
            privacy_level=PrivacyLevel.LOCAL_ONLY,
            network_used_this_request=True,
        ))


def test_local_only_with_public_egress_flag_rejected():
    """Two related invariants now fire here. The new 1b
    (origin_paths must include SELF_PUBLIC_EGRESS when the egress flag
    is set — red-team pass-2) catches the malformed combination first;
    the local_only-specific rejection is also still in place but
    covered by `test_local_only_with_public_origin_rejected`."""
    with pytest.raises(InvariantError,
                       match=r"public_egress_used_this_request=true|forbids public_egress_used"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_ONLY,
            public_egress_used_this_request=True,
        ))


def test_lan_friend_direct_placeholder_must_label_placeholder():
    with pytest.raises(InvariantError, match="not_anonymous_placeholder"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
            origin_paths=[OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER],
            dominant_origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
            privacy_level=PrivacyLevel.LOCAL_ONLY,  # wrong label
        ))


def test_lan_friend_dcnet_must_label_anonymous_query_visible():
    with pytest.raises(InvariantError, match="anonymous_within_lan_circle_query_visible"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
            origin_paths=[OriginPath.LAN_FRIEND_DCNET],
            dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
            privacy_level=PrivacyLevel.LOCAL_ONLY,  # wrong label
            network_used_this_request=True,
        ))


def test_lan_friend_dcnet_with_required_ticket_unaccepted_rejected():
    with pytest.raises(InvariantError, match="anonymous_ticket.accepted"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LAN_FRIEND_DCNET,
            origin_paths=[OriginPath.LAN_FRIEND_DCNET],
            dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
            privacy_level=PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE,
            network_used_this_request=True,
            anonymous_ticket={"required": True, "accepted": False},
        ))


def test_dominant_origin_must_be_in_origin_paths():
    with pytest.raises(InvariantError, match="dominant_origin_path"):
        SearchResponse.make(**_base(
            origin_paths=[OriginPath.LOCAL_INDREX],
            dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,  # not in list
            privacy_level=PrivacyLevel.LOCAL_ONLY,
        ))


def test_local_cache_delivery_must_not_use_network():
    """Two layered invariants now reject this combo: pass-4 #2's
    symmetric `network_used=true requires a network origin` fires
    first because LOCAL_INDREX isn't a network-touching origin;
    LOCAL_CACHE's own `must not use network` rule also still fires."""
    with pytest.raises(InvariantError,
                       match=r"network_used_this_request=false|no network-touching"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LOCAL_CACHE,
            origin_paths=[OriginPath.LOCAL_INDREX],
            dominant_origin_path=OriginPath.LOCAL_INDREX,
            privacy_level=PrivacyLevel.LOCAL_REPLAY,
            network_used_this_request=True,
        ))


def test_cached_public_result_must_label_replay_of_public():
    with pytest.raises(InvariantError, match="local_replay_of_public_result"):
        SearchResponse.make(**_base(
            delivery_path=DeliveryPath.LOCAL_CACHE,
            origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
            dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
            privacy_level=PrivacyLevel.LOCAL_REPLAY,  # wrong: must be _OF_PUBLIC_RESULT
        ))


# ─── serialization ─────────────────────────────────────────────────────

def test_to_json_uses_string_enum_values():
    r = SearchResponse.make(**_base())
    j = r.to_json()
    assert j["status"] == "ok"
    assert j["delivery_path"] == "LOCAL_INDREX"
    assert j["origin_paths"] == ["LOCAL_INDREX"]
    assert j["privacy_level"] == "local_only"
    assert j["schema"] == "swf.search_response.v1"


def test_to_json_handles_attempts():
    from swf.search.response import SearchAttempt
    r = SearchResponse.make(**_base(
        attempts=[SearchAttempt(
            path=DeliveryPath.LOCAL_CACHE, status="miss",
            started_ms=1, completed_ms=2, duration_ms=1, reason="not_in_cache",
        )]
    ))
    j = r.to_json()
    assert j["attempts"][0]["path"] == "LOCAL_CACHE"
