"""SPEC v0.3 §9, §29.1 policy tests."""
from __future__ import annotations

import pytest

from swf.search import (
    BUILT_IN_POLICIES,
    DeliveryPath,
    PolicyError,
    PublicEgressMode,
    RoutingGoal,
    SearchPolicy,
)

# ─── built-in policies parse and are coherent ──────────────────────────

def test_default_built_in():
    p = BUILT_IN_POLICIES["default"]
    assert p.name == "default"
    assert DeliveryPath.LOCAL_CACHE in p.route_order
    assert DeliveryPath.SELF_PUBLIC_EGRESS in p.route_order
    assert p.public_egress.mode == PublicEgressMode.ALLOW
    assert p.routing_goal == RoutingGoal.BALANCED


def test_private_circle_excludes_public():
    p = BUILT_IN_POLICIES["private_circle"]
    assert DeliveryPath.SELF_PUBLIC_EGRESS not in p.route_order
    assert p.public_egress.mode == PublicEgressMode.DENY
    assert p.allow.self_public_egress is False


def test_local_only_strictest():
    p = BUILT_IN_POLICIES["local_only"]
    assert p.route_order == (DeliveryPath.LOCAL_CACHE, DeliveryPath.LOCAL_INDREX)
    assert p.allow.lan_friend_dcnet is False
    assert p.friend_query_visibility.allow_query_visible_to_friends is False


def test_dev_placeholder_routes_through_placeholder():
    p = BUILT_IN_POLICIES["dev_placeholder_friends"]
    assert DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER in p.route_order
    assert p.allow.lan_friend_direct_placeholder is True
    assert p.public_egress.mode == PublicEgressMode.CONFIRM


# ─── §29.1 rejections ──────────────────────────────────────────────────

def test_placeholder_in_production_rejected():
    """A non-dev_-prefixed name with placeholder allowed → PolicyError."""
    with pytest.raises(PolicyError, match="dev-only"):
        SearchPolicy.parse("prod_with_placeholder", {
            "route_order": ["LOCAL_INDREX", "LAN_FRIEND_DIRECT_PLACEHOLDER"],
            "allow": {
                "local_indrex": True,
                "lan_friend_direct_placeholder": True,  # ← rejected
            },
        })


def test_placeholder_dev_prefix_no_underscore_rejected():
    """Red-team #3: `developer`, `devops`, `device-policy` must NOT
    silently opt into the placeholder transport (only `dev` and `dev_*`
    do)."""
    for name in ("developer", "devops", "device-policy", "devel", "devvy"):
        with pytest.raises(PolicyError, match="dev-only"):
            SearchPolicy.parse(name, {
                "route_order": ["LOCAL_INDREX", "LAN_FRIEND_DIRECT_PLACEHOLDER"],
                "allow": {
                    "local_indrex": True,
                    "lan_friend_direct_placeholder": True,
                },
            })


def test_placeholder_dev_underscore_allowed():
    """`dev` and `dev_<anything>` opt in correctly."""
    for name in ("dev", "dev_friends", "dev_local"):
        p = SearchPolicy.parse(name, {
            "route_order": ["LOCAL_INDREX", "LAN_FRIEND_DIRECT_PLACEHOLDER"],
            "allow": {
                "local_indrex": True,
                "lan_friend_direct_placeholder": True,
            },
        })
        assert p.allow.lan_friend_direct_placeholder is True


def test_route_in_order_must_be_allowed():
    with pytest.raises(PolicyError, match="allow.lan_friend_dcnet=false"):
        SearchPolicy.parse("inconsistent", {
            "route_order": ["LOCAL_INDREX", "LAN_FRIEND_DCNET"],
            "allow": {
                "local_indrex": True,
                "lan_friend_dcnet": False,  # ← in order but not allowed
            },
        })


def test_unknown_route_name_rejected():
    with pytest.raises(PolicyError, match="unknown route"):
        SearchPolicy.parse("badroute", {
            "route_order": ["LOCAL_INDREX", "MOON_RELAY"],
            "allow": {"local_indrex": True},
        })


def test_bad_public_egress_mode_rejected():
    with pytest.raises(PolicyError, match="public_egress.mode"):
        SearchPolicy.parse("badmode", {
            "route_order": ["LOCAL_INDREX"],
            "allow": {"local_indrex": True},
            "public_egress": {"mode": "maybe"},
        })


def test_cache_origin_local_cache_self_replay_rejected():
    with pytest.raises(PolicyError, match="cannot include LOCAL_CACHE"):
        SearchPolicy.parse("self_cache", {
            "route_order": ["LOCAL_INDREX"],
            "allow": {"local_indrex": True},
            "cache": {"allowed_origin_paths": ["LOCAL_CACHE"]},
        })


def test_cache_origin_broader_than_route_rejected():
    """Cache allows public origin but the route_order doesn't include
    public — would replay results from a route the policy bans."""
    with pytest.raises(PolicyError, match="cache would replay"):
        SearchPolicy.parse("cache_overreach", {
            "route_order": ["LOCAL_INDREX"],
            "allow": {
                "local_indrex": True,
                "self_public_egress": False,
            },
            "public_egress": {"mode": "deny"},  # coherent at route level
            "cache": {"allowed_origin_paths": ["SELF_PUBLIC_EGRESS"]},  # but cache leaks it
        })


def test_public_egress_mode_allow_with_disallowed_self_public_rejected():
    with pytest.raises(PolicyError, match="contradiction"):
        SearchPolicy.parse("contradiction", {
            "route_order": ["LOCAL_INDREX"],
            "allow": {
                "local_indrex": True,
                "self_public_egress": False,
            },
            "public_egress": {"mode": "allow"},
        })


# ─── parse_all (YAML round-trip) ───────────────────────────────────────

def test_parse_all_accepts_search_policies_root():
    doc = {
        "search_policies": {
            "tight": {
                "route_order": ["LOCAL_CACHE", "LOCAL_INDREX"],
                "allow": {"local_cache": True, "local_indrex": True,
                          "self_public_egress": False},
                "public_egress": {"mode": "deny"},
                "cache": {"allowed_origin_paths": ["LOCAL_INDREX"]},
            },
        }
    }
    out = SearchPolicy.parse_all(doc)
    assert "tight" in out
    assert out["tight"].allow.self_public_egress is False


def test_parse_all_accepts_bare_dict():
    doc = {
        "tight": {
            "route_order": ["LOCAL_CACHE", "LOCAL_INDREX"],
            "allow": {"local_cache": True, "local_indrex": True,
                      "self_public_egress": False},
            "public_egress": {"mode": "deny"},
            "cache": {"allowed_origin_paths": ["LOCAL_INDREX"]},
        }
    }
    out = SearchPolicy.parse_all(doc)
    assert "tight" in out
