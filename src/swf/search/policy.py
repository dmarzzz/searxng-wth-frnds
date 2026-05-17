"""SPEC v0.3 §9 + §29.1 search policy model.

Loads YAML, validates schema, rejects impossible route combinations.
SearchPolicy is a frozen dataclass — once handed to the router it does
not mutate.

§9 defines four built-in policies (default, private_circle, local_only,
dev_placeholder_friends). They live in `BUILT_IN_POLICIES` so a brand-new
deployment doesn't need to ship any YAML to function.

The full §30 config schema is broader (cache TTLs, search-wide settings,
peer trust). Phase 0 only models the per-policy fields the router will
actually consult. Wider config plumbing comes in later phases.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .response import DeliveryPath


class PolicyError(ValueError):
    """The policy as configured cannot be honored."""


class PublicEgressMode(str, Enum):
    """§9: public-fallback gating is more than a boolean."""
    ALLOW = "allow"
    CONFIRM = "confirm"
    DENY = "deny"


class RoutingGoal(str, Enum):
    """§9.1 routing_goal — biases sufficiency thresholds + tiebreakers."""
    BALANCED = "balanced"
    PRIVACY_FIRST = "privacy_first"
    LATENCY_FIRST = "latency_first"
    DEV = "dev"


@dataclass(frozen=True)
class _Allow:
    local_cache: bool = True
    local_indrex: bool = True
    lan_friend_dcnet: bool = False
    lan_friend_direct_placeholder: bool = False
    self_public_egress: bool = True


@dataclass(frozen=True)
class _PublicEgress:
    mode: PublicEgressMode = PublicEgressMode.ALLOW
    confirm_on_sensitive_query: bool = True
    confirm_after_suspicious_private_failure: bool = True


@dataclass(frozen=True)
class _Cache:
    allow_result_cache: bool = True
    allowed_origin_paths: tuple[DeliveryPath, ...] = ()
    disclose_origin_paths: bool = True


@dataclass(frozen=True)
class _FriendQueryVisibility:
    allow_query_visible_to_friends: bool = True


@dataclass(frozen=True)
class _AnonymousTickets:
    require_for_lan_friend_search: bool = True


@dataclass(frozen=True)
class SearchPolicy:
    """A validated, immutable policy. Construct via `SearchPolicy.parse(d)`
    so impossible combinations are rejected at the boundary."""
    name: str
    route_order: tuple[DeliveryPath, ...]
    allow: _Allow
    public_egress: _PublicEgress
    cache: _Cache
    friend_query_visibility: _FriendQueryVisibility
    anonymous_tickets: _AnonymousTickets
    routing_goal: RoutingGoal = RoutingGoal.BALANCED

    # ── parsing ────────────────────────────────────────────────────────

    @classmethod
    def parse(cls, name: str, d: dict[str, Any]) -> SearchPolicy:
        """Parse a single policy block (§9.x)."""
        try:
            ro_raw = d.get("route_order", [])
            route_order = tuple(_parse_path(p) for p in ro_raw)
        except KeyError as e:
            raise PolicyError(f"policy {name!r}: unknown route name in route_order: {e}") from e

        allow_raw = d.get("allow", {})
        allow = _Allow(
            local_cache=bool(allow_raw.get("local_cache", True)),
            local_indrex=bool(allow_raw.get("local_indrex", True)),
            lan_friend_dcnet=bool(allow_raw.get("lan_friend_dcnet", False)),
            lan_friend_direct_placeholder=bool(allow_raw.get("lan_friend_direct_placeholder", False)),
            self_public_egress=bool(allow_raw.get("self_public_egress", True)),
        )

        pe_raw = d.get("public_egress", {})
        try:
            mode = PublicEgressMode(pe_raw.get("mode", "allow"))
        except ValueError as e:
            raise PolicyError(f"policy {name!r}: bad public_egress.mode: {e}") from e
        pe = _PublicEgress(
            mode=mode,
            confirm_on_sensitive_query=bool(pe_raw.get("confirm_on_sensitive_query", True)),
            confirm_after_suspicious_private_failure=bool(
                pe_raw.get("confirm_after_suspicious_private_failure", True)
            ),
        )

        cache_raw = d.get("cache", {})
        try:
            cache = _Cache(
                allow_result_cache=bool(cache_raw.get("allow_result_cache", True)),
                allowed_origin_paths=tuple(
                    _parse_path(p) for p in cache_raw.get("allowed_origin_paths", [])
                ),
                disclose_origin_paths=bool(cache_raw.get("disclose_origin_paths", True)),
            )
        except KeyError as e:
            raise PolicyError(
                f"policy {name!r}: unknown route in cache.allowed_origin_paths: {e}"
            ) from e

        fqv_raw = d.get("friend_query_visibility", {})
        fqv = _FriendQueryVisibility(
            allow_query_visible_to_friends=bool(
                fqv_raw.get("allow_query_visible_to_friends", True)
            )
        )

        at_raw = d.get("anonymous_tickets", {})
        at = _AnonymousTickets(
            require_for_lan_friend_search=bool(
                at_raw.get("require_for_lan_friend_search", True)
            )
        )

        try:
            goal = RoutingGoal(d.get("routing_goal", "balanced"))
        except ValueError as e:
            raise PolicyError(f"policy {name!r}: bad routing_goal: {e}") from e

        policy = cls(
            name=name,
            route_order=route_order,
            allow=allow,
            public_egress=pe,
            cache=cache,
            friend_query_visibility=fqv,
            anonymous_tickets=at,
            routing_goal=goal,
        )
        # Underscore-anchored prefix: `developer`, `devops`, `device-X`
        # must NOT silently opt into the placeholder transport (red-team
        # finding #3). Bare `dev` and `dev_*` are allowed.
        _check_consistency(policy,
                           dev_allowed=(name == "dev" or name.startswith("dev_")))
        return policy

    @classmethod
    def parse_all(cls, doc: dict[str, Any]) -> dict[str, SearchPolicy]:
        """Parse a §30-style YAML doc with `search_policies: { name: {...}}`.
        Returns name → SearchPolicy. Built-ins are NOT auto-merged here;
        callers can do `BUILT_IN_POLICIES | parse_all(yaml)` if desired.
        """
        out: dict[str, SearchPolicy] = {}
        block = doc.get("search_policies", doc)  # accept bare dict too
        if not isinstance(block, dict):
            raise PolicyError("expected mapping at search_policies")
        for name, body in block.items():
            if not isinstance(body, dict):
                raise PolicyError(f"policy {name!r}: expected mapping body")
            out[name] = cls.parse(name, body)
        return out


# ─── helpers ───────────────────────────────────────────────────────────

def _parse_path(name: str) -> DeliveryPath:
    try:
        return DeliveryPath(name)
    except ValueError:
        raise KeyError(name) from None


MAX_ROUTE_ORDER_LENGTH = 8  # there are 6 distinct routes today; 8 is
                            # generous slack for future ones. A bigger
                            # number is a probable typo / abuse.


def _check_consistency(p: SearchPolicy, *, dev_allowed: bool) -> None:
    """§29.1 consistency rules. Raise PolicyError on violation."""
    # Pass-4 finding #4: cap route_order length and reject duplicates.
    # A YAML with `route_order: [LOCAL_CACHE]*10000` would make
    # `web_search` walk 10000 lookups and emit a 10000-attempt envelope.
    if len(p.route_order) > MAX_ROUTE_ORDER_LENGTH:
        raise PolicyError(
            f"policy {p.name!r}: route_order has {len(p.route_order)} "
            f"entries (max {MAX_ROUTE_ORDER_LENGTH}). A larger order is "
            f"a probable typo or abuse — collapse duplicates first."
        )
    if len(set(p.route_order)) != len(p.route_order):
        seen, dups = set(), []
        for r in p.route_order:
            if r in seen:
                dups.append(r.value)
            seen.add(r)
        raise PolicyError(
            f"policy {p.name!r}: route_order contains duplicate "
            f"entries {dups!r}. Each route should appear at most once."
        )

    # placeholder friend transport in production
    if p.allow.lan_friend_direct_placeholder and not dev_allowed:
        raise PolicyError(
            f"policy {p.name!r}: lan_friend_direct_placeholder is dev-only; "
            f"name a policy with the dev_ prefix to opt in"
        )

    # public_egress.mode = allow with local_only contradicts itself
    if p.public_egress.mode == PublicEgressMode.ALLOW and \
       not p.allow.self_public_egress:
        raise PolicyError(
            f"policy {p.name!r}: public_egress.mode=allow but "
            f"allow.self_public_egress=false (contradiction)"
        )
    if p.public_egress.mode != PublicEgressMode.DENY and \
       p.routing_goal == RoutingGoal.PRIVACY_FIRST and \
       not _has_only_local_routes(p.route_order) and \
       p.allow.self_public_egress is False:
        # privacy_first with self_public_egress disabled can still allow
        # confirm/allow-mode if the route_order doesn't include public —
        # this combination is intentional in the local_only built-in.
        pass

    # routes in route_order must be allow-listed
    for r in p.route_order:
        if not _route_allowed(p.allow, r):
            raise PolicyError(
                f"policy {p.name!r}: route_order contains {r.value} but "
                f"allow.{_allow_field(r)}=false"
            )

    # Red-team #4: SELF_PUBLIC_EGRESS must not appear before every private
    # route in the order. §15 requires the router to exhaust private
    # routes before the public-egress confirmation gate; if the policy
    # reverses that, the router's gate fires before any private attempt
    # ran, which would surprise an inattentive operator.
    private_routes = (
        DeliveryPath.LOCAL_CACHE, DeliveryPath.LOCAL_INDREX,
        DeliveryPath.LAN_FRIEND_DCNET,
        DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
    )
    pub_idx = next((i for i, r in enumerate(p.route_order)
                    if r == DeliveryPath.SELF_PUBLIC_EGRESS), None)
    if pub_idx is not None:
        # Find the position of any private route still in this order.
        private_idxs = [i for i, r in enumerate(p.route_order)
                        if r in private_routes]
        if private_idxs and pub_idx < min(private_idxs):
            raise PolicyError(
                f"policy {p.name!r}: SELF_PUBLIC_EGRESS appears before "
                f"every private route in route_order. §15 requires "
                f"private routes to run first; reorder so private routes "
                f"precede SELF_PUBLIC_EGRESS"
            )

    # cache origins must be a subset of {LOCAL_INDREX, LAN_FRIEND_*,
    # SELF_PUBLIC_EGRESS}; LOCAL_CACHE-as-origin is meaningless.
    for op in p.cache.allowed_origin_paths:
        if op == DeliveryPath.LOCAL_CACHE:
            raise PolicyError(
                f"policy {p.name!r}: cache.allowed_origin_paths cannot "
                f"include LOCAL_CACHE (a cache replaying a cache)"
            )
        if op == DeliveryPath.NO_RESULT or op == DeliveryPath.MIXED:
            raise PolicyError(
                f"policy {p.name!r}: cache.allowed_origin_paths cannot "
                f"include {op.value}"
            )

    # cache origins broader than route policy: any origin allowed in cache
    # whose route is denied in `allow` is suspicious — explicit override
    # would be a per-policy field; today we just reject.
    for op in p.cache.allowed_origin_paths:
        if op in (DeliveryPath.LOCAL_INDREX, DeliveryPath.LAN_FRIEND_DCNET,
                  DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
                  DeliveryPath.SELF_PUBLIC_EGRESS) and \
           not _route_allowed(p.allow, op):
            raise PolicyError(
                f"policy {p.name!r}: cache.allowed_origin_paths includes "
                f"{op.value} but allow.{_allow_field(op)}=false — cache "
                f"would replay results from a route this policy bans"
            )


def _route_allowed(a: _Allow, p: DeliveryPath) -> bool:
    return {
        DeliveryPath.LOCAL_CACHE: a.local_cache,
        DeliveryPath.LOCAL_INDREX: a.local_indrex,
        DeliveryPath.LAN_FRIEND_DCNET: a.lan_friend_dcnet,
        DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER: a.lan_friend_direct_placeholder,
        DeliveryPath.SELF_PUBLIC_EGRESS: a.self_public_egress,
    }.get(p, False)


def _allow_field(p: DeliveryPath) -> str:
    return {
        DeliveryPath.LOCAL_CACHE: "local_cache",
        DeliveryPath.LOCAL_INDREX: "local_indrex",
        DeliveryPath.LAN_FRIEND_DCNET: "lan_friend_dcnet",
        DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER: "lan_friend_direct_placeholder",
        DeliveryPath.SELF_PUBLIC_EGRESS: "self_public_egress",
    }.get(p, "")


def _has_only_local_routes(routes: tuple[DeliveryPath, ...]) -> bool:
    return all(r in (DeliveryPath.LOCAL_CACHE, DeliveryPath.LOCAL_INDREX)
               for r in routes)


# ─── built-in policies (§9.1–§9.4) ─────────────────────────────────────

def _build_default() -> SearchPolicy:
    return SearchPolicy.parse("default", {
        "route_order": [
            "LOCAL_CACHE", "LOCAL_INDREX", "LAN_FRIEND_DCNET",
            "SELF_PUBLIC_EGRESS",
        ],
        "allow": {
            "local_cache": True, "local_indrex": True,
            "lan_friend_dcnet": True, "lan_friend_direct_placeholder": False,
            "self_public_egress": True,
        },
        "public_egress": {
            "mode": "allow",
            "confirm_on_sensitive_query": True,
            "confirm_after_suspicious_private_failure": True,
        },
        "cache": {
            "allow_result_cache": True,
            "allowed_origin_paths": [
                "LOCAL_INDREX", "LAN_FRIEND_DCNET", "SELF_PUBLIC_EGRESS",
            ],
            "disclose_origin_paths": True,
        },
        "friend_query_visibility": {"allow_query_visible_to_friends": True},
        "anonymous_tickets": {"require_for_lan_friend_search": True},
        "routing_goal": "balanced",
    })


def _build_private_circle() -> SearchPolicy:
    return SearchPolicy.parse("private_circle", {
        "route_order": ["LOCAL_CACHE", "LOCAL_INDREX", "LAN_FRIEND_DCNET"],
        "allow": {
            "local_cache": True, "local_indrex": True,
            "lan_friend_dcnet": True, "lan_friend_direct_placeholder": False,
            "self_public_egress": False,
        },
        "public_egress": {"mode": "deny"},
        "cache": {
            "allow_result_cache": True,
            "allowed_origin_paths": ["LOCAL_INDREX", "LAN_FRIEND_DCNET"],
            "disclose_origin_paths": True,
        },
        "friend_query_visibility": {"allow_query_visible_to_friends": True},
        "anonymous_tickets": {"require_for_lan_friend_search": True},
        "routing_goal": "privacy_first",
    })


def _build_local_only() -> SearchPolicy:
    return SearchPolicy.parse("local_only", {
        "route_order": ["LOCAL_CACHE", "LOCAL_INDREX"],
        "allow": {
            "local_cache": True, "local_indrex": True,
            "lan_friend_dcnet": False, "lan_friend_direct_placeholder": False,
            "self_public_egress": False,
        },
        "public_egress": {"mode": "deny"},
        "cache": {
            "allow_result_cache": True,
            "allowed_origin_paths": ["LOCAL_INDREX"],
            "disclose_origin_paths": True,
        },
        "friend_query_visibility": {"allow_query_visible_to_friends": False},
        "anonymous_tickets": {"require_for_lan_friend_search": False},
        "routing_goal": "privacy_first",
    })


def _build_dev_placeholder() -> SearchPolicy:
    return SearchPolicy.parse("dev_placeholder_friends", {
        "route_order": [
            "LOCAL_CACHE", "LOCAL_INDREX",
            "LAN_FRIEND_DIRECT_PLACEHOLDER", "SELF_PUBLIC_EGRESS",
        ],
        "allow": {
            "local_cache": True, "local_indrex": True,
            "lan_friend_dcnet": False, "lan_friend_direct_placeholder": True,
            "self_public_egress": True,
        },
        "public_egress": {"mode": "confirm"},
        "cache": {
            "allow_result_cache": True,
            "allowed_origin_paths": ["LOCAL_INDREX", "LAN_FRIEND_DIRECT_PLACEHOLDER"],
            "disclose_origin_paths": True,
        },
        "friend_query_visibility": {"allow_query_visible_to_friends": True},
        "anonymous_tickets": {"require_for_lan_friend_search": False},
        "routing_goal": "dev",
    })


BUILT_IN_POLICIES: dict[str, SearchPolicy] = {
    "default": _build_default(),
    "private_circle": _build_private_circle(),
    "local_only": _build_local_only(),
    "dev_placeholder_friends": _build_dev_placeholder(),
}
