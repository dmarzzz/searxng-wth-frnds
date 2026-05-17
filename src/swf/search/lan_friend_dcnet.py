"""SPEC v0.3 §17 + §29.6 / §29.7 LAN_FRIEND_DCNET — interface stub.

This module ships the **interface skeleton** (`FriendSearchTransport`
Protocol, `ActiveCircle` / `PeerDiscoveryResult` / `FriendSearchOutcome`
dataclasses, and the `RouteHandler` glue) so a future PR can plug in a
real DC-net transport in one place without touching the router.

It does NOT ship cryptographic anonymity. Spec §2 explicitly excludes
formal DC-net cryptographic proof from this version, and §27.10 forbids
hand-rolling the primitives. Until a vetted DC-net library lands:

  * The default transport is `_NullTransport` — `min_anonymity_set_met`
    is always False, so §17.2 prevents the route from claiming
    `LAN_FRIEND_DCNET` at all.
  * The route is gated behind `SWF_ENABLE_DCNET=1`. With the flag UNSET
    the handler reports `is_enabled=False` and the router emits the
    existing `route_not_implemented` attempt — same behavior as before
    this module shipped.
  * With the flag SET, the handler runs but returns
    `attempt.status="dev_no_crypto"` and falls through; the router
    moves on to the next route. **Even with the flag set, no response
    is ever labeled with the §6 anonymity claim** — the §29.2 invariant
    check would reject any envelope that tried.

To plug in a real DC-net transport: implement `FriendSearchTransport`,
register the instance via `set_transport(...)`, and update
`_DEV_NO_CRYPTO_REASON` to a real success path. The §29.2 invariants
already enforce the privacy contract; nothing else in the router needs
to change.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .policy import SearchPolicy
from .query import QueryContext
from .response import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResult,
)
from .route import RouteHandler, RouteOutcome

# ── §17.1 ActiveCircle metadata ─────────────────────────────────────

@dataclass(frozen=True)
class ActiveCircle:
    """§17.1. The transport reports this so the router can decide
    whether `LAN_FRIEND_DCNET` is claimable per §17.2:
      - transport_kind == "dcnet_real"
      - active_peer_count >= configured min_anonymity_set
      - membership_fixed_for_round
      - min_anonymity_set_met
      - requester_anonymity_claim != "none"
    """
    epoch_id: str
    active_peer_count: int
    min_anonymity_set_met: bool
    membership_fixed_for_round: bool
    requester_anonymity_claim: str   # e.g. "anonymous_within_lan_circle_query_visible"
    transport_kind: str              # "dcnet_real" | "direct_placeholder" | "disabled"


@dataclass(frozen=True)
class PeerDiscoveryResult:
    """§17 discover_peers() shape."""
    peers: tuple[str, ...] = ()      # opaque identifiers; do NOT include IPs
    epoch_id: str = ""


@dataclass
class FriendSearchOutcome:
    """§17 search() return — the router converts this to a RouteOutcome."""
    results: list[SearchResult] = field(default_factory=list)
    suspicious_failure: bool = False
    reason: str = ""


# ── §17 FriendSearchTransport Protocol ──────────────────────────────

@runtime_checkable
class FriendSearchTransport(Protocol):
    """Drop-in interface for any DC-net implementation. The current
    `_NullTransport` is the placeholder; a real RFC-9474+library pair
    would implement this verbatim."""
    name: str
    privacy_level: str               # what the transport claims to provide

    def discover_peers(self) -> PeerDiscoveryResult: ...
    def active_circle(self) -> ActiveCircle: ...
    def search(self, ctx: QueryContext) -> FriendSearchOutcome: ...


# ── default null transport ──────────────────────────────────────────

class _NullTransport:
    """Default transport. Reports an empty circle so §17.2 correctly
    prevents the route from claiming `LAN_FRIEND_DCNET`. Returns no
    results. Documented as "no real anonymity"; never lies."""
    name = "null"
    privacy_level = "none"

    def discover_peers(self) -> PeerDiscoveryResult:
        return PeerDiscoveryResult(peers=(), epoch_id="dev")

    def active_circle(self) -> ActiveCircle:
        return ActiveCircle(
            epoch_id="dev",
            active_peer_count=0,
            min_anonymity_set_met=False,
            membership_fixed_for_round=False,
            requester_anonymity_claim="none",
            transport_kind="disabled",
        )

    def search(self, ctx: QueryContext) -> FriendSearchOutcome:
        return FriendSearchOutcome(
            results=[],
            suspicious_failure=False,
            reason=_DEV_NO_CRYPTO_REASON,
        )


_DEV_NO_CRYPTO_REASON = (
    "dev_no_crypto: SWF_ENABLE_DCNET is set but no real DC-net transport "
    "is registered. Route falls through; no anonymity claim is made."
)


# Module-level slot so a real transport can be installed via
# `set_transport(...)`. Single-process scope; tests can swap it.
_active_transport: FriendSearchTransport = _NullTransport()


def set_transport(t: FriendSearchTransport) -> None:
    """Register a real DC-net transport. Idempotent. The new instance
    wholly replaces the previous one — there is no transport stack."""
    global _active_transport
    _active_transport = t


def get_transport() -> FriendSearchTransport:
    return _active_transport


def reset_transport() -> None:
    """Restore the null transport. For tests."""
    global _active_transport
    _active_transport = _NullTransport()


# ── feature flag ────────────────────────────────────────────────────

def _flag_enabled() -> bool:
    """`SWF_ENABLE_DCNET=1` (or `true` / `yes`) opts the route in.
    Default off — preserves the pre-Phase-4 behavior verbatim."""
    return (os.environ.get("SWF_ENABLE_DCNET") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# ── route handler ───────────────────────────────────────────────────

def _is_enabled(policy: SearchPolicy) -> bool:
    """Two-key lock: the policy must allow the route AND the operator
    must opt in via `SWF_ENABLE_DCNET`. Without both, this handler
    behaves as if it didn't exist — the router emits the existing
    `route_not_implemented` attempt and moves on."""
    return policy.allow.lan_friend_dcnet and _flag_enabled()


def search(ctx: QueryContext) -> RouteOutcome:
    """The route's `run` callable. Constructs a RouteOutcome from the
    active transport's `search()` plus its `active_circle()` view.

    **§17.2 rule**: this function MUST NOT label the outcome with
    `LAN_FRIEND_DCNET` privacy unless `circle.min_anonymity_set_met`
    is True AND `circle.transport_kind == "dcnet_real"`. The default
    `_NullTransport` always returns `min_anonymity_set_met=False`, so
    the privacy claim is never made under it. The §29.2 invariants
    enforce the same boundary at construction time."""
    started_ms = int(time.time() * 1000)
    transport = get_transport()
    circle = transport.active_circle()
    outcome = transport.search(ctx)

    completed_ms = int(time.time() * 1000)

    # Policy: claim DCNET privacy iff the transport says it can.
    can_claim_anonymity = (
        circle.transport_kind == "dcnet_real"
        and circle.min_anonymity_set_met
        and circle.membership_fixed_for_round
    )

    if can_claim_anonymity and outcome.results:
        # Real DCNET path with a working transport. Privacy claim
        # validated against §29.2 invariant 5 (DCNET ⇒ query-visible
        # anonymous label).
        attempt = SearchAttempt(
            path=DeliveryPath.LAN_FRIEND_DCNET,
            status="ok",
            started_ms=started_ms, completed_ms=completed_ms,
            duration_ms=completed_ms - started_ms,
            results_count=len(outcome.results),
            network_used=True, public_egress_used=False,
            suspicious_failure=outcome.suspicious_failure,
        )
        return RouteOutcome(
            attempt=attempt,
            results=outcome.results,
            origin_paths=[OriginPath.LAN_FRIEND_DCNET],
            dominant_origin_path=OriginPath.LAN_FRIEND_DCNET,
            privacy_level=PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE,
            warnings=["Friend peers can see the query content."],
            network_used=True,
            friend_query_visible=True,
            anonymous_ticket={"required": True, "presented": True,
                              "accepted": True},
            extras={
                "circle": {
                    "epoch_id": circle.epoch_id,
                    "active_peer_count": circle.active_peer_count,
                    "transport_kind": circle.transport_kind,
                },
            },
        )

    # Stub / null / insufficient-anonymity path. Don't lie. Return an
    # empty outcome with a clear reason; router falls through to next.
    reason = outcome.reason or (
        "anonymity_set_not_met"
        if circle.transport_kind == "dcnet_real"
        else "dev_no_crypto"
    )
    attempt = SearchAttempt(
        path=DeliveryPath.LAN_FRIEND_DCNET,
        status="unavailable",
        started_ms=started_ms, completed_ms=completed_ms,
        duration_ms=completed_ms - started_ms,
        reason=reason,
        results_count=0,
        network_used=False, public_egress_used=False,
        suspicious_failure=outcome.suspicious_failure,
    )
    return RouteOutcome(
        attempt=attempt,
        results=[],
        origin_paths=[],
        dominant_origin_path=None,
        privacy_level=None,
        network_used=False,
        extras={
            "transport": transport.name,
            "transport_kind": circle.transport_kind,
            "active_peer_count": circle.active_peer_count,
            "min_anonymity_set_met": circle.min_anonymity_set_met,
        },
    )


HANDLER = RouteHandler(
    name=DeliveryPath.LAN_FRIEND_DCNET,
    is_enabled=_is_enabled,
    run=lambda ctx, policy: search(ctx),
)
