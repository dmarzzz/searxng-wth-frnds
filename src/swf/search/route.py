"""Common route-handler types.

Phase 1 had `IndrexResultSet` and `CacheResultSet` as ad-hoc per-route
shapes. Phase 2 adds a third (`PublicEgressResultSet`) and Phase 3 a
fourth. Architecture review's #3 recommendation: unify on a single
`RouteOutcome` so the §15 router algorithm can iterate handlers
generically.

A `RouteHandler` is anything callable with `(ctx, policy) -> RouteOutcome`.
Each handler is responsible for stamping its own attempt timing,
attaching origin metadata, and labeling network/public-egress flags
honestly. The router only orchestrates — it never relabels what a
handler reports.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .response import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResult,
)


@dataclass
class RouteOutcome:
    """One route's result. The router treats every route uniformly: a
    successful handler returns `results` non-empty and `attempt.status`
    in `{"ok", "partial"}`; a missed/skipped/erroring handler returns
    `results=[]` with the appropriate attempt status."""
    attempt: SearchAttempt
    results: list[SearchResult] = field(default_factory=list)
    origin_paths: list[OriginPath] = field(default_factory=list)
    dominant_origin_path: OriginPath | None = None
    privacy_level: PrivacyLevel | None = None
    warnings: list[str] = field(default_factory=list)
    network_used: bool = False
    public_egress_used: bool = False
    friend_query_visible: bool = False
    suspicious_failure: bool = False
    anonymous_ticket: dict[str, Any] = field(default_factory=dict)
    # Per-route extras the wall / clients can render but the router
    # doesn't reason about (e.g. SearXNG `engines_returned`, friend
    # `peer_count`). Threaded into response.debug under route name.
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def hit(self) -> bool:
        return bool(self.results)


# A RouteHandler is a thin shim: name (DeliveryPath), enablement check,
# and the run callable. Implementations live in their own modules
# (local_cache, local_indrex, public_egress, lan_friend_direct, ...).
@dataclass
class RouteHandler:
    name: DeliveryPath
    is_enabled: Callable[..., bool]   # (policy) -> bool
    run: Callable[..., RouteOutcome]  # (ctx, policy) -> RouteOutcome
