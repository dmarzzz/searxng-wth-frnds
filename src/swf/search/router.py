"""SPEC v0.3 §15 + §29.3 search router.

Walks `policy.route_order`, dispatches to a handler per route, applies
§14 sufficiency, and returns a §11.1 SearchResponse. Handlers are
plain `RouteHandler` records living in their own modules; new routes
plug in by appending to `_HANDLERS`.

Phase wiring:
- Phase 1 — LOCAL_CACHE, LOCAL_INDREX
- Phase 2 — SELF_PUBLIC_EGRESS (with §15+§26 confirmation gate)
- Phase 3 — LAN_FRIEND_DIRECT_PLACEHOLDER
- Phase 4 — LAN_FRIEND_DCNET (still emits route_not_implemented)
"""
from __future__ import annotations

import time

from . import (
    audit,
    lan_friend_dcnet,
    lan_friend_direct,
    local_cache,
    local_indrex,
    public_egress,
    reputation,
    sufficiency,
)
from .policy import (
    BUILT_IN_POLICIES,
    PublicEgressMode,
    SearchPolicy,
)
from .query import QueryContext, build_context
from .response import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResponse,
    Status,
)
from .route import RouteHandler, RouteOutcome

# ─── per-route adapters ───────────────────────────────────────────────
# Phase 1's LOCAL_CACHE / LOCAL_INDREX modules predate `RouteOutcome`,
# so we wrap them at this seam. New phase modules speak RouteOutcome
# directly via their own HANDLER records.

def _cache_handler(ctx: QueryContext, policy: SearchPolicy) -> RouteOutcome:
    rs = local_cache.lookup(
        ctx.normalized_query,
        allowed_origin_paths=policy.cache.allowed_origin_paths,
    )
    privacy: PrivacyLevel | None = None
    warnings: list[str] = list(rs.warnings)
    if rs.results:
        privacy = _privacy_for_cache_replay(rs.origin_paths)
        if privacy == PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT:
            warnings.append(
                "Returned from local cache, but these results were "
                "originally obtained through self public egress."
            )
    return RouteOutcome(
        attempt=rs.attempt,
        results=rs.results,
        origin_paths=list(rs.origin_paths),
        dominant_origin_path=(rs.dominant_origin_path
                              or (rs.origin_paths[0] if rs.origin_paths else None)),
        privacy_level=privacy,
        warnings=warnings,
        network_used=False,
        public_egress_used=False,
    )


def _indrex_handler(ctx: QueryContext, policy: SearchPolicy) -> RouteOutcome:
    rs = local_indrex.search(ctx.raw_query, top_k=ctx.requested_top_k)
    return RouteOutcome(
        attempt=rs.attempt,
        results=rs.results,
        origin_paths=[OriginPath.LOCAL_INDREX] if rs.results else [],
        dominant_origin_path=OriginPath.LOCAL_INDREX if rs.results else None,
        privacy_level=PrivacyLevel.LOCAL_ONLY if rs.results else None,
        network_used=False,
        public_egress_used=False,
    )


_CACHE_HANDLER = RouteHandler(
    name=DeliveryPath.LOCAL_CACHE,
    is_enabled=lambda p: p.allow.local_cache,
    run=_cache_handler,
)
_INDREX_HANDLER = RouteHandler(
    name=DeliveryPath.LOCAL_INDREX,
    is_enabled=lambda p: p.allow.local_indrex,
    run=_indrex_handler,
)


# Order in this dict doesn't matter; the actual walk follows
# `policy.route_order`. New handlers register here.
#
# `lan_friend_dcnet.HANDLER` is registered unconditionally but its
# `is_enabled(policy)` callable returns False unless `SWF_ENABLE_DCNET`
# is set AND `policy.allow.lan_friend_dcnet` is true. Without the env
# flag, the router behaves exactly as before — emits a
# `route_not_implemented` attempt and moves on. With the flag, the
# stub runs but only labels the response as anonymous when a real
# DC-net transport with min_anonymity_set_met=true is registered;
# the §29.2 invariants enforce that boundary.
_HANDLERS: dict[DeliveryPath, RouteHandler] = {
    DeliveryPath.LOCAL_CACHE: _CACHE_HANDLER,
    DeliveryPath.LOCAL_INDREX: _INDREX_HANDLER,
    DeliveryPath.LAN_FRIEND_DCNET: lan_friend_dcnet.HANDLER,
    DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER: lan_friend_direct.HANDLER,
    DeliveryPath.SELF_PUBLIC_EGRESS: public_egress.HANDLER,
}


# ─── top-level entry point ────────────────────────────────────────────

def web_search(
    q: str,
    *,
    policy_name: str = "default",
    policies: dict[str, SearchPolicy] | None = None,
    caller: str | None = None,
    requested_top_k: int = 10,
    request_id: str | None = None,
    confirm_public_egress: bool = False,
) -> SearchResponse:
    """§15 router entry. The HTTP `POST /web_search` handler calls this
    and returns the JSON form via `.to_json()`.

    `confirm_public_egress` is the client's "yes, I really want to send
    this query to the public web" signal. If a previous call returned
    `status=confirmation_required`, the client retries with this set.
    """
    policies = policies or BUILT_IN_POLICIES
    if policy_name not in policies:
        resp = _error(ctx=None, request_id=request_id,
                      reason=f"unknown_policy:{policy_name}",
                      requested_name=policy_name)
        audit.emit(resp)
        return resp

    policy = policies[policy_name]
    ctx = build_context(q, policy_name=policy_name,
                        requested_top_k=requested_top_k,
                        caller=caller, request_id=request_id)
    if not q or not q.strip():
        resp = _error(ctx=ctx, request_id=ctx.request_id, reason="empty_query")
        audit.emit(resp)
        return resp

    attempts: list[SearchAttempt] = []
    fallbacks: list[DeliveryPath] = []

    for path in policy.route_order:
        handler = _HANDLERS.get(path)
        if handler is None:
            attempts.append(_not_implemented_attempt(path))
            fallbacks.append(path)
            continue
        if not handler.is_enabled(policy):
            # Policy parser already rejects route_order ⊄ allow, but
            # leave the guard for externally-loaded policies that may
            # have skipped the consistency check.
            continue

        # §15 + §26 / issue #89: SELF_PUBLIC_EGRESS is gated whenever
        # the policy isn't a hard DENY. Policy can hard-DENY (mode=deny);
        # otherwise the client's `confirm_public_egress` is authoritative.
        # Before #89 the gate only fired for `mode=confirm`, which meant
        # the built-in `default` policy (`mode=allow`) silently
        # overrode an unchecked visualizer toggle. Now `mode: allow` and
        # `mode: confirm` both require explicit client confirmation;
        # only a hard DENY skips this gate (DENY routes are normally
        # filtered out earlier by allow.self_public_egress=false anyway,
        # but the inequality keeps that semantics regardless).
        if path == DeliveryPath.SELF_PUBLIC_EGRESS and \
           policy.public_egress.mode != PublicEgressMode.DENY and \
           not confirm_public_egress:
            resp = _confirmation_required(
                ctx, policy, attempts, fallbacks,
                reason="public_egress_requires_confirmation",
            )
            audit.emit(resp)
            return resp

        outcome = handler.run(ctx, policy)
        attempts.append(outcome.attempt)

        if outcome.results:
            suff = sufficiency.check(outcome.results, ctx)
            if suff.sufficient:
                resp = _build_response(
                    ctx, policy, outcome,
                    attempts=attempts, fallbacks=fallbacks,
                    sufficiency_reason=suff.reason,
                )
                _maybe_cache(ctx, policy, outcome)
                audit.emit(resp)
                return resp
            attempts[-1] = _annotate(outcome.attempt,
                                     reason=f"insufficient:{suff.reason}")

        # §15 lines 873-881 + §26 downgrade_protection: if a private
        # route failed suspiciously and policy demands confirmation
        # after such failures, escalate.
        if outcome.suspicious_failure and \
           policy.public_egress.confirm_after_suspicious_private_failure and \
           policy.public_egress.mode != PublicEgressMode.DENY and \
           path != DeliveryPath.SELF_PUBLIC_EGRESS and \
           not confirm_public_egress:
            resp = _confirmation_required(
                ctx, policy, attempts, fallbacks,
                reason="private_route_failed_suspiciously",
                proposed_path=DeliveryPath.SELF_PUBLIC_EGRESS,
            )
            audit.emit(resp)
            return resp

        fallbacks.append(path)

    # Every route exhausted without a sufficient hit. Honest NO_RESULT.
    # Origin_paths must include SELF_PUBLIC_EGRESS if any attempted
    # route consumed the egress flag (red-team pass-2 / live fuzz F5):
    # otherwise the response would silently drop the audit trail of
    # which path leaked the query into the public web.
    network_used = any(a.network_used for a in attempts)
    public_used = any(a.public_egress_used for a in attempts)
    no_result_origins = _origins_from_attempts(attempts,
                                                seed=[OriginPath.NO_RESULT])
    resp = SearchResponse.make(
        status=Status.NO_RESULTS,
        request_id=ctx.request_id,
        created_ms=ctx.created_ms,
        completed_ms=int(time.time() * 1000),
        delivery_path=DeliveryPath.NO_RESULT,
        origin_paths=no_result_origins,
        dominant_origin_path=OriginPath.NO_RESULT,
        privacy_level=PrivacyLevel.NONE,
        network_used_this_request=network_used,
        public_egress_used_this_request=public_used,
        friend_query_visible=False,
        policy=_policy_block(policy),
        fallbacks_tried=fallbacks,
        fallback_reason="all_routes_exhausted",
        warnings=[],
        attempts=attempts,
        results=[],
        debug={"query_hmac": ctx.query_hmac,
               "sufficiency": {"sufficient": False,
                               "reason": "no_route_succeeded"}},
    )
    audit.emit(resp)
    return resp


# ─── helpers ──────────────────────────────────────────────────────────

def _not_implemented_attempt(path: DeliveryPath) -> SearchAttempt:
    """For paths that still don't have a handler (Phase 4 LAN_FRIEND_DCNET)."""
    now_ms = int(time.time() * 1000)
    return SearchAttempt(
        path=path, status="route_not_implemented",
        started_ms=now_ms, completed_ms=now_ms, duration_ms=0,
        reason="handler_not_registered",
        results_count=0, network_used=False, public_egress_used=False,
    )


def _build_response(
    ctx: QueryContext,
    policy: SearchPolicy,
    outcome: RouteOutcome,
    *,
    attempts: list[SearchAttempt],
    fallbacks: list[DeliveryPath],
    sufficiency_reason: str,
) -> SearchResponse:
    debug: dict = {
        "query_hmac": ctx.query_hmac,
        "sufficiency": {"sufficient": True, "reason": sufficiency_reason},
    }
    if outcome.extras:
        debug["route"] = outcome.extras

    # §29.10 reputation enrichment: populate provider_score_local on
    # every result that has a provider_pubkey. The router does NOT
    # re-rank by default — sufficiency thresholds ran on the
    # un-reranked list, by design (route quality is about the route,
    # not the contributor). Clients that want re-ranking call
    # `reputation.rerank()` themselves.
    reputation.enrich_results(outcome.results)

    return SearchResponse.make(
        status=Status.OK,
        request_id=ctx.request_id,
        created_ms=ctx.created_ms,
        completed_ms=int(time.time() * 1000),
        delivery_path=outcome.attempt.path,
        origin_paths=outcome.origin_paths,
        dominant_origin_path=outcome.dominant_origin_path
                             or outcome.origin_paths[0],
        privacy_level=outcome.privacy_level,
        network_used_this_request=outcome.network_used,
        public_egress_used_this_request=outcome.public_egress_used,
        friend_query_visible=outcome.friend_query_visible,
        policy=_policy_block(policy),
        anonymous_ticket=outcome.anonymous_ticket,
        fallbacks_tried=fallbacks,
        warnings=outcome.warnings,
        attempts=attempts,
        results=outcome.results,
        debug=debug,
    )


def _maybe_cache(
    ctx: QueryContext,
    policy: SearchPolicy,
    outcome: RouteOutcome,
) -> None:
    """Cache the outcome iff the active policy allows it AND the
    dominant origin is in `policy.cache.allowed_origin_paths`. The
    cache layer's lookup-time gate is a separate defense."""
    if not policy.cache.allow_result_cache:
        return
    if outcome.attempt.path == DeliveryPath.LOCAL_CACHE:
        return  # don't re-cache a cache replay
    if outcome.dominant_origin_path is None or \
       outcome.dominant_origin_path not in policy.cache.allowed_origin_paths:
        return
    local_cache.store(
        ctx.normalized_query,
        delivery_path=outcome.attempt.path,
        origin_paths=outcome.origin_paths,
        dominant_origin_path=outcome.dominant_origin_path,
        privacy_level=(outcome.privacy_level.value
                       if outcome.privacy_level else "none"),
        results=outcome.results,
        warnings=outcome.warnings,
    )


def _privacy_for_cache_replay(origins: list[OriginPath]) -> PrivacyLevel:
    """§6: cache replay of a public-egress result must be labelled
    differently from a cache replay of a purely local result."""
    if OriginPath.SELF_PUBLIC_EGRESS in origins:
        return PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT
    return PrivacyLevel.LOCAL_REPLAY


def _annotate(a: SearchAttempt, *, reason: str) -> SearchAttempt:
    return SearchAttempt(
        path=a.path, status=a.status,
        started_ms=a.started_ms, completed_ms=a.completed_ms,
        duration_ms=a.duration_ms,
        reason=reason or a.reason,
        results_count=a.results_count,
        network_used=a.network_used,
        public_egress_used=a.public_egress_used,
        suspicious_failure=a.suspicious_failure,
    )


_ATTEMPT_TO_ORIGIN: dict[DeliveryPath, OriginPath] = {
    DeliveryPath.SELF_PUBLIC_EGRESS: OriginPath.SELF_PUBLIC_EGRESS,
    DeliveryPath.LAN_FRIEND_DCNET: OriginPath.LAN_FRIEND_DCNET,
    DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER:
        OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
}


def _origins_from_attempts(
    attempts: list[SearchAttempt],
    *,
    seed: list[OriginPath],
) -> list[OriginPath]:
    """Build an `origin_paths` list that includes `seed` plus every
    network-touching attempt's origin. Pass-4 finding #2 / invariant
    1c requires this for any envelope where `network_used=true`."""
    out = list(seed)
    for a in attempts:
        if not (a.network_used or a.public_egress_used):
            continue
        origin = _ATTEMPT_TO_ORIGIN.get(a.path)
        if origin is not None and origin not in out:
            out.append(origin)
    return out


def _policy_block(p: SearchPolicy) -> dict:
    return {
        "requested": p.name,
        "effective": p.name,
        "routing_goal": p.routing_goal.value,
    }


def _confirmation_required(
    ctx: QueryContext, policy: SearchPolicy,
    attempts: list[SearchAttempt], fallbacks: list[DeliveryPath],
    *, reason: str,
    proposed_path: DeliveryPath = DeliveryPath.SELF_PUBLIC_EGRESS,
) -> SearchResponse:
    network_used = any(a.network_used for a in attempts)
    public_used = any(a.public_egress_used for a in attempts)
    # Pass-4 finding #2: every attempt that touched the network must
    # appear in origin_paths so the §29.2 audit trail isn't silently
    # incomplete. The new invariant 1c rejects responses that claim
    # network_used=true with no network-touching origin.
    origin_paths = _origins_from_attempts(attempts,
                                           seed=[OriginPath.NO_RESULT])
    return SearchResponse.make(
        status=Status.CONFIRMATION_REQUIRED,
        request_id=ctx.request_id,
        created_ms=ctx.created_ms,
        completed_ms=int(time.time() * 1000),
        delivery_path=DeliveryPath.NO_RESULT,
        origin_paths=origin_paths,
        dominant_origin_path=OriginPath.NO_RESULT,
        privacy_level=PrivacyLevel.NONE,
        network_used_this_request=network_used,
        public_egress_used_this_request=public_used,
        policy=_policy_block(policy),
        fallbacks_tried=fallbacks,
        fallback_reason=reason,
        warnings=[
            "Confirmation required before falling back to public egress. "
            "Retry with confirm_public_egress=true to proceed.",
        ],
        attempts=attempts,
        results=[],
        debug={
            "query_hmac": ctx.query_hmac,
            "proposed_path": proposed_path.value,
            "reason": reason,
        },
    )


def _error(*, ctx: QueryContext | None, request_id: str | None,
           reason: str, requested_name: str | None = None) -> SearchResponse:
    """Error envelope (unknown policy / empty query / etc.). Even on
    the error path the response carries a §11.1-shaped `policy` block
    so clients can render it uniformly — live fuzz F6.

    `requested_name` overrides the ctx-derived name; useful for the
    unknown-policy path where ctx is None but we still want to echo
    back what the client asked for."""
    rid = request_id or (ctx.request_id if ctx else "req_error")
    cms = ctx.created_ms if ctx else int(time.time() * 1000)
    name = requested_name or (ctx.policy_name if ctx else "default")
    policy_block = {
        "requested": name,
        "effective": "default",
        "routing_goal": "balanced",
    }
    return SearchResponse.make(
        status=Status.ERROR,
        request_id=rid, created_ms=cms,
        completed_ms=int(time.time() * 1000),
        delivery_path=DeliveryPath.NO_RESULT,
        origin_paths=[OriginPath.NO_RESULT],
        dominant_origin_path=OriginPath.NO_RESULT,
        privacy_level=PrivacyLevel.NONE,
        network_used_this_request=False,
        public_egress_used_this_request=False,
        friend_query_visible=False,
        policy=policy_block, fallbacks_tried=[], warnings=[],
        attempts=[], results=[],
        debug={"reason": reason,
               "query_hmac": ctx.query_hmac if ctx else None},
    )
