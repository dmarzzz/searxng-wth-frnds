"""Direct tests for `swf.search.route` — the `RouteHandler` /
`RouteOutcome` contracts that all route modules speak.

These types were exercised indirectly through the router and per-route
test files. This module pins their shape so a future refactor can't
quietly break the contract.
"""
from __future__ import annotations

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResult,
)
from swf.search.response import (
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)
from swf.search.route import RouteHandler, RouteOutcome


def _attempt(path: DeliveryPath = DeliveryPath.LOCAL_INDREX,
             status: str = "ok") -> SearchAttempt:
    return SearchAttempt(
        path=path, status=status,
        started_ms=1, completed_ms=2, duration_ms=1,
        results_count=0,
    )


def _result(url: str = "https://x.example/1") -> SearchResult:
    return SearchResult(
        result_id="res_x", canonical_url=url, display_url=url,
        title="t", snippet="s", score=0.5, rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=OriginPath.LOCAL_INDREX,
        provider=_Provider(), freshness=_Freshness(),
        verification=_Verification(), receipt=_Receipt(),
        safety=_Safety(),
    )


# ─── RouteOutcome shape ─────────────────────────────────────────────

def test_outcome_defaults_are_safe():
    """Default-constructed RouteOutcome is a no-result, no-network,
    no-leak shape — this is the empty-attempt baseline."""
    out = RouteOutcome(attempt=_attempt(status="miss"))
    assert out.results == []
    assert out.origin_paths == []
    assert out.dominant_origin_path is None
    assert out.privacy_level is None
    assert out.warnings == []
    assert out.network_used is False
    assert out.public_egress_used is False
    assert out.friend_query_visible is False
    assert out.suspicious_failure is False
    assert out.anonymous_ticket == {}
    assert out.extras == {}


def test_outcome_hit_property():
    """`outcome.hit` is True iff results is non-empty."""
    miss = RouteOutcome(attempt=_attempt(status="miss"))
    assert miss.hit is False
    hit = RouteOutcome(attempt=_attempt(), results=[_result()])
    assert hit.hit is True


def test_outcome_extras_isolated_per_instance():
    """The default `extras={}` must NOT be shared across instances —
    `field(default_factory=dict)` is the right pattern; this test
    catches a future refactor that swaps in a mutable class default."""
    a = RouteOutcome(attempt=_attempt())
    b = RouteOutcome(attempt=_attempt())
    a.extras["k"] = "v"
    assert b.extras == {}


def test_outcome_warnings_isolated_per_instance():
    a = RouteOutcome(attempt=_attempt())
    b = RouteOutcome(attempt=_attempt())
    a.warnings.append("w1")
    assert b.warnings == []


def test_outcome_results_isolated_per_instance():
    a = RouteOutcome(attempt=_attempt())
    b = RouteOutcome(attempt=_attempt())
    a.results.append(_result())
    assert b.results == []


def test_outcome_origin_paths_isolated_per_instance():
    a = RouteOutcome(attempt=_attempt())
    b = RouteOutcome(attempt=_attempt())
    a.origin_paths.append(OriginPath.LOCAL_INDREX)
    assert b.origin_paths == []


# ─── RouteHandler shape ─────────────────────────────────────────────

def test_handler_dispatch_via_callables():
    """`is_enabled` and `run` are plain callables; nothing fancy."""
    seen = []
    def is_enabled(p):
        seen.append("e")
        return True
    def run(ctx, p):
        seen.append("r")
        return RouteOutcome(attempt=_attempt(status="ok"))
    h = RouteHandler(name=DeliveryPath.LOCAL_INDREX,
                     is_enabled=is_enabled, run=run)
    assert h.is_enabled(None) is True
    assert h.run(None, None).attempt.status == "ok"
    assert seen == ["e", "r"]
