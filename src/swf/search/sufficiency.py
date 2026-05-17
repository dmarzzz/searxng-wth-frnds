"""SPEC v0.3 §14 sufficiency heuristic.

Decides whether a route's result-set is "good enough" or whether the
router should fall through to the next route. The defaults match §14.1.

`Sufficiency` is a tiny named result so the router can carry the reason
into the response's `debug.sufficiency` block (§11.1).
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .query import FreshnessRequirement, QueryContext, QueryIntent
from .response import SearchResult

# §14 defaults.
DEFAULT_MIN_RESULTS = 3
DEFAULT_MIN_UNIQUE_HOSTS = 2
DEFAULT_MIN_TOP_SCORE = 0.25
DEFAULT_MIN_MEAN_SCORE = 0.18
DEFAULT_REQUIRE_FRESH_FOR_FRESHNESS = True
DEFAULT_ALLOW_SINGLE_EXACT_HIT = True


@dataclass(frozen=True)
class Sufficiency:
    sufficient: bool
    reason: str


def _host(url: str) -> str:
    try:
        h = urlparse(url).hostname or ""
        return h[4:] if h.startswith("www.") else h
    except Exception:
        return ""


def _exact_navigational_hit(results: list[SearchResult], ctx: QueryContext) -> bool:
    """Single high-score hit whose host matches the navigational query
    domain. §14.1 `allow_single_exact_hit` short-circuit."""
    if ctx.inferred_intent != QueryIntent.NAVIGATIONAL:
        return False
    if not results:
        return False
    top = results[0]
    if top.score < 0.50:
        return False
    return _host(top.canonical_url).endswith(ctx.normalized_query)


def check(
    results: list[SearchResult],
    ctx: QueryContext,
    *,
    min_results: int = DEFAULT_MIN_RESULTS,
    min_unique_hosts: int = DEFAULT_MIN_UNIQUE_HOSTS,
    min_top_score: float = DEFAULT_MIN_TOP_SCORE,
    min_mean_score: float = DEFAULT_MIN_MEAN_SCORE,
    require_fresh_for_freshness: bool = DEFAULT_REQUIRE_FRESH_FOR_FRESHNESS,
    allow_single_exact_hit: bool = DEFAULT_ALLOW_SINGLE_EXACT_HIT,
) -> Sufficiency:
    """§14.1 reference implementation. `results` is the merged set so far
    for this route — assumes scores are normalized to `[0, 1]` per §11.4."""
    scored = [r for r in results if r.score is not None]
    if not scored:
        return Sufficiency(False, "no_results")

    if ctx.freshness_requirement == FreshnessRequirement.REQUIRE_FRESH \
            and require_fresh_for_freshness:
        # Phase 1 doesn't carry per-result staleness yet; we conservatively
        # treat LOCAL_INDREX-only result sets as not freshness-meeting if
        # the request requires fresh. Phase 1 will continue routing.
        # (Phase 2 SELF_PUBLIC_EGRESS attaches `served_at_ms` and we'll
        # actually evaluate the cutoff.)
        return Sufficiency(False, "freshness_not_met")

    if allow_single_exact_hit and _exact_navigational_hit(scored, ctx):
        return Sufficiency(True, "single_exact_hit")

    if len(scored) < min_results:
        return Sufficiency(False, "too_few_results")

    hosts = {_host(r.canonical_url) for r in scored if _host(r.canonical_url)}
    if len(hosts) < min_unique_hosts:
        return Sufficiency(False, "too_little_source_diversity")

    top_score = max(r.score for r in scored)
    if top_score < min_top_score:
        return Sufficiency(False, "top_score_too_low")

    top3 = sorted((r.score for r in scored), reverse=True)[:3]
    mean3 = sum(top3) / max(1, len(top3))
    if mean3 < min_mean_score:
        return Sufficiency(False, "mean_score_too_low")

    return Sufficiency(True, "thresholds_met")
