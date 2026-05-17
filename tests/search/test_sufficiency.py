"""§14 sufficiency heuristic tests."""
from __future__ import annotations

from swf.search import (
    DeliveryPath,
    OriginPath,
    SearchResult,
    build_context,
)
from swf.search.response import (
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)
from swf.search.sufficiency import check


def _r(url: str, score: float = 0.5) -> SearchResult:
    return SearchResult(
        result_id=f"res_{abs(hash(url))%10**8:08d}",
        canonical_url=url,
        display_url=url,
        title="t",
        snippet="",
        score=score,
        rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=OriginPath.LOCAL_INDREX,
        provider=_Provider(),
        freshness=_Freshness(),
        verification=_Verification(),
        receipt=_Receipt(),
        safety=_Safety(),
    )


def _ctx(query: str = "differential privacy"):
    return build_context(query, policy_name="default", hmac_secret=b"x" * 32)


def test_sufficient_when_thresholds_met():
    rs = [_r("https://a.example/1", 0.9),
          _r("https://b.example/2", 0.7),
          _r("https://c.example/3", 0.5)]
    s = check(rs, _ctx())
    assert s.sufficient is True
    assert s.reason == "thresholds_met"


def test_insufficient_when_too_few_results():
    rs = [_r("https://a.example/1", 0.9),
          _r("https://b.example/2", 0.7)]  # below default min_results=3
    s = check(rs, _ctx())
    assert s.sufficient is False
    assert s.reason == "too_few_results"


def test_insufficient_when_top_score_too_low():
    # Three results, all below min_top_score=0.25
    rs = [_r("https://a/1", 0.10), _r("https://b/2", 0.05), _r("https://c/3", 0.02)]
    s = check(rs, _ctx())
    assert s.sufficient is False
    assert s.reason == "top_score_too_low"


def test_insufficient_when_all_same_host():
    rs = [_r("https://shared.example/1", 0.9),
          _r("https://shared.example/2", 0.7),
          _r("https://shared.example/3", 0.5)]
    s = check(rs, _ctx())
    assert s.sufficient is False
    assert s.reason == "too_little_source_diversity"


def test_freshness_required_query_falls_through_local_only():
    """A REQUIRE_FRESH query (`latest CVE…`) on Phase 1 falls through
    LOCAL_INDREX so the router can try a fresher route."""
    rs = [_r("https://a/1", 0.9), _r("https://b/2", 0.8), _r("https://c/3", 0.7)]
    s = check(rs, _ctx("latest cve openssl"))
    assert s.sufficient is False
    assert s.reason == "freshness_not_met"


def test_no_results_short_circuits():
    s = check([], _ctx())
    assert s.sufficient is False
    assert s.reason == "no_results"
