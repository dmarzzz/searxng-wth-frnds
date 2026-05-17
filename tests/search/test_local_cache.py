"""LOCAL_CACHE tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchResult,
    local_cache,
)
from swf.search.response import (
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path: Path, monkeypatch):
    """Each test gets its own cache DB + secret file. Prevents tests from
    contaminating each other or the user's real cache."""
    monkeypatch.setenv("SWF_CACHE_DB", str(tmp_path / "search_cache.db"))
    monkeypatch.setenv("SWF_CACHE_SECRET_FILE", str(tmp_path / "secret.bin"))
    yield


def _result(url: str, *, origin: OriginPath = OriginPath.LOCAL_INDREX) -> SearchResult:
    return SearchResult(
        result_id=f"res_{abs(hash(url))%10**8:08d}",
        canonical_url=url,
        display_url=url,
        title=f"Title {url}",
        snippet=f"Snippet for {url}",
        score=0.7,
        rank=1,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_path=origin,
        source="test",
        provider=_Provider(),
        freshness=_Freshness(),
        verification=_Verification(),
        receipt=_Receipt(),
        safety=_Safety(share_scope="friends"),
    )


# ─── store + lookup round-trip ─────────────────────────────────────────

def test_store_and_lookup_round_trip():
    res = [_result("https://a.example.com/1"), _result("https://b.example.com/2")]
    local_cache.store(
        "differential privacy",
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_ONLY.value,
        results=res,
    )
    rs = local_cache.lookup("differential privacy",
                            allowed_origin_paths=[OriginPath.LOCAL_INDREX])
    assert rs.attempt.status == "ok"
    assert len(rs.results) == 2
    # delivery_path on rebuilt rows is LOCAL_CACHE; origin_path is preserved
    for r in rs.results:
        assert r.delivery_path == DeliveryPath.LOCAL_CACHE
        assert r.origin_path == OriginPath.LOCAL_INDREX


def test_lookup_miss_when_query_absent():
    rs = local_cache.lookup("something never seen",
                            allowed_origin_paths=[OriginPath.LOCAL_INDREX])
    assert rs.attempt.status == "miss"
    assert rs.attempt.reason == "not_in_cache"


def test_origin_not_allowed_by_policy_blocks_replay():
    """If a query was cached with PUBLIC_EGRESS origin and the active
    policy forbids public origins, the cache must not return the entry."""
    res = [_result("https://search.example/q?x", origin=OriginPath.SELF_PUBLIC_EGRESS)]
    local_cache.store(
        "leaky query",
        delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.PUBLIC_FROM_SELF.value,
        results=res,
    )
    # local_only-ish allowed list: only LOCAL_INDREX origins allowed
    rs = local_cache.lookup("leaky query",
                            allowed_origin_paths=[OriginPath.LOCAL_INDREX])
    assert rs.attempt.status == "miss"
    assert rs.attempt.reason == "origin_not_allowed_by_policy"


def test_mixed_origin_cache_entry_blocked_by_strict_subset():
    """Red-team #2: a cached entry whose origins are
    [LOCAL_INDREX, SELF_PUBLIC_EGRESS] must NOT be replayed when the
    active policy only allows [LOCAL_INDREX]. The earlier intersection
    check returned the whole entry — public-tainted results included."""
    res = [
        _result("https://local.example/1", origin=OriginPath.LOCAL_INDREX),
        _result("https://search.example/q", origin=OriginPath.SELF_PUBLIC_EGRESS),
    ]
    local_cache.store(
        "mixed-origin query",
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX, OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT.value,
        results=res,
    )
    rs = local_cache.lookup("mixed-origin query",
                            allowed_origin_paths=[OriginPath.LOCAL_INDREX])
    assert rs.attempt.status == "miss"
    assert rs.attempt.reason == "origin_not_allowed_by_policy"
    # Confirm we did NOT silently return only the local result.
    assert rs.results == []


def test_normalized_query_drives_key():
    """A cache hit must work after whitespace/casing normalization on the
    LOOKUP side. The store path receives the already-normalized string;
    callers normalize via swf.search.query.normalize_query."""
    from swf.search.query import normalize_query
    nq = normalize_query("  Hello  WORLD  ")
    local_cache.store(
        nq,
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_ONLY.value,
        results=[_result("https://x.example/1")],
    )
    rs = local_cache.lookup(normalize_query("HELLO  world"),
                            allowed_origin_paths=[OriginPath.LOCAL_INDREX])
    assert rs.attempt.status == "ok"


def test_secret_persisted_across_processes():
    """Across two `_load_or_create_secret()` calls, the same bytes come
    back — that's what lets a separate process find an entry by its
    HMAC key."""
    s1 = local_cache._load_or_create_secret()
    s2 = local_cache._load_or_create_secret()
    assert s1 == s2
    assert len(s1) == 32


def test_vacuum_expired_drops_old_entries(monkeypatch):
    res = [_result("https://x.example/1")]
    local_cache.store(
        "old query",
        delivery_path=DeliveryPath.LOCAL_INDREX,
        origin_paths=[OriginPath.LOCAL_INDREX],
        dominant_origin_path=OriginPath.LOCAL_INDREX,
        privacy_level=PrivacyLevel.LOCAL_ONLY.value,
        results=res,
        ttl_hours=0,  # immediate expiry
    )
    n = local_cache.vacuum_expired()
    assert n >= 1
    # second pass: nothing left to drop
    assert local_cache.vacuum_expired() == 0
