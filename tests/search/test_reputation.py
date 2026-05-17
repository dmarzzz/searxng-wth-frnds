"""Phase 5 §29.10 local reputation tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    SearchResult,
    reputation,
)
from swf.search.reputation import (
    DEFAULT_SCORE,
    HALF_LIFE_MS,
    MAX_SCORE,
    MIN_SCORE,
    NEUTRAL_PULL,
    bump,
    decay_all,
    enrich_results,
    rerank,
    score_for,
    scores_for_many,
)
from swf.search.response import (
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SWF_REPUTATION_DB", str(tmp_path / "reputation.db"))
    yield


def _result(pubkey: str | None, *, score: float = 0.5) -> SearchResult:
    return SearchResult(
        result_id=f"res_{abs(hash(pubkey or 'x'))%10**8:08d}",
        canonical_url=f"https://example/{pubkey}",
        display_url="example",
        title="t", snippet="s",
        score=score, rank=1,
        delivery_path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        provider=_Provider(provider_pubkey=pubkey),
        freshness=_Freshness(),
        verification=_Verification(),
        receipt=_Receipt(),
        safety=_Safety(),
    )


# ── score_for / defaults ─────────────────────────────────────────────

def test_unknown_provider_gets_default_score():
    assert score_for("unknown_pubkey") == DEFAULT_SCORE


def test_empty_pubkey_returns_default():
    assert score_for("") == DEFAULT_SCORE


def test_score_within_bounds_after_repeated_bumps():
    """Cap enforcement: a thousand "save" bumps must not exceed MAX_SCORE."""
    for _ in range(1000):
        bump("alice", "save")
    assert score_for("alice") <= MAX_SCORE
    for _ in range(1000):
        bump("bob", "user_marked_useless")
    assert score_for("bob") >= MIN_SCORE


# ── bump events ──────────────────────────────────────────────────────

def test_bump_open_increases_score():
    base = score_for("alice")
    bump("alice", "open")
    assert score_for("alice") > base


def test_bump_useless_decreases_score():
    bump("bob", "open")  # bring above default
    bump("bob", "open")
    bump("bob", "open")
    high = score_for("bob")
    bump("bob", "user_marked_useless")
    assert score_for("bob") < high


def test_bump_unknown_event_is_noop():
    bump("carol", "open")  # establish a baseline above default
    s1 = score_for("carol")
    bump("carol", "moon_dance")  # not in EVENT_DELTA
    s2 = score_for("carol")
    # `s1 == s2` modulo a few-ms decay tick (HALF_LIFE = 30d → epsilon).
    assert abs(s1 - s2) < 1e-6


def test_bump_signature_verified_helps():
    base = score_for("dave")
    bump("dave", "signature_verified")
    assert score_for("dave") > base


def test_bump_claim_violated_penalizes_hard():
    """Claim violations are the heaviest penalty; verify magnitude."""
    base = score_for("evil")
    bump("evil", "claim_violated")
    new = score_for("evil")
    # Claim violation drops by ~0.12; default 0.5 → ~0.38.
    assert new < base - 0.10


# ── decay ────────────────────────────────────────────────────────────

def test_decay_pulls_score_back_toward_neutral():
    bump("frank", "save")
    bump("frank", "save")
    high = score_for("frank")
    assert high > NEUTRAL_PULL

    # Read 30 days later — the half-life — score should be roughly
    # halfway between `high` and NEUTRAL_PULL.
    future = int(__import__("time").time() * 1000) + int(HALF_LIFE_MS)
    decayed = score_for("frank", now_ms=future)
    midpoint = (high + NEUTRAL_PULL) / 2
    # Half-life decay: score should be near midpoint within tolerance.
    assert abs(decayed - midpoint) < 0.02


def test_decay_all_materializes_decay():
    """`decay_all()` writes the lazy-decayed values back to the table."""
    bump("alice", "save")
    bump("alice", "save")
    bump("bob", "user_marked_useless")
    future = int(__import__("time").time() * 1000) + int(HALF_LIFE_MS) * 4
    n_changed = decay_all(now_ms=future)
    assert n_changed >= 2


# ── bulk read ────────────────────────────────────────────────────────

def test_scores_for_many_returns_default_for_unknown():
    bump("alice", "save")
    out = scores_for_many(["alice", "ghost", ""])
    assert "alice" in out
    assert out["alice"] > DEFAULT_SCORE
    assert out.get("ghost") == DEFAULT_SCORE
    # empty-string keys get filtered out (we never store empty pubkeys)
    assert "" not in out


def test_scores_for_many_dedupes_input():
    bump("alice", "save")
    out = scores_for_many(["alice", "alice", "alice"])
    assert len(out) == 1


# ── enrich_results ───────────────────────────────────────────────────

def test_enrich_populates_provider_score_local():
    bump("alice", "save")
    bump("bob", "user_marked_useless")
    rs = [_result("alice"), _result("bob"), _result(None)]
    enrich_results(rs)
    a = next(r for r in rs if r.provider.provider_pubkey == "alice")
    b = next(r for r in rs if r.provider.provider_pubkey == "bob")
    n = next(r for r in rs if r.provider.provider_pubkey is None)
    assert a.provider.provider_score_local > DEFAULT_SCORE
    assert b.provider.provider_score_local < DEFAULT_SCORE
    # No-pubkey row stays None
    assert n.provider.provider_score_local is None


# ── rerank ───────────────────────────────────────────────────────────

def test_rerank_promotes_high_score_provider():
    # Stack enough positive feedback so the rep boost overtakes a
    # +0.05 base-score deficit at weight=0.30.
    for _ in range(5):
        bump("alice", "user_marked_useful")  # +0.08 each
    rs = [
        _result("bob",   score=0.50),
        _result("alice", score=0.45),  # lower base score, higher rep
        _result("carol", score=0.40),
    ]
    out = rerank(rs)
    # Alice should be promoted past Bob despite lower base.
    assert out[0].provider.provider_pubkey == "alice"
    # Ranks rewritten 1..n
    assert [r.rank for r in out] == [1, 2, 3]


def test_rerank_does_not_mutate_input():
    rs = [_result("alice"), _result("bob")]
    out = rerank(rs)
    # Different list object; input ranks unchanged.
    assert out is not rs
    assert all(r.rank == 1 for r in rs)
