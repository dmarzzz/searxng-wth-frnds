"""SPEC v0.3 §10 QueryContext tests."""
from __future__ import annotations

from swf.search import FreshnessRequirement, QueryIntent, QuerySensitivity
from swf.search.query import (
    build_context,
    hmac_query,
    infer_freshness,
    infer_intent,
    infer_sensitivity,
    normalize_query,
)

# ─── normalization ─────────────────────────────────────────────────────

def test_normalize_collapses_whitespace_and_casefolds():
    assert normalize_query("  Hello   WORLD  ") == "hello world"


def test_normalize_handles_unicode_nfkc():
    # ﬁ (single ligature codepoint) → "fi"
    assert normalize_query("oﬃce") == "office"


def test_normalize_preserves_diacritics():
    """Diacritic stripping would fold meaningful queries (`naïve` ≠ `naive`)."""
    assert normalize_query("naïve") == "naïve"


# ─── HMAC ──────────────────────────────────────────────────────────────

def test_hmac_query_is_stable_per_secret():
    secret = b"test-secret-32-bytes-aaaaaaaaaaaa"
    h1 = hmac_query("hello", secret=secret)
    h2 = hmac_query("hello", secret=secret)
    assert h1 == h2
    assert h1.startswith("hmac-sha256:")


def test_hmac_query_diverges_with_different_secret():
    a = hmac_query("hello", secret=b"a" * 32)
    b = hmac_query("hello", secret=b"b" * 32)
    assert a != b


# ─── intent inference ─────────────────────────────────────────────────

def test_intent_navigational_for_bare_domain():
    assert infer_intent("example.com") == QueryIntent.NAVIGATIONAL
    assert infer_intent("docs.python.org") == QueryIntent.NAVIGATIONAL


def test_intent_freshness_for_strong_freshness_terms():
    assert infer_intent("latest cve linux kernel") == QueryIntent.FRESHNESS_REQUIRED
    assert infer_intent("score lakers tonight") == QueryIntent.FRESHNESS_REQUIRED


def test_intent_fact_lookup_for_what_is():
    assert infer_intent("what is a merkle proof") == QueryIntent.FACT_LOOKUP


def test_intent_deep_research_for_survey_terms():
    assert infer_intent("survey of differential privacy literature") == QueryIntent.DEEP_RESEARCH


def test_intent_unknown_otherwise():
    assert infer_intent("some random query") == QueryIntent.UNKNOWN


# ─── freshness ─────────────────────────────────────────────────────────

def test_freshness_require_on_strong_terms():
    assert infer_freshness("price of bitcoin today") == FreshnessRequirement.REQUIRE_FRESH


def test_freshness_prefer_on_weak_terms():
    """`recent` is in _FRESH_TERMS but not _STRONG_FRESH."""
    assert infer_freshness("recent papers on differential privacy") == FreshnessRequirement.PREFER_FRESH


def test_freshness_none_otherwise():
    assert infer_freshness("history of public-key crypto") == FreshnessRequirement.NONE


# ─── sensitivity (hint only) ───────────────────────────────────────────

def test_sensitivity_high_on_obvious_substrings():
    assert infer_sensitivity("symptom checker for migraine") == QuerySensitivity.HIGH


def test_sensitivity_unknown_default():
    assert infer_sensitivity("the cat sat on the mat") == QuerySensitivity.UNKNOWN


# ─── build_context (one-shot) ──────────────────────────────────────────

def test_build_context_populates_all_fields():
    ctx = build_context(
        "What is the LATEST CVE in OpenSSL",
        policy_name="default",
        requested_top_k=5,
        caller="test",
        request_id="req_test_aaaa",
        hmac_secret=b"k" * 32,
    )
    assert ctx.request_id == "req_test_aaaa"
    assert ctx.policy_name == "default"
    assert ctx.requested_top_k == 5
    assert ctx.normalized_query == "what is the latest cve in openssl"
    assert ctx.query_hmac.startswith("hmac-sha256:")
    assert ctx.inferred_intent == QueryIntent.FRESHNESS_REQUIRED
    assert ctx.freshness_requirement == FreshnessRequirement.REQUIRE_FRESH


def test_build_context_request_id_autogen_when_omitted():
    ctx = build_context("hello", policy_name="default")
    assert ctx.request_id.startswith("req_")
    assert len(ctx.request_id) > len("req_")
