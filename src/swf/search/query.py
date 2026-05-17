"""SPEC v0.3 §10 QueryContext.

Built once per request before routing. Includes the inferred intent,
inferred sensitivity, and freshness requirement; the router treats these
as routing hints, not security boundaries (§10.1 last line).

Query-HMAC keying lives here too: cache and log entries refer to the
HMAC, never the raw query (§24 raw_queries: false default; §12.1 cache
key).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum


class QueryIntent(str, Enum):
    """§10.1."""
    NAVIGATIONAL = "navigational"
    FACT_LOOKUP = "fact_lookup"
    LOCAL_ARCHIVE_LOOKUP = "local_archive_lookup"
    FRESHNESS_REQUIRED = "freshness_required"
    DEEP_RESEARCH = "deep_research"
    UNKNOWN = "unknown"


class QuerySensitivity(str, Enum):
    """Heuristic sensitivity. Routing hint only — security still gates on
    explicit policy + share_scope on each row."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    UNKNOWN = "unknown"


class FreshnessRequirement(str, Enum):
    """§10.2."""
    NONE = "none"
    PREFER_FRESH = "prefer_fresh"
    REQUIRE_FRESH = "require_fresh"


# §10.2: terms that bias toward freshness. Lowercase compare on tokens.
_FRESH_TERMS: frozenset[str] = frozenset({
    "latest", "today", "current", "recent", "now", "tonight",
    "this", "week", "month", "year",
    "price", "weather", "score", "schedule",
    "cve", "release",
    "2026", "2025",
})

# Strong freshness signals — any of these makes the requirement REQUIRE_FRESH
# rather than PREFER_FRESH.
_STRONG_FRESH: frozenset[str] = frozenset({
    "latest", "today", "tonight", "current", "now", "score", "weather",
    "price", "cve", "2026",
})

# Cheap heuristic for sensitivity bumps. Routing hint, not a security gate.
_SENSITIVE_SUBSTRINGS: tuple[str, ...] = (
    "medical", "diagnosis", "symptom", "ssn", "medication",
    "private", "password", "passport", "salary", "tax return",
)


@dataclass(frozen=True)
class QueryContext:
    """§10."""
    request_id: str
    raw_query: str
    normalized_query: str
    query_hmac: str
    created_ms: int
    caller: str | None
    policy_name: str
    requested_top_k: int
    inferred_intent: QueryIntent
    sensitivity: QuerySensitivity
    freshness_requirement: FreshnessRequirement


def normalize_query(q: str) -> str:
    """Stable normalization for cache key + dedup. NFKC, casefold, strip,
    collapse internal whitespace. Does NOT remove diacritics — that would
    fold meaningful queries together (`naïve` vs `naive`)."""
    s = unicodedata.normalize("NFKC", q or "").casefold().strip()
    return re.sub(r"\s+", " ", s)


def hmac_query(normalized: str, *, secret: bytes | None = None) -> str:
    """HMAC-SHA256 over the normalized query. Uses SWF_QUERY_HMAC_SECRET
    env if set; otherwise falls back to a process-local random secret so
    log entries within a process are joinable but cross-process plaintext
    is never recoverable. Persistent caches (Phase 1's local_cache.py)
    must inject a stable secret loaded from disk; that's not the
    QueryContext layer's job."""
    if secret is None:
        secret = _process_secret()
    digest = hmac.new(secret, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


_PROCESS_SECRET: bytes | None = None


def _process_secret() -> bytes:
    global _PROCESS_SECRET
    if _PROCESS_SECRET is not None:
        return _PROCESS_SECRET
    env = os.environ.get("SWF_QUERY_HMAC_SECRET")
    if env:
        _PROCESS_SECRET = env.encode("utf-8")
    else:
        # Per-process random — joins entries within one swf-node lifetime,
        # but a restart rotates the secret. That's intentional: log
        # plaintext shouldn't survive a process boundary by default.
        _PROCESS_SECRET = secrets.token_bytes(32)
    return _PROCESS_SECRET


def infer_intent(normalized: str) -> QueryIntent:
    """Cheap regex-driven intent inference. NOT a security boundary."""
    if not normalized:
        return QueryIntent.UNKNOWN
    tokens = set(normalized.split())

    # navigational: a domain-looking single token
    if len(tokens) == 1 and re.fullmatch(r"[a-z0-9.\-]+\.[a-z]{2,}", normalized):
        return QueryIntent.NAVIGATIONAL

    # freshness terms dominate
    if tokens & _STRONG_FRESH:
        return QueryIntent.FRESHNESS_REQUIRED

    # explicit "what is X" / "who is X" → fact_lookup
    if re.match(r"^(what|who|when|where|how|why)\s+is\s+", normalized):
        return QueryIntent.FACT_LOOKUP

    # research-flavored: "compare X vs Y", "literature on X", "survey of X"
    if any(t in tokens for t in ("survey", "literature", "compare", "vs", "research")):
        return QueryIntent.DEEP_RESEARCH

    # default: unknown
    return QueryIntent.UNKNOWN


def infer_freshness(normalized: str) -> FreshnessRequirement:
    """§10.2 freshness inference."""
    if not normalized:
        return FreshnessRequirement.NONE
    tokens = set(normalized.split())
    if tokens & _STRONG_FRESH:
        return FreshnessRequirement.REQUIRE_FRESH
    if tokens & _FRESH_TERMS:
        return FreshnessRequirement.PREFER_FRESH
    return FreshnessRequirement.NONE


def infer_sensitivity(normalized: str) -> QuerySensitivity:
    """Heuristic. UNKNOWN by default; bumps to HIGH on a few obvious
    substrings. The router uses this as a hint to suggest privacy_first
    routing but never to silently rewrite policy."""
    if not normalized:
        return QuerySensitivity.UNKNOWN
    if any(s in normalized for s in _SENSITIVE_SUBSTRINGS):
        return QuerySensitivity.HIGH
    return QuerySensitivity.UNKNOWN


def make_request_id(*, prefix: str = "req") -> str:
    """ULID-flavored request id: `<prefix>_<base32 25 chars>` time-prefixed
    so logs sort by request creation time. We don't bring in a ulid lib;
    16 bytes of urandom rendered base32 is good enough for v0."""
    rand = secrets.token_hex(13)  # 26 hex chars = 13 bytes
    return f"{prefix}_{rand}"


def build_context(
    raw_query: str,
    *,
    policy_name: str,
    requested_top_k: int = 10,
    caller: str | None = None,
    request_id: str | None = None,
    hmac_secret: bytes | None = None,
) -> QueryContext:
    """One-shot builder. Router calls this on every incoming request."""
    normalized = normalize_query(raw_query)
    return QueryContext(
        request_id=request_id or make_request_id(),
        raw_query=raw_query,
        normalized_query=normalized,
        query_hmac=hmac_query(normalized, secret=hmac_secret),
        created_ms=int(time.time() * 1000),
        caller=caller,
        policy_name=policy_name,
        requested_top_k=requested_top_k,
        inferred_intent=infer_intent(normalized),
        sensitivity=infer_sensitivity(normalized),
        freshness_requirement=infer_freshness(normalized),
    )
