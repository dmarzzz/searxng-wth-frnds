"""SPEC v0.3 §11 SearchResponse + §29.2 invariant checker.

DeliveryPath, OriginPath, PrivacyLevel, Status enums, plus the dataclasses
for SearchResult, SearchAttempt, SearchResponse. `validate_invariants()`
enforces every assertion listed in §29.2; constructing a SearchResponse
runs them.

These are pure data; no router logic, no network, no IO. Phase 1 wires
them into a real router.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class InvariantError(ValueError):
    """A SearchResponse violates one of §29.2's invariants."""


class DeliveryPath(str, Enum):
    """How this response was delivered for the current request (§5)."""
    LOCAL_CACHE = "LOCAL_CACHE"
    LOCAL_INDREX = "LOCAL_INDREX"
    LAN_FRIEND_DIRECT_PLACEHOLDER = "LAN_FRIEND_DIRECT_PLACEHOLDER"
    LAN_FRIEND_DCNET = "LAN_FRIEND_DCNET"
    SELF_PUBLIC_EGRESS = "SELF_PUBLIC_EGRESS"
    NO_RESULT = "NO_RESULT"
    MIXED = "MIXED"  # reserved; v0 prefers single-route result sets (§8)


# Origin paths are the same enum as delivery, except a result is *from*
# somewhere (§5: cache replay can have an origin distinct from delivery).
# The spec uses a single DeliveryPath enum for both fields; we follow.
OriginPath = DeliveryPath


class PrivacyLevel(str, Enum):
    """§6. Human/agent-readable classification of the request's privacy."""
    LOCAL_ONLY = "local_only"
    LOCAL_REPLAY = "local_replay"
    LOCAL_REPLAY_OF_PUBLIC_RESULT = "local_replay_of_public_result"
    ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE = "anonymous_within_lan_circle_query_visible"
    NOT_ANONYMOUS_PLACEHOLDER = "not_anonymous_placeholder"
    PUBLIC_FROM_SELF = "public_from_self"
    PUBLIC_FROM_SELF_TOR = "public_from_self_tor"
    NONE = "none"


class Status(str, Enum):
    """§11.2 top-level response status."""
    OK = "ok"
    PARTIAL = "partial"
    NO_RESULTS = "no_results"
    NO_ACCEPTABLE_ROUTE = "no_acceptable_route"
    CONFIRMATION_REQUIRED = "confirmation_required"
    ERROR = "error"


@dataclass
class SearchAttempt:
    """§11.3."""
    path: DeliveryPath
    status: str
    started_ms: int
    completed_ms: int
    duration_ms: int
    reason: str = ""
    results_count: int = 0
    network_used: bool = False
    public_egress_used: bool = False
    suspicious_failure: bool = False


@dataclass
class _Provider:
    provider_pubkey: str | None = None
    provider_label: str | None = None
    provider_score_local: float | None = None


@dataclass
class _Freshness:
    fetched_at_ms: int | None = None
    indexed_at_ms: int | None = None
    served_at_ms: int | None = None
    staleness_days: int | None = None


@dataclass
class _Verification:
    verified_slice: bool = False
    content_hash: str | None = None
    merkle_root: str | None = None
    inclusion_proof: str | None = None
    sigchain_head: str | None = None
    dsse_attestation: str | None = None
    verification_status: str = "not_checked"


@dataclass
class _Receipt:
    receipt_eligible: bool = False
    service_proof_hash: str | None = None
    receipt_challenge: str | None = None


@dataclass
class _Safety:
    html_sanitized: bool = True
    url_validated: bool = True
    share_scope: str = "public"   # private | local_only | friends | public


@dataclass
class SearchResult:
    """§11.4. All peer/public string fields are untrusted; UI must escape."""
    result_id: str
    canonical_url: str
    display_url: str
    title: str
    snippet: str
    score: float
    rank: int
    delivery_path: DeliveryPath
    origin_path: OriginPath
    source: str = ""
    provider: _Provider = field(default_factory=_Provider)
    freshness: _Freshness = field(default_factory=_Freshness)
    verification: _Verification = field(default_factory=_Verification)
    receipt: _Receipt = field(default_factory=_Receipt)
    safety: _Safety = field(default_factory=_Safety)


_PUBLIC_ORIGINS: frozenset[OriginPath] = frozenset({OriginPath.SELF_PUBLIC_EGRESS})
# §6: `local_only` means "no network was used." Anything outside the
# device — public egress AND any LAN friend route — invalidates the
# label. Red-team finding #4.
_NON_LOCAL_ORIGINS: frozenset[OriginPath] = frozenset({
    OriginPath.SELF_PUBLIC_EGRESS,
    OriginPath.LAN_FRIEND_DCNET,
    OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
})


@dataclass
class SearchResponse:
    """§11.1. Constructed via `make()` so invariants run before return."""
    schema: str
    status: Status
    request_id: str
    created_ms: int
    completed_ms: int
    delivery_path: DeliveryPath
    origin_paths: list[OriginPath]
    dominant_origin_path: OriginPath
    privacy_level: PrivacyLevel
    network_used_this_request: bool
    public_egress_used_this_request: bool
    friend_query_visible: bool = False

    policy: dict[str, Any] = field(default_factory=dict)
    anonymous_ticket: dict[str, Any] = field(default_factory=dict)
    fallbacks_tried: list[DeliveryPath] = field(default_factory=list)
    fallback_reason: str = ""
    privacy_downgrade: bool = False
    warnings: list[str] = field(default_factory=list)
    attempts: list[SearchAttempt] = field(default_factory=list)
    results: list[SearchResult] = field(default_factory=list)
    debug: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def make(cls, **kwargs: Any) -> SearchResponse:
        """Build a SearchResponse and assert its invariants. Use this from
        the router rather than `SearchResponse(...)` directly so that no
        invariant-violating envelope ever escapes."""
        kwargs.setdefault("schema", "swf.search_response.v1")
        resp = cls(**kwargs)
        validate_invariants(resp)
        return resp

    def to_json(self) -> dict[str, Any]:
        """Plain-dict serialization, enums → string values."""
        d = asdict(self)
        d["status"] = self.status.value
        d["delivery_path"] = self.delivery_path.value
        d["origin_paths"] = [p.value for p in self.origin_paths]
        d["dominant_origin_path"] = self.dominant_origin_path.value
        d["privacy_level"] = self.privacy_level.value
        d["fallbacks_tried"] = [p.value for p in self.fallbacks_tried]
        for a in d.get("attempts", []):
            if isinstance(a.get("path"), DeliveryPath):
                a["path"] = a["path"].value
        # asdict() already turned attempts/results into dicts via dataclass
        # recursion, so the only enum left is the .path inside each one;
        # we don't recurse into nested results because asdict turned those
        # too. Re-walk to be safe:
        for r in d.get("results", []):
            for k in ("delivery_path", "origin_path"):
                v = r.get(k)
                if isinstance(v, DeliveryPath):
                    r[k] = v.value
        return d


# ─── invariants (§29.2) ────────────────────────────────────────────────

def validate_invariants(r: SearchResponse) -> None:
    """Raise InvariantError if any §29.2 invariant is violated.

    Invariants enforced:
      1. SELF_PUBLIC_EGRESS implies public_egress_used_this_request = true.
      2. LOCAL_CACHE requires non-empty origin_paths.
      3. local_only privacy implies no public origin paths.
      4. LAN_FRIEND_DIRECT_PLACEHOLDER implies not_anonymous_placeholder.
      5. LAN_FRIEND_DCNET requires anonymous_within_lan_circle_query_visible
         OR (with explicit op-flag) anonymous-set check carried elsewhere.
      6. anonymous_ticket.accepted = true if route is LAN_FRIEND_DCNET and
         tickets are required.

    Plus a couple of bookkeeping cross-checks the spec doesn't enumerate
    but that follow directly from the field definitions:
      * dominant_origin_path must appear in origin_paths.
      * results' origin_path must match the response's dominant origin OR
        be in origin_paths (mixed result sets).
      * LOCAL_CACHE delivery requires network_used_this_request = false.
      * Any PUBLIC origin requires public_egress_used_this_request = true
        OR the response is replaying a cached public result, in which case
        privacy_level must be LOCAL_REPLAY_OF_PUBLIC_RESULT.
    """
    dp = r.delivery_path
    ops = list(r.origin_paths)

    # 2. LOCAL_CACHE requires non-empty origin_paths
    if dp == DeliveryPath.LOCAL_CACHE and not ops:
        raise InvariantError(
            "LOCAL_CACHE delivery requires non-empty origin_paths "
            "(otherwise cache becomes privacy laundering — §5)"
        )

    # 1. SELF_PUBLIC_EGRESS delivery implies public_egress_used_this_request
    if dp == DeliveryPath.SELF_PUBLIC_EGRESS and not r.public_egress_used_this_request:
        raise InvariantError(
            "SELF_PUBLIC_EGRESS delivery implies public_egress_used_this_request=true"
        )

    # 1b. Symmetric (red-team pass-2 / live fuzz F5): if the response
    #     claims `public_egress_used_this_request=true`, then the
    #     audit trail in `origin_paths` MUST list SELF_PUBLIC_EGRESS.
    #     Otherwise a NO_RESULT response can quietly admit egress
    #     happened without surfacing which path consumed the flag.
    if r.public_egress_used_this_request and \
       OriginPath.SELF_PUBLIC_EGRESS not in ops:
        raise InvariantError(
            "public_egress_used_this_request=true but origin_paths "
            "does not contain SELF_PUBLIC_EGRESS"
        )

    # 1c. Symmetric (pass-4 finding #2): if `network_used_this_request`
    #     is true, then origin_paths must include AT LEAST ONE
    #     network-touching path (public, DCNET, or DIRECT_PLACEHOLDER).
    #     Otherwise a handler bug could quietly claim "we hit the
    #     network" without surfacing which path did. Cache replay
    #     and pure-local routes have network=false.
    if r.network_used_this_request and \
       not (_NON_LOCAL_ORIGINS & set(ops)):
        raise InvariantError(
            "network_used_this_request=true but origin_paths contains "
            "no network-touching path "
            "(SELF_PUBLIC_EGRESS / LAN_FRIEND_DCNET / "
            "LAN_FRIEND_DIRECT_PLACEHOLDER)"
        )

    # 4. LAN_FRIEND_DIRECT_PLACEHOLDER implies not_anonymous_placeholder
    if dp == DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER and \
       r.privacy_level != PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER:
        raise InvariantError(
            "LAN_FRIEND_DIRECT_PLACEHOLDER must label privacy_level "
            "as not_anonymous_placeholder"
        )

    # 5. LAN_FRIEND_DCNET implies anonymous_within_lan_circle_query_visible
    if dp == DeliveryPath.LAN_FRIEND_DCNET and \
       r.privacy_level != PrivacyLevel.ANONYMOUS_WITHIN_LAN_CIRCLE_QUERY_VISIBLE:
        raise InvariantError(
            "LAN_FRIEND_DCNET must label privacy_level as "
            "anonymous_within_lan_circle_query_visible (§6: query content "
            "is visible to friend peers)"
        )

    # 6. anonymous_ticket.accepted=true if DCNET and tickets required
    if dp == DeliveryPath.LAN_FRIEND_DCNET:
        ticket = r.anonymous_ticket or {}
        if ticket.get("required") and not ticket.get("accepted"):
            raise InvariantError(
                "LAN_FRIEND_DCNET with anonymous_ticket.required=true "
                "must have anonymous_ticket.accepted=true"
            )

    # 3. local_only privacy implies no NON-LOCAL origin paths.
    #    "no network used" means no public egress AND no LAN friend route
    #    (red-team finding #4). The earlier version only checked public.
    if r.privacy_level == PrivacyLevel.LOCAL_ONLY:
        leaks = _NON_LOCAL_ORIGINS.intersection(ops)
        if leaks:
            raise InvariantError(
                f"privacy_level=local_only cannot have non-local origins: "
                f"{sorted(p.value for p in leaks)}"
            )
        if r.public_egress_used_this_request:
            raise InvariantError(
                "privacy_level=local_only forbids public_egress_used_this_request=true"
            )
        if r.network_used_this_request:
            raise InvariantError(
                "privacy_level=local_only forbids network_used_this_request=true"
            )

    # bookkeeping: dominant_origin_path must be present in origin_paths
    if r.dominant_origin_path not in ops:
        raise InvariantError(
            f"dominant_origin_path={r.dominant_origin_path.value} must "
            f"appear in origin_paths={[p.value for p in ops]}"
        )

    # bookkeeping: LOCAL_CACHE delivery never uses network this request
    if dp == DeliveryPath.LOCAL_CACHE and r.network_used_this_request:
        raise InvariantError(
            "LOCAL_CACHE delivery must have network_used_this_request=false"
        )

    # bookkeeping: cached public result requires the right privacy_level.
    # If there's a public origin but the delivery is LOCAL_CACHE, the
    # privacy level must be LOCAL_REPLAY_OF_PUBLIC_RESULT (§5 example).
    has_public_origin = any(o in _PUBLIC_ORIGINS for o in ops)
    if dp == DeliveryPath.LOCAL_CACHE and has_public_origin and \
       r.privacy_level != PrivacyLevel.LOCAL_REPLAY_OF_PUBLIC_RESULT:
        raise InvariantError(
            "LOCAL_CACHE delivery with a SELF_PUBLIC_EGRESS origin must "
            "label privacy_level as local_replay_of_public_result"
        )

    # bookkeeping: per-result origin_path must be in origin_paths
    op_set = set(ops)
    for res in r.results:
        if res.origin_path not in op_set:
            raise InvariantError(
                f"result {res.result_id!r} has origin_path="
                f"{res.origin_path.value} not in response.origin_paths"
            )


def origin_paths_from_results(results: Iterable[SearchResult]) -> list[OriginPath]:
    """Helper: deduplicated, order-preserving list of origins drawn from
    a set of results. Useful when assembling a response."""
    seen: set[OriginPath] = set()
    out: list[OriginPath] = []
    for r in results:
        if r.origin_path not in seen:
            seen.add(r.origin_path)
            out.append(r.origin_path)
    return out
