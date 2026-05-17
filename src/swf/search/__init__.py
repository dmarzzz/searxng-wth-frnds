"""searxng-wth-frnds search router (SPEC v0.3).

Phase 0 shipped pure data models + §29.2 invariants. Phase 1 added
LOCAL_CACHE + LOCAL_INDREX, sufficiency, and the router orchestrator
behind `web_search()`. Phase 2 added SELF_PUBLIC_EGRESS via local
SearXNG. Phase 3 added LAN_FRIEND_DIRECT_PLACEHOLDER + the friend
responder. Phases 4-6 wire DC-net, reputation, anonymous tickets.

The spec lives at docs/SPEC_v0.3.md. Where this code diverges from the
spec, the divergence is documented inline. Notable: the spec wires the
router to a separate port 7780; we host on the existing swf-node port
7777 (single binary, the spec didn't see the existing server).
"""
from .policy import (
    BUILT_IN_POLICIES,
    PolicyError,
    PublicEgressMode,
    RoutingGoal,
    SearchPolicy,
)
from .query import (
    FreshnessRequirement,
    QueryContext,
    QueryIntent,
    QuerySensitivity,
    build_context,
)
from .receipts import (
    AnonymousReceipt,
    PublicBoardRecord,
    ReceiptClass,
    ReceiptRejection,
    ServiceProof,
)
from .receipts import (
    DeliveryMode as ReceiptDeliveryMode,
)
from .response import (
    DeliveryPath,
    InvariantError,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResponse,
    SearchResult,
    Status,
)
from .route import RouteHandler, RouteOutcome
from .router import web_search
from .sufficiency import Sufficiency
from .tickets import (
    IssuerKey,
    TicketEnvelope,
    TicketFamily,
    TicketRejection,
    TicketStatus,
    TokenBody,
)

__all__ = [
    # response.py
    "DeliveryPath", "OriginPath", "PrivacyLevel", "Status",
    "SearchAttempt", "SearchResult", "SearchResponse", "InvariantError",
    # policy.py
    "PublicEgressMode", "RoutingGoal", "SearchPolicy", "PolicyError",
    "BUILT_IN_POLICIES",
    # query.py
    "QueryIntent", "QuerySensitivity", "FreshnessRequirement",
    "QueryContext", "build_context",
    # sufficiency.py
    "Sufficiency",
    # route.py
    "RouteHandler", "RouteOutcome",
    # router.py
    "web_search",
    # tickets.py
    "TicketFamily", "TicketStatus", "TicketEnvelope", "TokenBody",
    "IssuerKey", "TicketRejection",
    # receipts.py
    "ReceiptClass", "ReceiptRejection", "ReceiptDeliveryMode",
    "ServiceProof", "AnonymousReceipt", "PublicBoardRecord",
]
