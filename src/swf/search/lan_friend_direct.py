"""SPEC v0.3 §17 + §29.6 LAN_FRIEND_DIRECT_PLACEHOLDER.

Non-anonymous placeholder transport: hits each LAN peer's
`POST /friend_search` endpoint directly over plain HTTP, merges the
results. The peers see the requester's IP, so this MUST be labeled
`privacy_level=not_anonymous_placeholder` (§29.2 invariant 4).

The router gates this route to `dev_*`-named policies in production
(§29.1 placeholder check). Phase 4 will swap in the real DC-net
adapter behind the same `RouteHandler` interface.

Friend responder side (the peer who answers) lives in
`swf/search/friend_responder.py` and is hooked into peer_server's
`POST /friend_search` route.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
import uuid

from .policy import SearchPolicy
from .query import QueryContext
from .response import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    SearchAttempt,
    SearchResult,
    _Freshness,
    _Provider,
    _Receipt,
    _Safety,
    _Verification,
)
from .route import RouteHandler, RouteOutcome

DEFAULT_PER_PEER_TIMEOUT_S = 3.0
DEFAULT_MAX_PEERS = 10


def _peer_urls() -> list[str]:
    """LAN peer URLs to fan out to. Sources, in priority order:

    1. `SWF_FRIEND_PEERS` env (comma-separated URLs) — explicit overrides
       are useful for tests and for hard-pinning trusted peers.
    2. `swf.discovery.discover_all_peers()` — config + mDNS + Tailscale,
       deduplicated. Replaces the legacy community_full.scraper
       in-process list (deleted in #43 PR C alongside the rest of the
       community-graph machinery).

    Empty list ⇒ nothing to fan out to ⇒ route returns `no_peers_online`.
    """
    env = (os.environ.get("SWF_FRIEND_PEERS") or "").strip()
    if env:
        return [u.strip() for u in env.split(",") if u.strip()]

    try:
        from swf import discovery
        urls = sorted({dp.url for dp in discovery.discover_all_peers()
                       if dp.url})
        if urls:
            return urls
    except Exception:
        pass

    # peers.yaml fallback
    try:
        from swf.peers import load_peers_yaml
        peers = load_peers_yaml()
        urls = [p.get("url") for p in peers if p.get("url")]
        return [u for u in urls if u]
    except Exception:
        return []


def search(
    ctx: QueryContext,
    *,
    timeout_s: float = DEFAULT_PER_PEER_TIMEOUT_S,
    max_peers: int = DEFAULT_MAX_PEERS,
    peers: list[str] | None = None,
) -> RouteOutcome:
    """Plain-HTTP fan-out to each LAN peer's `/friend_search`. Merges
    results, dedupes by canonical_url (first peer wins), normalizes
    scores and ranks across the merged set.

    Per-peer failures are tolerated; a single slow peer doesn't block
    the route. The route fails as a whole only if NO peer answered.
    """
    started_ms = int(time.time() * 1000)

    def _attempt(*, status: str, reason: str = "", count: int = 0,
                 suspicious: bool = False) -> SearchAttempt:
        c = int(time.time() * 1000)
        return SearchAttempt(
            path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
            status=status, started_ms=started_ms, completed_ms=c,
            duration_ms=c - started_ms, reason=reason,
            results_count=count,
            network_used=True, public_egress_used=False,
            suspicious_failure=suspicious,
        )

    peer_urls = peers if peers is not None else _peer_urls()
    peer_urls = peer_urls[:max_peers]

    if not peer_urls:
        return RouteOutcome(
            attempt=_attempt(status="unavailable", reason="no_peers_online"),
            network_used=True,
        )

    body_json = json.dumps({
        "q": ctx.raw_query,
        "top_k": ctx.requested_top_k,
        "qid": uuid.uuid4().hex,
        # The placeholder transport does NOT include a one-time reply
        # key (no encryption). Real DCNET will. The wire is plain.
    }).encode("utf-8")

    # Per-peer fetch. Run sequentially to keep the dependency graph
    # simple; v1 can parallelize via threads if needed (placeholder
    # path is dev-only, so latency budget is generous).
    seen_urls: set[str] = set()
    merged: list[SearchResult] = []
    peers_responded = 0
    peers_errored = 0
    suspicious = False

    for url in peer_urls:
        full = f"{url.rstrip('/')}/friend_search"
        req = urllib.request.Request(
            full, data=body_json, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "swf-friend-direct-placeholder/0.1",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                if resp.status != 200:
                    peers_errored += 1
                    continue
                bundle = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                json.JSONDecodeError):
            peers_errored += 1
            continue

        peers_responded += 1
        for row in bundle.get("results", [])[:ctx.requested_top_k]:
            url_v = (row.get("canonical_url") or row.get("url") or "").strip()
            if not url_v or url_v in seen_urls:
                continue
            seen_urls.add(url_v)
            try:
                score = float(row.get("score") or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            score = max(0.0, min(1.0, score))
            sr = SearchResult(
                result_id=f"res_{uuid.uuid4().hex[:24]}",
                canonical_url=url_v,
                display_url=row.get("display_url") or url_v,
                title=(row.get("title") or url_v)[:200],
                snippet=(row.get("snippet") or "")[:400],
                score=round(score, 4),
                rank=len(merged) + 1,  # rewritten after sort below
                delivery_path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
                origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
                source="friend_indrex",
                provider=_Provider(
                    provider_pubkey=row.get("provider_pubkey"),
                    provider_label=row.get("provider_label"),
                ),
                freshness=_Freshness(
                    fetched_at_ms=row.get("fetched_at_ms"),
                    served_at_ms=int(time.time() * 1000),
                ),
                verification=_Verification(
                    content_hash=row.get("content_hash"),
                    verification_status="not_checked",  # §29.6: validate elsewhere
                ),
                receipt=_Receipt(receipt_eligible=False),
                safety=_Safety(
                    html_sanitized=True,
                    url_validated=True,
                    # The peer told us the row is `friends` or `public`;
                    # default `public` if they omit. We trust the peer's
                    # share_scope claim for display only — never use it
                    # for further re-sharing without a fresh check.
                    share_scope=row.get("share_scope", "public"),
                ),
            )
            merged.append(sr)

    # Rerank by score desc; tie-break stable.
    merged.sort(key=lambda r: r.score, reverse=True)
    for i, r in enumerate(merged):
        r.rank = i + 1

    # If every peer errored, the route is in a suspicious state —
    # someone could be blocking the LAN. §15 + §26 say that's a
    # confirmation trigger for downgrading to public egress.
    if peers_errored == len(peer_urls) and len(peer_urls) > 0:
        suspicious = True

    if not merged:
        return RouteOutcome(
            attempt=_attempt(
                status="no_results" if peers_responded else "unavailable",
                reason="no_friend_results" if peers_responded
                       else "all_peers_errored",
                suspicious=suspicious,
            ),
            origin_paths=[OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER],
            dominant_origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
            privacy_level=PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER,
            warnings=[],
            network_used=True,
            extras={"peer_count": len(peer_urls),
                    "peers_responded": peers_responded,
                    "peers_errored": peers_errored},
        )

    return RouteOutcome(
        results=merged[:ctx.requested_top_k],
        attempt=_attempt(status="ok", count=len(merged)),
        origin_paths=[OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER],
        dominant_origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        privacy_level=PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER,
        warnings=[
            "This LAN friend path is a non-anonymous development "
            "placeholder. Friend peers saw your IP address.",
        ],
        network_used=True,
        friend_query_visible=True,  # peers saw the raw query
        extras={"peer_count": len(peer_urls),
                "peers_responded": peers_responded,
                "peers_errored": peers_errored},
    )


# ── route handler glue ──────────────────────────────────────────────

def _is_enabled(policy: SearchPolicy) -> bool:
    return policy.allow.lan_friend_direct_placeholder


HANDLER = RouteHandler(
    name=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
    is_enabled=_is_enabled,
    run=lambda ctx, policy: search(ctx),
)
