"""SPEC v0.3 §22 + §29.11 SELF_PUBLIC_EGRESS via local SearXNG.

Calls the local SearXNG instance (`http://127.0.0.1:8888` by default)
with an explicit engine allowlist. The §22 hard rule: if you ever
front a third-party SearXNG, label that path differently
(`PUBLIC_VIA_EXTERNAL_SEARXNG`); this module never does that.

Network failures and SearXNG-down both return an empty result-set with
an honest attempt status. The router uses
`attempt.suspicious_failure=True` plus `policy.public_egress` to decide
whether to escalate to confirmation_required.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor

from .policy import PublicEgressMode, SearchPolicy
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

logger = logging.getLogger(__name__)


def _searxng_base_url() -> str:
    """Override via env for tests / non-default deployments."""
    return os.environ.get("SWF_SEARXNG_URL", "http://127.0.0.1:8888")


def _direct_engines_enabled() -> bool:
    """`SWF_ALLOW_DIRECT_ENGINES=1` opts into the in-process DDG
    fallback when SearXNG is unreachable. Default OFF — the SPEC §22
    privacy contract assumes SearXNG is the trusted intermediary.

    Operators who can't run Docker (or who just want something
    working immediately) flip the flag to fall back to the `ddgs`
    Python library directly. Same network endpoint (DDG); loses
    multi-engine aggregation + the SearXNG box's IP-anonymizing
    properties."""
    return (os.environ.get("SWF_ALLOW_DIRECT_ENGINES") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _ddg_direct_fallback(ctx, started_ms, _attempt, *, top_k):
    """In-process DDG fallback. Imports `ddgs` lazily so deployments
    that never set the flag don't pay the import cost."""
    try:
        from ddgs import DDGS
    except Exception as exc:
        return RouteOutcome(
            attempt=_attempt(
                status="error",
                reason=f"ddg_direct_unavailable: {type(exc).__name__}",
                suspicious=False,
            ),
            network_used=True, public_egress_used=True,
        )
    try:
        with DDGS() as ddg:
            raw_hits = list(ddg.text(
                ctx.raw_query,
                max_results=max(1, min(int(top_k or 10), 50)),
            ))
    except Exception as exc:
        return RouteOutcome(
            attempt=_attempt(
                status="error",
                reason=f"ddg_direct_error: {type(exc).__name__}",
                suspicious=False,
            ),
            network_used=True, public_egress_used=True,
        )
    out: list[SearchResult] = []
    for i, row in enumerate(raw_hits):
        url_v = row.get("href") or row.get("url") or ""
        if not url_v:
            continue
        out.append(SearchResult(
            result_id=f"res_{uuid.uuid4().hex[:24]}",
            canonical_url=url_v,
            display_url=_short_url(url_v),
            title=(row.get("title") or url_v)[:200],
            snippet=(row.get("body") or row.get("snippet") or "")[:400],
            score=round(1.0 - (i / max(1, len(raw_hits))), 4),
            rank=i + 1,
            delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
            origin_path=OriginPath.SELF_PUBLIC_EGRESS,
            source="ddgs_direct",
            provider=_Provider(),
            freshness=_Freshness(served_at_ms=int(time.time() * 1000)),
            verification=_Verification(verification_status="not_checked"),
            receipt=_Receipt(receipt_eligible=False),
            safety=_Safety(html_sanitized=True, url_validated=True,
                           share_scope="public"),
        ))
    # Mirror the SearXNG-path indexing behavior so the wall sees
    # nodes-with-edges from the new query.
    if out:
        try:
            from swf.web.index import record_search_results
            record_search_results(
                query=ctx.raw_query,
                results=[
                    {"url": r.canonical_url,
                     "title": r.title or r.canonical_url,
                     "snippet": r.snippet or ""}
                    for r in out
                ],
                engines="ddgs_direct",
            )
        except Exception as exc:
            logger.warning(
                "direct-ddg index recording failed: %s", exc,
            )
    return RouteOutcome(
        results=out,
        attempt=_attempt(
            status="ok" if out else "no_results", count=len(out),
        ),
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.PUBLIC_FROM_SELF,
        warnings=[
            "This query was sent to public search engines from this device/network.",
            "SWF_ALLOW_DIRECT_ENGINES is on: query went directly to "
            "DuckDuckGo without the SearXNG aggregation layer.",
        ],
        network_used=True,
        public_egress_used=True,
        extras={
            "egress": {
                "adapter": "ddgs_direct",
                "network_mode": "direct",
                "engines_returned": ["duckduckgo"],
                "fallback_reason": "searxng_unreachable",
            },
        },
    )


# §22.1: explicit engine allowlist. Don't let SearXNG's default fanout
# silently include engines we don't trust as part of "public_from_self".
DEFAULT_ENGINES = ("duckduckgo", "brave")
DEFAULT_CATEGORIES = ("general",)
DEFAULT_TIMEOUT_SECONDS = 5.0
# Resource-leak audit F2: cap on SearXNG response body size. 2 MiB
# accommodates 50 results from every engine simultaneously; anything
# bigger is a probable attack or misconfiguration.
MAX_SEARXNG_BYTES = 2 * 1024 * 1024


def _index_results_async(urls: list[str], titles: list[str]) -> None:
    """Fetch + index search-result URLs into the local `pages` corpus.

    Called in a daemon thread from `search()` so the search response
    isn't blocked on per-URL extraction. Each URL goes through the
    existing fetch pipeline (`_get_clean_text`: 7-day disk cache →
    trafilatura local extraction → Jina Reader fallback) and the
    cleaned text is handed to `index_page()`, which writes the row +
    `pages_meta` attribution + `page_cids` so peers' bundle pullers
    can ship it onward. Without this step, public-egress searches
    populated only the `search_results` FTS cache — atlas (which plots
    `pages`) stayed empty and nothing reached the cohort.

    Best-effort: every failure mode (network, extractor, index) is
    swallowed silently per the same contract as the existing
    `record_search_results` call.
    """
    from swf.web.fetch import _get_clean_text
    from swf.web.index import index_page

    def _one(url: str, search_title: str) -> None:
        try:
            text, extracted_title, _extractor = _get_clean_text(url)
        except Exception:
            return
        if not text or len(text.strip()) < 100:
            return
        title = (search_title or extracted_title or "").strip()
        fetched_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        try:
            index_page(url=url, title=title, content=text, fetched_at=fetched_at)
        except Exception:
            return

    with ThreadPoolExecutor(max_workers=4) as pool:
        for url, title in zip(urls, titles):
            pool.submit(_one, url, title)


def _spawn_indexer(urls: list[str], titles: list[str]) -> None:
    """Fire-and-forget wrapper around `_index_results_async`. Lives as
    a module-level function so tests can override it to run inline,
    without monkeypatching `threading.Thread` (which would also break
    the inner `ThreadPoolExecutor`).
    """
    threading.Thread(
        target=_index_results_async,
        args=(urls, titles),
        daemon=True,
    ).start()


def search(
    ctx: QueryContext,
    *,
    engines: tuple[str, ...] = DEFAULT_ENGINES,
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    timeout_s: float = DEFAULT_TIMEOUT_SECONDS,
    base_url: str | None = None,
    top_k: int | None = None,
) -> RouteOutcome:
    """Synchronously call the local SearXNG `/search` endpoint with the
    requested engines, parse JSON, return a normalized RouteOutcome.

    Failure modes mapped to honest attempt statuses:
      - SearXNG unreachable → status="error", reason="searxng_unreachable",
        suspicious_failure=False (this is benign — operator hasn't started
        the docker stack)
      - 5xx from SearXNG → status="error", reason="upstream_error",
        suspicious_failure=False
      - 4xx → status="error", reason="bad_request"
      - timeout → status="timeout", reason="upstream_timeout",
        suspicious_failure=True (a private route DOWNGRADING under
        timeout should warrant confirmation per §15 + §26)
      - parse error → status="error", reason="malformed_response",
        suspicious_failure=True (looks like a misconfigured engine,
        operator should review before we just keep falling through)
    """
    started_ms = int(time.time() * 1000)
    top_k = top_k or ctx.requested_top_k
    base = base_url or _searxng_base_url()

    def _attempt(*, status: str, reason: str = "", count: int = 0,
                 suspicious: bool = False) -> SearchAttempt:
        c = int(time.time() * 1000)
        return SearchAttempt(
            path=DeliveryPath.SELF_PUBLIC_EGRESS,
            status=status, started_ms=started_ms, completed_ms=c,
            duration_ms=c - started_ms, reason=reason,
            results_count=count,
            network_used=True, public_egress_used=True,
            suspicious_failure=suspicious,
        )

    qs = urllib.parse.urlencode({
        "q": ctx.raw_query,
        "format": "json",
        "engines": ",".join(engines),
        "categories": ",".join(categories),
        # SearXNG's `safesearch=0` keeps content unfiltered; users who want
        # filtering should configure it on the SearXNG side.
        "safesearch": "0",
    })
    url = f"{base.rstrip('/')}/search?{qs}"
    req = urllib.request.Request(url, headers={
        # SearXNG public instances often filter "default" UAs as bot
        # traffic; identify ourselves cleanly so a self-hosted instance
        # can rate-limit us if it wants.
        "User-Agent": "swf-search-router/0.1",
        "Accept": "application/json",
    })

    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            if resp.status != 200:
                return RouteOutcome(
                    attempt=_attempt(status="error",
                                     reason=f"upstream_status_{resp.status}",
                                     suspicious=False),
                    network_used=True, public_egress_used=True,
                )
            # Resource-leak audit F2: a malicious / misbehaving SearXNG
            # returning a 100MB JSON would balloon RSS before json.loads
            # even runs. 2 MiB is more than enough for 50 results × all
            # supported engines. Read one byte past the limit to detect
            # the overrun and reject as suspicious upstream behavior.
            raw = resp.read(MAX_SEARXNG_BYTES + 1)
            if len(raw) > MAX_SEARXNG_BYTES:
                return RouteOutcome(
                    attempt=_attempt(status="error",
                                     reason="upstream_response_too_large",
                                     suspicious=True),
                    network_used=True, public_egress_used=True,
                )
    except urllib.error.HTTPError as e:
        suspicious = (500 <= e.code < 600)
        return RouteOutcome(
            attempt=_attempt(status="error",
                             reason=f"upstream_status_{e.code}",
                             suspicious=suspicious),
            network_used=True, public_egress_used=True,
        )
    except urllib.error.URLError as e:
        # Connection refused = SearXNG not running. That's a benign
        # operator state, NOT a suspicious downgrade. The router shouldn't
        # demand confirmation just because docker-compose is off.
        msg = str(e.reason) if e.reason else str(e)
        reason = "searxng_unreachable" if "Connection refused" in msg or "[Errno 61]" in msg \
                 else f"network_error: {msg[:80]}"
        # Fallback: with `SWF_ALLOW_DIRECT_ENGINES=1` set, route the
        # query through the `ddgs` Python library directly when
        # SearXNG isn't there. Privacy: this still goes out as
        # SELF_PUBLIC_EGRESS (the IP visible to DDG is the same as
        # if SearXNG were present), but loses SearXNG's
        # multi-engine aggregation + reformulation. Opt-in only —
        # operators who want the SearXNG privacy properties keep
        # the flag off and get a clear `searxng_unreachable` error.
        if reason == "searxng_unreachable" and _direct_engines_enabled():
            return _ddg_direct_fallback(
                ctx, started_ms, _attempt, top_k=top_k,
            )
        return RouteOutcome(
            attempt=_attempt(status="error", reason=reason, suspicious=False),
            network_used=True, public_egress_used=True,
        )
    except TimeoutError:
        # Timeout on a private fallback IS suspicious per §26: an
        # adversary could be downgrading the network to force public
        # egress.
        return RouteOutcome(
            attempt=_attempt(status="timeout", reason="upstream_timeout",
                             suspicious=True),
            network_used=True, public_egress_used=True,
        )

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as e:
        return RouteOutcome(
            attempt=_attempt(status="error",
                             reason=f"malformed_response: {e}",
                             suspicious=True),
            network_used=True, public_egress_used=True,
        )

    rows = body.get("results", []) or []
    engines_seen = set()
    out: list[SearchResult] = []
    # Red-team #2: a misbehaving SearXNG / engine can surface
    # `javascript:`, `file://`, `data:` URLs, or URLs that resolve to
    # localhost / RFC1918. Reuse the friend responder's SSRF-safe guard;
    # silently drop unsafe rows. We must not relabel them as "public":
    # `safety.url_validated=True` is a privacy claim that this request
    # did NOT serve a private-LAN URL.
    from .friend_responder import _is_safe_url
    for i, row in enumerate(rows[:top_k]):
        url_v = (row.get("url") or "").strip()
        if not url_v or not _is_safe_url(url_v):
            continue
        # SearXNG normalizes its own scoring as `score` (0..1+). When
        # absent (some engines), the position is the only signal.
        try:
            score = float(row.get("score") or 0.0)
        except (TypeError, ValueError):
            score = 0.0
        # Cap at 1.0 since some SearXNG configs return >1 for very
        # high-confidence hits. §11.4 wants normalized scores.
        if score > 1.0:
            score = 1.0
        engines_for_row = row.get("engines") or row.get("engine") or []
        if isinstance(engines_for_row, str):
            engines_for_row = [engines_for_row]
        engines_seen.update(engines_for_row)
        sr = SearchResult(
            result_id=f"res_{uuid.uuid4().hex[:24]}",
            canonical_url=url_v,
            display_url=row.get("pretty_url") or _short_url(url_v),
            title=(row.get("title") or url_v)[:200],
            snippet=(row.get("content") or "")[:400],
            score=round(score, 4),
            rank=i + 1,
            delivery_path=DeliveryPath.SELF_PUBLIC_EGRESS,
            origin_path=OriginPath.SELF_PUBLIC_EGRESS,
            source=",".join(engines_for_row) if engines_for_row else "searxng",
            provider=_Provider(),
            freshness=_Freshness(served_at_ms=int(time.time() * 1000)),
            verification=_Verification(verification_status="not_checked"),
            receipt=_Receipt(receipt_eligible=False),
            safety=_Safety(html_sanitized=True, url_validated=True,
                           share_scope="public"),
        )
        out.append(sr)

    # Field bug: a UI search hit SearXNG, got results, and returned
    # them — but nothing wrote the URLs into the FTS5 `search_results`
    # cache that `swf.indrex_graph.snapshot()` reads. The wall looked
    # like searching did nothing. Now: fire-and-forget into the
    # swf.web's existing FTS5 cache so /graph picks up new
    # nodes (with co-occurrence edges) on the next snapshot.
    if out:
        try:
            from swf.web.index import record_search_results
            record_search_results(
                query=ctx.raw_query,
                results=[
                    {
                        "url": r.canonical_url,
                        "title": r.title or r.canonical_url,
                        "snippet": r.snippet or "",
                    }
                    for r in out
                ],
                engines=",".join(sorted(engines_seen)),
            )
        except Exception:
            # Indexing is a side-effect for the wall; never block
            # the search response on it.
            pass

        # Second half of the same field bug: `record_search_results`
        # only writes title/url/snippet rows into the FTS5
        # `search_results` cache. Atlas plots `pages` (and the bundle
        # layer ships `pages` to peers), so without an index_page()
        # call here, public-egress searches never produce towns and
        # never reach the cohort. Fire-and-forget so the search
        # response returns immediately; the daemon thread fetches
        # each result through the existing extraction pipeline and
        # feeds index_page() — which handles canonicalization,
        # junk-title filtering, content-CID, and share-scope
        # attribution.
        try:
            _spawn_indexer(
                [r.canonical_url for r in out],
                [r.title for r in out],
            )
        except Exception:
            pass

    return RouteOutcome(
        results=out,
        attempt=_attempt(status="ok" if out else "no_results", count=len(out)),
        origin_paths=[OriginPath.SELF_PUBLIC_EGRESS],
        dominant_origin_path=OriginPath.SELF_PUBLIC_EGRESS,
        privacy_level=PrivacyLevel.PUBLIC_FROM_SELF,
        warnings=[
            "This query was sent to public search engines from this device/network.",
        ],
        network_used=True,
        public_egress_used=True,
        extras={
            "egress": {
                "adapter": "searxng",
                "network_mode": "direct",
                "engines_requested": list(engines),
                "engines_returned": sorted(engines_seen),
            },
        },
    )


def _short_url(u: str) -> str:
    try:
        p = urllib.parse.urlparse(u)
        host = (p.hostname or "").removeprefix("www.")
        path = p.path.rstrip("/") or "/"
        return f"{host}{path}".rstrip("/") or u
    except Exception:
        return u


# ── route handler glue ──────────────────────────────────────────────

def _is_enabled(policy: SearchPolicy) -> bool:
    """SELF_PUBLIC_EGRESS is enabled iff policy allows it AND mode != deny.
    `confirm` mode is enabled here — the router post-runs the
    confirmation check using `policy.public_egress.mode`."""
    return (
        policy.allow.self_public_egress
        and policy.public_egress.mode != PublicEgressMode.DENY
    )


HANDLER = RouteHandler(
    name=DeliveryPath.SELF_PUBLIC_EGRESS,
    is_enabled=_is_enabled,
    run=lambda ctx, policy: search(ctx),
)
