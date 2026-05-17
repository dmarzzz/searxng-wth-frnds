"""Search providers — self-sovereign only.

See DESIGN.md + INDREX.md. Since 0.7 the swarm's `web_search` delegates
to `swf.fanout.search`, which runs fully in-process over three engines
(local indrex, friends, DDG). SearXNG is no longer required for the
swarm path; it's an optional add-on for users who want a human web UI.

Rejected as paid intermediaries over the public web: Tavily, Brave API,
Exa, Google CSE, Kagi, SerpAPI.

`nitter_search` lives here as a separate tool because its output shape
is different (tweet stream vs. web result list).
"""

from __future__ import annotations

import logging
import os
import re
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level handles the gate.
    logger.debug("%s", msg)


def _http_get(url: str, headers: dict | None = None, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# Note: provider fan-out lives in `swf.fanout` since 0.7. This module
# only keeps the cache-gate wrapping around `swf.fanout.search`, plus
# `nitter_search` (which has a different output shape and stays a
# distinct tool). SearXNG is no longer in the swarm's hot path.


def _fmt_results(results: list[dict]) -> str:
    if not results:
        return ""
    blocks = []
    for r in results:
        title = (r.get("title") or "(no title)").strip()
        url = (r.get("url") or "").strip()
        snippet = (r.get("snippet") or "").strip().replace("\n", " ")[:500]
        blocks.append(f"- {title}\n  {url}\n  {snippet}")
    return "\n\n".join(blocks)


def _dedupe_by_url(results: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in results:
        u = (r.get("url") or "").strip().rstrip("/")
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(r)
    return out


# Queries that contain any of these markers imply time-sensitivity and
# auto-bypass the cache. See INDREX.md "Staleness principle" for rationale.
# Word-boundary matching so "nowhere" and "today" don't collide by accident.
_TEMPORAL_MARKERS = (
    "today",
    "yesterday",
    "this week",
    "this month",
    "latest",
    "recent",
    "recently",
    "current",
    "currently",
    "right now",
    "breaking",
    "just released",
    "as of",
)


def _query_is_time_sensitive(query: str) -> str | None:
    """Return the marker that tripped, or None. Case-insensitive, word-boundary."""
    import re as _re

    q = (query or "").lower()
    for marker in _TEMPORAL_MARKERS:
        # Use word-boundary for single-word markers; substring for multi-word.
        if " " in marker:
            if marker in q:
                return marker
        else:
            if _re.search(rf"\b{_re.escape(marker)}\b", q):
                return marker
    # Any 4-digit year within +/-1 of the current calendar year suggests
    # the user cares about freshness for that window.
    from datetime import datetime as _dt

    year = _dt.now().year
    for y in (year - 1, year, year + 1):
        if _re.search(rf"\b{y}\b", q):
            return str(y)
    return None


def web_search(query: str, fresh: bool = False) -> str:
    """Search the live web, local-first. Fully in-process since v0.7.

    Pipeline:
      1. Staleness gate: queries containing time-sensitive markers
         ("latest", "today", "2026", etc.) auto-bypass the cache. See
         `_TEMPORAL_MARKERS` and INDREX.md "Staleness principle".
      2. Cache gate: if we have seen this exact query recently
         (`RA_CACHE_TTL_SEARCH` seconds, default 7 days) and have >=
         `RA_CACHE_HIT_MIN` URLs on file (default 3), return cached
         results and SKIP the network entirely.
      3. Otherwise, fan out in parallel via `swf.fanout.search` to:
         - local indrex (world_knowledge FTS5, weight 4.0)
         - friends (peer_server HTTP per peers.yaml, weight 3.0)
         - DDG (public web, weight 1.0)
         Merge by canonical URL with weight-biased scoring, write to
         cache for next time, return formatted with per-result source
         tags so the agent can reason about provenance.

    No SearXNG required. No Flask, no docker, no daemon. SearXNG is
    optional if you want a human-browsable web UI on top of the same
    indrex; see `searxng/settings.yml`. The swarm path is fully in-
    process and does not touch SearXNG.

    Force-fresh: pass `fresh=True`, or set `RA_BYPASS_CACHE=1`.

    Prefer `arxiv_search` for peer-reviewed papers, `github_search` for
    code, `nitter_search` for Twitter/X, and `local_search` to search
    only the indexed markdown of pages the agent actually fetched.

    Args:
        query: Short, specific natural-language query.
        fresh: If True, bypass the query cache for this call only.

    Returns:
        Up to ~16 merged results with per-result `[source]` tags.
    """
    # ── 1. Staleness + cache gates ───────────────────────────────────────
    env_bypass = os.environ.get("RA_BYPASS_CACHE") in ("1", "true", "yes")
    temporal = None if (env_bypass or fresh) else _query_is_time_sensitive(query)
    if temporal:
        _log(f"cache bypass · time-sensitive marker {temporal!r} in query")
    bypass = env_bypass or fresh or bool(temporal)

    if not bypass:
        hit_min = int(os.environ.get("RA_CACHE_HIT_MIN", "3"))
        ttl_sec = int(os.environ.get("RA_CACHE_TTL_SEARCH", str(7 * 24 * 3600)))
        try:
            from swf.web.index import get_cached_results

            cached = get_cached_results(query, max_age_seconds=ttl_sec)
        except Exception as exc:
            _log(f"cache read failed: {exc}")
            cached = []
        if len(cached) >= hit_min:
            _log(f"cache HIT · {len(cached)} rows for {query!r}")
            header = (
                f"[web_search LOCAL CACHE · {len(cached)} rows · "
                f"seen {cached[0].get('seen_at', '?')[:10]} · "
                f"skip network (pass fresh=True to override)]\n"
            )
            return header + _fmt_results(cached[:16])
        _log(f"cache miss · {len(cached)} rows for {query!r} (need {hit_min})")

    # ── 2. Local-sufficient gate: if indrex alone has enough matches,
    #       skip the network entirely (no DDG, no friend fan-out).
    #
    # Rationale: once the agent has accumulated material on a topic, there
    # is no point re-asking DDG (wastes bandwidth, leaks queries, slower).
    # Temporal-marker queries already bypassed above, so time-sensitive
    # things still hit the network; this only fires on stable-topic queries.
    from swf.fanout import format_results
    from swf.fanout import search as fanout_search

    if not bypass:
        local_sufficient = int(os.environ.get("RA_LOCAL_SUFFICIENT_MIN", "5"))
        if local_sufficient > 0:
            local_only = fanout_search(
                query, limit=16, include_friends=False, include_ddg=False
            )
            if len(local_only) >= local_sufficient:
                _log(f"local-sufficient · {len(local_only)} local hits · skip network")
                header = (
                    f"[web_search LOCAL INDREX · {len(local_only)} hits · "
                    f"no network (set RA_LOCAL_SUFFICIENT_MIN=0 to disable)]\n"
                )
                # Refresh the query-hash cache too so future same-query
                # lookups hit the cheaper layer first.
                try:
                    from swf.web.index import record_search_results

                    cache_rows = [
                        {"url": r.url, "title": r.title, "snippet": r.snippet}
                        for r in local_only
                    ]
                    record_search_results(
                        query=query, results=cache_rows, engines="local-only"
                    )
                except Exception as exc:
                    _log(f"cache write failed: {exc}")
                return header + format_results(local_only)
            _log(
                f"local insufficient · {len(local_only)} hits "
                f"(need {local_sufficient}); falling through to network"
            )

    # ── 3. In-process fan-out via swf.fanout ─────────────────────────────
    results = fanout_search(query, limit=16)
    if not results:
        return "No web results found for that query."

    # Build contributor summary for header + cache row.
    contrib_counts: dict[str, int] = {}
    for r in results:
        for s in r.sources:
            # Normalize "local:page" / "local:cache" → "local", "friend:alice" → "friend"
            key = s.split(":", 1)[0]
            contrib_counts[key] = contrib_counts.get(key, 0) + 1

    contrib = ", ".join(f"{k}:{v}" for k, v in sorted(contrib_counts.items()))
    header = (
        f"[web_search NETWORK · {contrib} · merged={len(results)} · "
        f"in-process (no SearXNG)]\n"
    )

    # ── 3. Write-through to the local cache ─────────────────────────────
    try:
        from swf.web.index import record_search_results

        cache_rows = [
            {
                "url": r.url,
                "title": r.title,
                "snippet": r.snippet,
            }
            for r in results
        ]
        record_search_results(
            query=query, results=cache_rows, engines=contrib
        )
    except Exception as exc:
        _log(f"cache write failed: {exc}")

    return header + format_results(results)


# ── Nitter (Twitter/X) ─────────────────────────────────────────────────────


def _nitter_candidates() -> list[str]:
    """Nitter instances to try in order. Public instances are fragile so we
    rotate; users can override with `NITTER_URL` (comma-separated list OK).
    """
    raw = os.environ.get("NITTER_URL")
    if raw:
        return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]
    # Well-known public mirrors. These come and go — the real answer is
    # self-hosting. Documented in DESIGN.md.
    return [
        "https://nitter.net",
        "https://nitter.privacydev.net",
        "https://nitter.poast.org",
        "https://nitter.fdn.fr",
    ]


_UA = (
    "Mozilla/5.0 (research-agent web_search) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def nitter_search(query: str, from_user: str = "") -> str:
    """Search Twitter/X via Nitter (open-source frontend, no API key).

    Use for real-time discourse on niche technical topics that don't
    show up in blogs: protocol debates, reactions to releases, expert
    commentary. Twitter's own API is paid and gates this content; Nitter
    exposes it through scrapable HTML.

    Public Nitter instances are fragile — this tool rotates through
    several and returns the first one that works. Self-host via the
    instructions in the Nitter repo for reliability, and point
    `NITTER_URL` at your instance.

    Args:
        query: Search terms (hashtags, phrases, usernames are fine).
        from_user: Optional — restrict to a specific handle (without @).

    Returns:
        Up to 10 tweet stubs: author, date, snippet, nitter permalink.
        Returns an instructional error if all mirrors are down.
    """
    q = query.strip()
    if from_user:
        q = f"{q} (from:{from_user.lstrip('@')})".strip()
    if not q:
        return "nitter_search: empty query"

    last_err: str | None = None
    for base in _nitter_candidates():
        url = f"{base}/search?f=tweets&q={urllib.parse.quote(q)}"
        try:
            raw = _http_get(
                url,
                headers={
                    "User-Agent": _UA,
                    "Accept": "text/html,application/xhtml+xml",
                    "Accept-Language": "en-US,en;q=0.5",
                },
                timeout=15,
            ).decode("utf-8", errors="replace")
        except Exception as exc:
            last_err = f"{base}: {type(exc).__name__}: {exc}"
            _log(f"nitter {base} failed: {exc}")
            continue

        tweets = _parse_nitter(raw, base)
        if tweets:
            header = f"[nitter_search via {base} · {len(tweets)} tweets]\n"
            blocks = [header]
            for t in tweets[:10]:
                blocks.append(
                    f"- @{t['user']} · {t['date']}\n"
                    f"  {base}{t['permalink']}\n"
                    f"  {t['text']}"
                )
            return "\n\n".join(blocks)

    return (
        "nitter_search: all public Nitter mirrors failed (or returned no tweets). "
        "Set NITTER_URL to a working instance, or self-host per "
        "https://github.com/zedeus/nitter. "
        f"Last error: {last_err or 'unknown'}"
    )


def _parse_nitter(html: str, base: str) -> list[dict]:
    """Extract tweet stubs from a Nitter search page. Best-effort HTML parse."""
    tweets: list[dict] = []

    # Each tweet block starts with <div class="timeline-item">. Use a
    # non-greedy match to isolate it, then pull fields out.
    items = re.findall(
        r'<div[^>]*class="[^"]*timeline-item[^"]*"[^>]*>(.*?)(?=<div[^>]*class="[^"]*timeline-item|$)',
        html,
        flags=re.DOTALL | re.IGNORECASE,
    )
    for item in items:
        user_m = re.search(r'class="username"[^>]*>@?([A-Za-z0-9_]+)', item)
        date_m = re.search(r'class="tweet-date"[^>]*>\s*<a[^>]*title="([^"]+)"', item)
        link_m = re.search(r'class="tweet-link"[^>]*href="([^"]+)"', item)
        text_m = re.search(
            r'class="tweet-content[^"]*"[^>]*>(.*?)</div>',
            item,
            flags=re.DOTALL,
        )
        if not user_m or not link_m:
            continue
        text = ""
        if text_m:
            text = re.sub(r"<[^>]+>", " ", text_m.group(1))
            text = re.sub(r"\s+", " ", text).strip()[:400]
        tweets.append(
            {
                "user": user_m.group(1),
                "date": (date_m.group(1) if date_m else "")[:60],
                "permalink": link_m.group(1),
                "text": text or "(no text extracted)",
            }
        )
    return tweets
