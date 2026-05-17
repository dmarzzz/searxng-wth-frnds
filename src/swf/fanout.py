"""In-process meta-search. Replaces SearXNG's orchestration role.

Fan out a query in parallel to:
  1. Local indrex  (pages + search_results, via swf.indrex.query)
  2. Friends       (HTTP to peer_servers from peers.yaml)
  3. Public engines (DDG by default; rejected: Tavily/Brave/Exa/etc.)

Merge by canonical URL dedup with a weight-biased score:

    score(url) = sum(engine_weight / (position+1)  for each engine that returned url)

which gives the same ordering properties as SearXNG's merger
(contributions from multiple engines stack; higher-weight engines
dominate) without the Flask machinery.

Engine weights, in line with searxng/settings.yml for consistency
(users can tune via env vars):

    RA_WEIGHT_LOCAL   (default 4.0)
    RA_WEIGHT_FRIENDS (default 3.0)
    RA_WEIGHT_DDG     (default 1.0)

Public surface:
    search(q, limit=16, include_friends=True, include_ddg=True) -> list[MergedResult]
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from swf import friends as friends_mod
from swf import indrex as indrex_mod
from swf.canonical import canonical_url_safe

logger = logging.getLogger(__name__)


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level (DEBUG when
    # RA_VERBOSE / SWF_VERBOSE is set, INFO otherwise) handles the gate.
    logger.debug("%s", msg)


def _weight(name: str, default: float) -> float:
    try:
        return float(os.environ.get(f"RA_WEIGHT_{name.upper()}", default))
    except ValueError:
        return default


@dataclass
class MergedResult:
    url: str
    title: str
    snippet: str
    score: float
    sources: list[str] = field(default_factory=list)      # e.g. ["local:page", "friend:alice", "ddg"]
    whens: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "snippet": self.snippet,
            "score": round(self.score, 4),
            "sources": self.sources,
            "whens": self.whens,
        }


def _engine_local(q: str, limit: int) -> list[tuple[int, dict]]:
    """Return [(position, result_dict), ...]. position starts at 0."""
    hits = indrex_mod.query(q, limit=limit)
    out = []
    for pos, h in enumerate(hits):
        out.append(
            (
                pos,
                {
                    "url": h.url,
                    "title": h.title,
                    "snippet": h.snippet,
                    "source": f"local:{h.source}",
                    "when": h.when,
                },
            )
        )
    return out


def _engine_friends(q: str, limit: int) -> list[tuple[int, dict]]:
    hits = friends_mod.query_friends(q, limit=limit)
    out = []
    for pos, h in enumerate(hits):
        out.append(
            (
                pos,
                {
                    "url": h.url,
                    "title": h.title,
                    "snippet": h.snippet,
                    "source": f"friend:{h.peer}",
                    "when": h.seen_at,
                },
            )
        )
    return out


def _engine_ddg(q: str, limit: int) -> list[tuple[int, dict]]:
    from ddgs import DDGS

    try:
        rows = DDGS().text(q, max_results=limit) or []
    except Exception as exc:
        _log(f"ddg failed: {exc}")
        return []
    out = []
    for pos, r in enumerate(rows):
        canon = canonical_url_safe(r.get("href") or r.get("url") or "")
        if not canon:
            continue
        out.append(
            (
                pos,
                {
                    "url": canon,
                    "title": r.get("title") or canon,
                    "snippet": (r.get("body") or r.get("description") or "")[:500],
                    "source": "ddg",
                    "when": "",
                },
            )
        )
    return out


def search(
    q: str,
    limit: int = 16,
    include_friends: bool = True,
    include_ddg: bool = True,
) -> list[MergedResult]:
    """Fan out, merge by URL, score by weighted position.

    Engines run in parallel via ThreadPoolExecutor. Failing engines are
    logged (if RA_VERBOSE) and skipped.
    """
    engines = [("local", _engine_local, _weight("local", 4.0))]
    if include_friends:
        engines.append(("friends", _engine_friends, _weight("friends", 3.0)))
    if include_ddg:
        engines.append(("ddg", _engine_ddg, _weight("ddg", 1.0)))

    # Parallel execute each engine; collect per-engine results.
    results_by_engine: dict[str, list[tuple[int, dict]]] = {}
    with ThreadPoolExecutor(max_workers=len(engines)) as pool:
        futs = {
            pool.submit(fn, q, limit): (name, weight)
            for name, fn, weight in engines
        }
        for fut in as_completed(futs):
            name, _weight_ = futs[fut]
            try:
                results_by_engine[name] = fut.result()
            except Exception as exc:
                _log(f"engine {name} failed: {exc}")
                results_by_engine[name] = []

    # Merge. Score(url) = sum(weight / (position+1)).
    merged: dict[str, MergedResult] = {}
    for name, _fn, weight in engines:
        rows = results_by_engine.get(name, [])
        for pos, r in rows:
            url = r["url"]
            contrib = weight / (pos + 1)
            if url not in merged:
                merged[url] = MergedResult(
                    url=url,
                    title=r["title"] or url,
                    snippet=r["snippet"] or "",
                    score=0.0,
                )
            m = merged[url]
            m.score += contrib
            m.sources.append(r["source"])
            if r["when"]:
                m.whens.append(r["when"])
            # Prefer a richer snippet if we have a short one.
            if r["snippet"] and len(r["snippet"]) > len(m.snippet):
                m.snippet = r["snippet"]

    ranked = sorted(merged.values(), key=lambda m: m.score, reverse=True)
    return ranked[:limit]


def format_results(results: list[MergedResult]) -> str:
    """Agent-facing formatted string. Source tags are visible so the
    agent can reason about provenance."""
    if not results:
        return "No results found."
    blocks = []
    for r in results:
        src_tag = " · ".join(r.sources)
        blocks.append(
            f"- {r.title}\n"
            f"  {r.url}\n"
            f"  [{src_tag}] score={r.score:.2f}\n"
            f"  {r.snippet}"
        )
    return "\n\n".join(blocks)
