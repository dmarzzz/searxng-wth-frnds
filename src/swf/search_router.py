"""Source-aware search router. Backs the unified `/search` + `/metasearch`
route surface on swf-node.

Source kinds:
  "local"          → this node's local indrex (FTS5)
  "<peer_alias>"   → POST /search { source: "local" } against that peer's URL
  "<engine_name>"  → public engine (deferred — currently routes through
                      swf.web.providers if available)
  "*"              → wildcard, expands to all configured sources
  list[str]        → fan out + merge

Auth model is decided in peer_server.py at request time:
  - source ∈ {"local", "<known peer alias>"}     → no token required
  - any other source                              → bearer-token required

This module is auth-agnostic; it just executes whatever sources it's
given.
"""
from __future__ import annotations

import concurrent.futures
import json
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from swf.peers import load_peers


@dataclass
class _Resolved:
    kind: str            # "local" | "peer" | "engine"
    name: str            # original source string ("local", "alice", "ddg", …)
    url: str | None = None  # for kind=="peer"


def _peer_aliases() -> dict[str, str]:
    """name → URL, for every known peer in peers.yaml. Empty dict on error."""
    try:
        cfg = load_peers()
        return {p.name: p.canonical() for p in cfg.enabled_peers}
    except Exception:
        return {}


def known_engine_names() -> set[str]:
    """Names that are NOT 'local' and NOT in peers.yaml; treated as public
    engines. Today the providers stack is decided inside swf.web.providers;
    we just whitelist the names so callers can reach them by hitting
    /search { source: "ddg" }. Adjusting this list adds engine routing."""
    return {"ddg", "duckduckgo", "nitter", "arxiv", "searxng"}


def public_source_names() -> list[str]:
    return sorted(known_engine_names())


def all_known_source_names() -> list[str]:
    return ["local"] + sorted(_peer_aliases().keys()) + public_source_names()


def resolve_source(source: str) -> _Resolved:
    if source == "local":
        return _Resolved(kind="local", name="local")
    aliases = _peer_aliases()
    if source in aliases:
        return _Resolved(kind="peer", name=source, url=aliases[source])
    if source in known_engine_names():
        return _Resolved(kind="engine", name=source)
    raise ValueError(
        f"unknown source {source!r}; valid: 'local', "
        f"peers={list(aliases.keys())}, engines={sorted(known_engine_names())}"
    )


def expand_sources(source: Any) -> list[_Resolved]:
    """Expand `source` (which may be str, list, or '*') into a list of
    _Resolved entries. Validates and dedupes."""
    if source == "*":
        names = ["local"] + list(_peer_aliases().keys()) + sorted(known_engine_names())
    elif isinstance(source, str):
        names = [source]
    elif isinstance(source, list):
        if not source:
            raise ValueError("source list is empty")
        if "*" in source and len(source) > 1:
            raise ValueError("'*' is only valid as the sole value")
        if "*" in source:
            return expand_sources("*")
        # dedup preserving order
        seen: set[str] = set()
        names = [s for s in source if not (s in seen or seen.add(s))]
    else:
        raise ValueError(f"source must be str or list[str]; got {type(source).__name__}")
    return [resolve_source(n) for n in names]


def is_privileged(resolved: _Resolved) -> bool:
    """True if this source requires a bearer token (it costs us network /
    quota / CPU). False for local + known peers."""
    return resolved.kind == "engine"


# ── per-source executors ──────────────────────────────────────────────────

def _search_local(q: str, limit: int) -> list[dict]:
    """Run an FTS5 query against ~/world_knowledge/index.db.
    Returns the same shape swf-peer-server's existing /search route returns."""
    from swf.web.knowledge import knowledge_root

    db = knowledge_root() / "index.db"
    if not db.exists():
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT url, title, snippet(pages, 2, '<b>', '</b>', '…', 32) AS snippet "
            "FROM pages WHERE pages MATCH ? LIMIT ?",
            (q, limit),
        ).fetchall()
        return [{"url": r["url"], "title": r["title"], "snippet": r["snippet"]}
                for r in rows]
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()


def _search_peer(url: str, q: str, limit: int, *,
                 timeout: float = 4.0) -> list[dict]:
    """Ask another peer for their local indrex. Tries POST /search with
    source:"local" (the new shape); falls back to GET /search?q= on older
    peers for one deprecation cycle."""
    body = json.dumps({"q": q, "source": "local", "limit": limit}).encode("utf-8")
    req = urllib.request.Request(
        f"{url.rstrip('/')}/search",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "swf-search-router"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
            return data.get("results", []) or []
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # legacy peer — try GET /search?q=
            try:
                from urllib.parse import quote_plus
                with urllib.request.urlopen(
                    f"{url.rstrip('/')}/search?q={quote_plus(q)}&limit={limit}",
                    timeout=timeout,
                ) as r:
                    return json.loads(r.read().decode("utf-8")).get("results", []) or []
            except Exception:
                return []
        return []
    except Exception:
        return []


def _search_engine(name: str, q: str, limit: int) -> list[dict]:
    """Public-web engine. Routed through swf.web's provider stack
    when available; otherwise empty list. Network calls are best-effort
    and time-bounded by the per-source timeout in the orchestrator."""
    try:
        from swf.web import providers
        single = getattr(providers, f"search_{name}", None)
        if callable(single):
            return single(q, limit=limit) or []
    except Exception:
        pass
    return []


# ── orchestrator ──────────────────────────────────────────────────────────

def search(*, q: str, source: Any = "local", limit: int = 10,
           per_source_timeout: float = 4.0) -> dict:
    """Top-level dispatcher. Returns:

        {
          "q":       <str>,
          "sources": [{"name": str, "kind": str, "count": int, "took_ms": float, "error": str|None}, ...],
          "results": [merged + deduped dicts in insertion order],
        }
    """
    resolved = expand_sources(source)
    out_per_source: list[dict] = []
    seen_urls: set[str] = set()
    merged: list[dict] = []

    def _run(r: _Resolved) -> tuple[_Resolved, list[dict], float, str | None]:
        t0 = time.monotonic()
        try:
            if r.kind == "local":
                rows = _search_local(q, limit=limit)
            elif r.kind == "peer":
                rows = _search_peer(r.url or "", q, limit=limit, timeout=per_source_timeout)
            elif r.kind == "engine":
                rows = _search_engine(r.name, q, limit=limit)
            else:
                rows = []
            return (r, rows, (time.monotonic() - t0) * 1000.0, None)
        except Exception as e:
            return (r, [], (time.monotonic() - t0) * 1000.0, f"{type(e).__name__}: {e}")

    if len(resolved) == 1:
        r, rows, took, err = _run(resolved[0])
        out_per_source.append({"name": r.name, "kind": r.kind,
                                "count": len(rows), "took_ms": round(took, 1),
                                "error": err})
        for row in rows:
            url = row.get("url")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            merged.append(row)
    else:
        # parallel fan-out
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(resolved))) as ex:
            for fut in concurrent.futures.as_completed([ex.submit(_run, r) for r in resolved]):
                r, rows, took, err = fut.result()
                out_per_source.append({"name": r.name, "kind": r.kind,
                                        "count": len(rows), "took_ms": round(took, 1),
                                        "error": err})
                for row in rows:
                    url = row.get("url")
                    if not url or url in seen_urls:
                        continue
                    seen_urls.add(url)
                    merged.append(row)

    return {"q": q, "sources": out_per_source, "results": merged}
