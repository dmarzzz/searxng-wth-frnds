"""One local indrex library, one query function, zero daemons.

This is the core primitive. Three call sites used to reimplement the
same FTS5 lookup (`swf.web.index.local_search`,
`swf.local_index.search`, `swf.peer_server._do_search`). They drifted.
Now they all thin-wrap `swf.indrex.query`.

Schema assumed (created by `swf.web.index._conn`):
    pages           (url, title, content, fetched_at)       FTS5
    search_results  (query_hash, query, url, title,
                     snippet, engines, seen_at)             FTS5

WAL mode is mandatory so concurrent readers (SearXNG, peer_server,
agent) see the writer's committed rows without blocking. The writer
side is `swf.web.index.index_page` and `record_search_results`.

Public surface:
    Result          named tuple of (url, title, snippet, source, when)
    query(q, limit=8) -> list[Result]
    urls() -> list[str]            all canonical URLs (for digest build)
    db_path() -> Path
    open_read() -> sqlite3.Connection   (read-only; caller closes)
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path


def db_path(override: Path | str | None = None) -> Path:
    """Return the path to `world_knowledge/index.db`.

    Explicit `override` wins. Without it, resolves from
    `SWF_KNOWLEDGE_DIR` (preferred) or `RA_WORLD_KNOWLEDGE_DIR`
    (legacy) env var; default `~/world_knowledge/`. Consistent with
    `swf.web.knowledge.knowledge_root` which owns creation.
    """
    if override is not None:
        return Path(override)
    env = os.environ.get("SWF_KNOWLEDGE_DIR") or os.environ.get(
        "RA_WORLD_KNOWLEDGE_DIR"
    )
    root = Path(env) if env else (Path.home() / "world_knowledge")
    (root / "web").mkdir(parents=True, exist_ok=True)
    return root / "index.db"


def open_read(override: Path | str | None = None) -> sqlite3.Connection:
    """Open the indrex DB read-only. WAL mode on the writer side lets
    us never block. Caller is responsible for `.close()`."""
    uri = f"file:{db_path(override)}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    conn.row_factory = sqlite3.Row
    return conn


@dataclass
class Result:
    url: str
    title: str
    snippet: str
    source: str   # "page" | "cache"
    when: str     # fetched_at or seen_at

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "title": self.title,
            "snippet": self.snippet,
            "source": self.source,
            "when": self.when,
        }


def _fts_match(user_q: str) -> str:
    """Turn a user query into a safe FTS5 MATCH expression. AND-join
    whitespace tokens, quote each to neutralize FTS5 operators."""
    tokens = [t for t in (user_q or "").split() if t]
    if not tokens:
        return '""'
    return " AND ".join(f'"{t.replace(chr(34), "")}"' for t in tokens)


_PAGES_SQL = (
    "SELECT url, title, "
    "       snippet(pages, 2, '«', '»', '…', 20) AS snip, "
    "       fetched_at AS ts, "
    "       bm25(pages) AS rank "
    "  FROM pages WHERE pages MATCH :q "
    " ORDER BY rank LIMIT :lim"
)

_CACHE_SQL = (
    "SELECT url, title, "
    "       snippet(search_results, 4, '«', '»', '…', 20) AS snip, "
    "       seen_at AS ts, "
    "       bm25(search_results) AS rank "
    "  FROM search_results WHERE search_results MATCH :q "
    " ORDER BY rank LIMIT :lim"
)


def query(q: str, limit: int = 8, db: Path | str | None = None) -> list[Result]:
    """Return up to `limit` results. Unions `pages` (full content) with
    `search_results` (cached snippets). Same-URL hit from `pages` wins.

    Empty string / whitespace query returns []. Syntax errors from FTS5
    retry with the whole query quoted once. Any other error returns [].

    `db` pins a specific DB path (wins over `RA_WORLD_KNOWLEDGE_DIR`
    env var). Used by `swf.peer_server` so multi-peer-in-one-process
    test harnesses can isolate their DBs.
    """
    q = (q or "").strip()
    if not q:
        return []
    path = db_path(db)
    if not path.exists():
        return []

    lim = max(1, min(limit, 50))
    match = _fts_match(q)
    try:
        conn = open_read(path)
    except sqlite3.OperationalError:
        return []

    try:
        try:
            page_rows = conn.execute(_PAGES_SQL, {"q": match, "lim": lim}).fetchall()
        except sqlite3.OperationalError:
            page_rows = []
        try:
            cache_rows = conn.execute(_CACHE_SQL, {"q": match, "lim": lim}).fetchall()
        except sqlite3.OperationalError:
            cache_rows = []
    finally:
        conn.close()

    seen: set[str] = set()
    out: list[Result] = []

    for row in page_rows:
        u = row["url"] or ""
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(
            Result(
                url=u,
                title=row["title"] or u,
                snippet=(row["snip"] or "")[:400],
                source="page",
                when=row["ts"] or "",
            )
        )

    for row in cache_rows:
        u = row["url"] or ""
        if not u or u in seen:
            continue
        seen.add(u)
        out.append(
            Result(
                url=u,
                title=row["title"] or u,
                snippet=(row["snip"] or "")[:400],
                source="cache",
                when=row["ts"] or "",
            )
        )

    return out[:lim]


def urls() -> list[str]:
    """Return every canonical URL in the indrex (pages + search_results).
    Sorted, deduped. Used for digest construction."""
    if not db_path().exists():
        return []
    out: set[str] = set()
    try:
        conn = open_read()
    except sqlite3.OperationalError:
        return []
    try:
        for t in ("pages", "search_results"):
            try:
                for row in conn.execute(f"SELECT url FROM {t}"):
                    u = row[0]
                    if u:
                        out.add(u)
            except sqlite3.OperationalError:
                continue
    finally:
        conn.close()
    return sorted(out)


def stats() -> dict:
    """Row counts for health / diagnostics."""
    counts = {"pages": 0, "search_results": 0}
    if not db_path().exists():
        return counts
    try:
        conn = open_read()
    except sqlite3.OperationalError:
        return counts
    try:
        for t in counts:
            with contextlib.suppress(sqlite3.OperationalError):
                counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
    finally:
        conn.close()
    return counts
