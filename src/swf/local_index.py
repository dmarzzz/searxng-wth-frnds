# SPDX-License-Identifier: AGPL-3.0-or-later
"""SearXNG offline engine over the local FTS5 indrex.

Deployment: bind-mount this file to `/usr/local/searxng/searx/engines/local_index.py`
in the searxng container, and register it in `settings.yml` (example below
and in this repo at `searxng/settings.yml`).

Example `settings.yml` fragment:

    engines:
      - name: local indrex
        engine: local_index
        shortcut: li
        categories: [general]
        database: /world_knowledge/index.db
        limit: 10
        weight: 4.0            # >1 so merged URLs float above public hits
        disabled: false
        timeout: 1.0

This file imports ONLY from `searx.*`. No dependency on the `swf` package
inside the container; URL canonicalization already happened at ingest
time in the host process writing the FTS5 DB. The engine just reads.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import typing as t

from searx.result_types import EngineResults, MainResult

# ── SearXNG engine contract ────────────────────────────────────────────────

engine_type = "offline"
categories = ["general"]
shortcut = "li"
disabled = False
timeout = 1.0
paging = True

about = {
    "website": "https://github.com/dmarzzz/searxng-wth-frnds",
    "require_api_key": False,
    "results": "sqlite-fts5",
}


# ── Module-level config (populated from settings.yml via `init`) ──────────

database: str = ""
limit: int = 10
snippet_len: int = 240


def init(engine_settings: dict[str, t.Any]) -> bool:
    """Called once by searxng at startup. Return False to disable the engine."""
    global database, limit, snippet_len  # pylint: disable=global-statement

    database = os.path.expanduser(engine_settings.get("database") or database)
    limit = int(engine_settings.get("limit") or limit)
    snippet_len = int(engine_settings.get("snippet_len") or snippet_len)

    if not database or not os.path.exists(database):
        return False

    # Confirm the `pages` FTS5 table exists. If not, stay loaded but
    # return empty (the agent may not have indexed anything yet).
    try:
        with _cursor() as cur:
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='pages'"
            )
            return cur.fetchone() is not None
    except Exception:
        return False


@contextlib.contextmanager
def _cursor():
    # Read-only connection per query. WAL mode on the writer side means
    # readers see committed writes immediately and never block. Timeout
    # is short since searxng's offline processor kills the thread on a
    # 1s budget anyway.
    uri = f"file:{database}?mode=ro"
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=0.5)) as conn:
        conn.row_factory = sqlite3.Row
        with contextlib.closing(conn.cursor()) as cur:
            yield cur


def _fts_query(user_q: str) -> str:
    """Turn a user query into an FTS5 MATCH expression.

    Tokenize on whitespace, quote each token to neutralize FTS5 syntax
    chars (`*`, `:`, `-`, `"`), AND-join. Empty query becomes `""` which
    FTS5 treats as no-match.
    """
    tokens = [t for t in user_q.split() if t]
    return " AND ".join(
        f'"{token.replace(chr(34), "")}"' for token in tokens
    ) or '""'


_SQL_PAGES = (
    "SELECT url, title, "
    "       snippet(pages, 2, '<mark>', '</mark>', '...', 20) AS snip, "
    "       fetched_at AS ts, "
    "       bm25(pages) AS rank "
    "  FROM pages "
    " WHERE pages MATCH :q "
    " ORDER BY rank "
    " LIMIT :lim OFFSET :off"
)

_SQL_CACHE = (
    "SELECT url, title, "
    "       snippet(search_results, 4, '<mark>', '</mark>', '...', 20) AS snip, "
    "       seen_at AS ts, "
    "       bm25(search_results) AS rank "
    "  FROM search_results "
    " WHERE search_results MATCH :q "
    " ORDER BY rank "
    " LIMIT :lim OFFSET :off"
)


def search(query: str, params) -> EngineResults:
    """Query entry point. Called once per request by the offline processor.

    Unions results from two FTS5 tables:
      - `pages`: full markdown content the agent has fetched.
      - `search_results`: cached title+snippet from prior searches.

    Same-URL hits are deduped (pages wins, since it has full content).
    """
    res = EngineResults()
    if not query.strip() or not database:
        return res

    pageno = int(params.get("pageno", 1) or 1)
    offset = (pageno - 1) * limit
    q = _fts_query(query)
    bindargs = {"q": q, "lim": limit, "off": offset}

    try:
        with _cursor() as cur:
            pages_rows = cur.execute(_SQL_PAGES, bindargs).fetchall()
            # `search_results` table may not exist on older DBs; guard.
            try:
                cache_rows = cur.execute(_SQL_CACHE, bindargs).fetchall()
            except sqlite3.OperationalError:
                cache_rows = []
    except sqlite3.OperationalError:
        # DB briefly inaccessible (WAL checkpoint, file replacement, etc).
        return EngineResults()

    seen: set[str] = set()
    # pages first (full content beats snippet)
    for row in pages_rows:
        url = row["url"] or ""
        if not url or url in seen:
            continue
        seen.add(url)
        ts = row["ts"] or ""
        res.add(
            MainResult(
                url=url,
                title=row["title"] or url,
                content=(row["snip"] or "")[:snippet_len],
                metadata=f"local·page·{ts[:10]}" if ts else "local·page",
            )
        )

    for row in cache_rows:
        url = row["url"] or ""
        if not url or url in seen:
            continue
        seen.add(url)
        ts = row["ts"] or ""
        res.add(
            MainResult(
                url=url,
                title=row["title"] or url,
                content=(row["snip"] or "")[:snippet_len],
                metadata=f"local·cache·{ts[:10]}" if ts else "local·cache",
            )
        )

    return res
