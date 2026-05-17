"""SQLite FTS5 index of everything in world_knowledge/web/.

The agent should check here before going online. Every `fetch_url` call
that writes to world_knowledge/ also updates this index.

Database path: `<knowledge_root>/index.db`.

Public surface:
    - index_page(url, title, content, fetched_at)  — upsert one page
    - local_search(query, limit=8)  — FTS5 search, returns snippets
    - reindex_knowledge()  — rebuild from scratch from world_knowledge/web/
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
import threading
from pathlib import Path

from swf.canonical import canonical_url_safe
from swf.web.knowledge import knowledge_root

_LOCK = threading.Lock()

logger = logging.getLogger(__name__)


def _db_path() -> Path:
    root = knowledge_root()
    return root / "index.db"


def _conn() -> sqlite3.Connection:
    # check_same_thread=False + our own lock so we can use this from ReAct's
    # thread pool. SQLite is fast enough on a single-writer index.
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode is mandatory: it lets concurrent readers (the searxng engine
    # adapter in swf/local_index.py) see committed writes without blocking.
    # Idempotent; safe to set on every connection.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.DatabaseError:
        # Fresh DB may need the table created first; fall through.
        pass
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS pages USING fts5(
            url UNINDEXED,
            title,
            content,
            fetched_at UNINDEXED,
            tokenize = 'porter unicode61'
        )
        """
    )
    # search_results caches every URL+title+snippet we've ever seen from
    # ANY engine for ANY query, not just pages we actually fetched. This
    # is what makes "same query twice is local" work even for URLs the
    # agent never picked to fetch_url. Content-searchable via FTS5 on
    # title+snippet; also queryable by exact query_hash for cache-hit
    # detection in the agent's web_search gate.
    conn.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS search_results USING fts5(
            query_hash UNINDEXED,
            query UNINDEXED,
            url UNINDEXED,
            title,
            snippet,
            engines UNINDEXED,
            seen_at UNINDEXED,
            tokenize = 'porter unicode61'
        )
        """
    )
    # page_cids: side-table of IPFS CIDv1 (raw, sha256) over the cleaned
    # content. FTS5 virtual tables can't add columns, so we keep CIDs
    # alongside the FTS index and JOIN by url. Populated on write
    # (see index_page) and via the backfill CLI for legacy rows.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS page_cids (
            url          TEXT PRIMARY KEY,
            content_cid  TEXT NOT NULL,
            computed_at  TEXT NOT NULL
        )
        """
    )
    # Second attempt after tables exist, in case the fresh-DB path took
    # the exception branch above.
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


_ALLOWED_DEFAULT_SCOPES = ("private", "local_only", "friends", "public")


def _default_share_scope() -> str:
    """Default share_scope for newly-indexed user-fetched pages.

    Read from SWF_DEFAULT_SHARE_SCOPE env var; falls back to 'friends'
    so a node running in --full mode actually has content to ship in
    its /index/pages bundles. Set to 'private' on machines with
    sensitive browsing.
    """
    val = (os.environ.get("SWF_DEFAULT_SHARE_SCOPE") or "friends").strip().lower()
    return val if val in _ALLOWED_DEFAULT_SCOPES else "friends"


def _fetched_at_ms(fetched_at: str) -> int:
    """Parse the ISO-ish `fetched_at` string into ms-epoch. Falls back
    to now() on any parse failure — pages_meta wants an int."""
    import time
    from datetime import datetime, timezone
    s = (fetched_at or "").strip()
    if s:
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
    return int(time.time() * 1000)


def index_page(*, url: str, title: str, content: str, fetched_at: str) -> None:
    """Upsert a page into the FTS index. Best-effort; never raises.

    URL is canonicalized on the way in so the searxng engine adapter's
    exact-string dedup against public-engine results will work. If the
    URL fails canonicalization we skip the row (invalid URLs in, no
    record out).
    """
    if not url or not content:
        return
    canon = canonical_url_safe(url)
    if canon is None:
        logger.warning("skipped invalid url: %r", url)
        return
    # #84: drop junk-title pages (404s, "Publications" landing pages, etc.)
    # at index time so they never enter the corpus and never get gossiped
    # to peers via /index/pages or /community/slice. Mirrors the viz-side
    # blocklist (shape-rotator-wrld-knwldge-viz#42).
    from swf.search.junk_titles import junk_title_reason
    junk = junk_title_reason(title)
    if junk is not None:
        # Pre-#79 this used `[indexer]` as a one-off prefix; now lives
        # under `swf.web.index` like the rest of the file.
        logger.info("skipped junk-title %s: %s", url, junk)
        return
    try:
        with _LOCK:
            conn = _conn()
            try:
                # Delete any prior entry for this URL, then insert fresh.
                conn.execute("DELETE FROM pages WHERE url = ?", (canon,))
                conn.execute(
                    "INSERT INTO pages (url, title, content, fetched_at) VALUES (?, ?, ?, ?)",
                    (canon, title or "", content, fetched_at or ""),
                )
                # Sidecar: pages_meta carries §13.1 attribution + share_scope
                # so the peer-bundle builder can find this row. Without it,
                # `LEFT JOIN pages_meta ... COALESCE(share_scope,'private')`
                # filters every user-fetched page out of /index/pages, which
                # is why pre-fix nodes shipped empty bundles forever.
                try:
                    from swf.cid import cid_for_content
                    from swf.search import migration
                    cid = cid_for_content(content)
                    migration.ensure_schema(conn)
                    migration.set_meta(
                        conn, canon,
                        source_type="user_fetched",
                        share_scope=_default_share_scope(),
                        content_hash=cid,
                        fetched_at_ms=_fetched_at_ms(fetched_at),
                    )
                    conn.execute(
                        """INSERT INTO page_cids(url, content_cid, computed_at)
                           VALUES(?, ?, ?)
                           ON CONFLICT(url) DO UPDATE SET
                             content_cid = excluded.content_cid,
                             computed_at = excluded.computed_at""",
                        (canon, cid, fetched_at or ""),
                    )
                except Exception as meta_exc:
                    logger.warning(
                        "meta/cid skipped for %s: %s", url, meta_exc,
                    )
                conn.commit()
            finally:
                conn.close()
    except Exception as exc:
        logger.warning("skipped %s: %s", url, exc)


# ── Ship 0.1: query + result-list cache ────────────────────────────────────


def _query_hash(query: str) -> str:
    """Stable hash of a query string. Case-insensitive, whitespace-normalized."""
    import hashlib as _h

    normalized = " ".join((query or "").lower().split())
    return _h.sha1(normalized.encode("utf-8")).hexdigest()[:16]


def record_search_results(
    *, query: str, results: list[dict], engines: str = "", now_iso: str | None = None
) -> int:
    """Persist a searxng/web_search result list into the `search_results`
    cache. Each result dict should have keys: `url`, `title`, `snippet`
    (snippet may also be called `content`/`body`/`description`; we try
    common aliases). Returns the number of rows actually written.

    Idempotent per (query_hash, url): re-running the same query replaces
    prior rows for that query (staleness via `seen_at`).
    """
    if not query or not results:
        return 0
    from datetime import datetime as _dt

    qh = _query_hash(query)
    stamp = now_iso or _dt.now().isoformat(timespec="seconds")

    rows: list[tuple] = []
    for r in results:
        url = r.get("url") or r.get("href") or ""
        canon = canonical_url_safe(url)
        if not canon:
            continue
        title = (r.get("title") or "").strip()
        snippet = (
            r.get("snippet")
            or r.get("content")
            or r.get("body")
            or r.get("description")
            or ""
        ).strip().replace("\n", " ")[:800]
        rows.append((qh, query, canon, title, snippet, engines, stamp))

    if not rows:
        return 0

    try:
        with _LOCK:
            conn = _conn()
            try:
                # Fresh per-query snapshot: drop prior rows for this query,
                # then insert the new set. Keeps the cache stable-sized and
                # reflects the most recent observation.
                conn.execute(
                    "DELETE FROM search_results WHERE query_hash = ?", (qh,)
                )
                conn.executemany(
                    "INSERT INTO search_results "
                    "(query_hash, query, url, title, snippet, engines, seen_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as exc:
        logger.error("record_search_results failed: %s", exc)
        return 0
    return len(rows)


def get_cached_results(
    query: str, max_age_seconds: int = 7 * 24 * 3600
) -> list[dict]:
    """Return cached search-results rows for this exact query if any were
    seen within the last `max_age_seconds`. Empty list if miss or stale.

    Each row: {url, title, snippet, seen_at, engines}. URLs are canonical.
    """
    if not query:
        return []

    qh = _query_hash(query)
    try:
        with _LOCK:
            conn = _conn()
            try:
                rows = conn.execute(
                    "SELECT url, title, snippet, seen_at, engines "
                    "  FROM search_results "
                    " WHERE query_hash = ? "
                    " ORDER BY seen_at DESC",
                    (qh,),
                ).fetchall()
            finally:
                conn.close()
    except Exception as exc:
        logger.error("get_cached_results failed: %s", exc)
        return []

    if not rows:
        return []

    # Freshness filter: drop rows older than max_age_seconds.
    from datetime import datetime as _dt

    fresh: list[dict] = []
    now = _dt.now()
    for r in rows:
        seen_at = r["seen_at"] or ""
        try:
            age = (now - _dt.fromisoformat(seen_at)).total_seconds()
        except Exception:
            age = 0
        if age <= max_age_seconds:
            fresh.append(
                {
                    "url": r["url"],
                    "title": r["title"],
                    "snippet": r["snippet"],
                    "seen_at": seen_at,
                    "engines": r["engines"],
                }
            )
    return fresh


def _fts_search_table(
    conn: sqlite3.Connection,
    table: str,
    match_col_index: int,
    query: str,
    limit: int,
    extra_cols: str,
) -> list[sqlite3.Row]:
    """Run one FTS5 MATCH against a specific table with a quoted-phrase
    fallback on syntax error. `match_col_index` is the column index of
    the matching content column for the `snippet()` aux function."""
    sql = (
        f"SELECT url, title, {extra_cols}, "
        f"       snippet({table}, {match_col_index}, '«', '»', '…', 20) AS snip "
        f"  FROM {table} "
        f" WHERE {table} MATCH ? "
        f" ORDER BY rank "
        f" LIMIT ?"
    )
    try:
        return conn.execute(sql, (query, limit)).fetchall()
    except sqlite3.OperationalError as exc:
        if "syntax error" in str(exc).lower():
            return conn.execute(sql, (f'"{query}"', limit)).fetchall()
        raise


def local_search(query: str, limit: int = 8) -> str:
    """Search the local world_knowledge archive.

    Thin wrapper over `swf.indrex.query` since 0.7. The agent-facing
    output format (with `[page]` / `[cache]` tags per hit) is unchanged.

    Args:
        query: FTS5 query string. Supports phrases, booleans, prefix.
        limit: Max results to return (default 8).

    Returns:
        Header + per-result block. Each block marked [page] or [cache]
        so the caller can tell full content from snippet-only entries.
    """
    if not query or not query.strip():
        return "local_search: empty query"

    from swf.indrex import query as indrex_query

    results = indrex_query(query, limit=limit)
    if not results:
        return (
            f"local_search: no local matches for {query!r} — archive may not "
            "cover this yet; try web_search."
        )

    n_page = sum(1 for r in results if r.source == "page")
    n_cache = sum(1 for r in results if r.source == "cache")

    blocks: list[str] = []
    for r in results:
        tag = f"[{r.source}]"
        title = r.title.strip().splitlines()[0][:120] if r.title else "(no title)"
        date = (r.when or "")[:10]
        verb = "fetched" if r.source == "page" else "seen"
        snippet = r.snippet.replace("\n", " ").strip()[:300]
        blocks.append(f"- {tag} {title}\n  {r.url}\n  {verb} {date}\n  {snippet}")

    header = (
        f"[local_search · {n_page} page-hit(s) + {n_cache} cache-hit(s) in world_knowledge]"
    )
    return header + "\n\n" + "\n\n".join(blocks)


def reindex_knowledge() -> str:
    """Rebuild the FTS index from everything on disk in world_knowledge/web/.

    Idempotent. Useful after manual edits, after restoring from backup,
    or after upgrading the schema.
    """
    root = knowledge_root() / "web"
    count = 0
    errors = 0

    with _LOCK:
        conn = _conn()
        try:
            conn.execute("DELETE FROM pages")
            for md_path in root.rglob("*.md"):
                try:
                    text = md_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    errors += 1
                    continue
                url, title, fetched_at, body = _parse_frontmatter(text)
                if not url:
                    continue
                canon = canonical_url_safe(url) or url
                conn.execute(
                    "INSERT INTO pages (url, title, content, fetched_at) VALUES (?, ?, ?, ?)",
                    (canon, title or md_path.stem, body, fetched_at or ""),
                )
                count += 1
            conn.commit()
        finally:
            conn.close()

    return f"reindex_knowledge: indexed {count} page(s), {errors} read error(s). DB: {_db_path()}"


def _parse_frontmatter(text: str) -> tuple[str, str, str, str]:
    """Very small YAML-ish frontmatter parser. Returns (url, title, fetched_at, body)."""
    if not text.startswith("---\n"):
        return "", "", "", text
    end = text.find("\n---\n", 4)
    if end == -1:
        return "", "", "", text
    header_block = text[4:end]
    body = text[end + 5 :]
    kv: dict[str, str] = {}
    for line in header_block.splitlines():
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        kv[k.strip()] = v.strip()
    return kv.get("url", ""), kv.get("title", ""), kv.get("fetched_at", ""), body
