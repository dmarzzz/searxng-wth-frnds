"""Shared FTS5 indrex seed for tests.

Eight test files duplicated the same `CREATE VIRTUAL TABLE pages` +
`CREATE TABLE page_cids` boilerplate. One source of truth lives here
and the tests import it. Any change to the FTS5 column shape or the
sidecar tables touches one place."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from swf.search import migration


def seed_empty_indrex(db: Path) -> None:
    """Create an empty indrex.db with FTS5 `pages`, `search_results`,
    `page_cids`, and the migration's `pages_meta` / `peers` /
    `events` / `swf_kv` tables. Idempotent — calling on an existing
    DB does nothing destructive (CREATE IF NOT EXISTS)."""
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS pages USING fts5(
            url UNINDEXED, title, content, fetched_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS search_results USING fts5(
            query_hash UNINDEXED, query UNINDEXED, url UNINDEXED,
            title, snippet, engines UNINDEXED, seen_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE TABLE IF NOT EXISTS page_cids(
            url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        """
    )
    migration.ensure_schema(conn)
    conn.commit()
    conn.close()


def seed_pages(
    db: Path,
    rows: list[tuple[str, str, str, str]],
    *,
    share_scope: str | None = None,
) -> None:
    """Insert rows into `pages`. Each row: (url, title, content,
    fetched_at). If `share_scope` is provided, every row also gets a
    `pages_meta` upsert with that scope — necessary because
    build_bundle filters out the §13.1-default `private` rows."""
    conn = sqlite3.connect(str(db))
    for u, t, c, f in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) "
            "VALUES(?,?,?,?)", (u, t, c, f),
        )
        if share_scope is not None:
            migration.set_meta(conn, u, share_scope=share_scope)
    conn.commit()
    conn.close()


__all__ = ["seed_empty_indrex", "seed_pages"]
