"""Issue #65: when a peer-pulled URL is already in the local indrex
(via earlier user fetch or a previous peer pull), attribution must
still be recorded for the contributing peer.

The chosen fix is Option B from the issue: a `page_contributors` join
table that records every (url, source_pubkey) pair. `pages_meta` keeps
its single-attribution `source_pubkey` (primary contributor, first
writer); `page_contributors` accumulates the long tail.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.search import migration


def _seed(db: Path) -> None:
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE VIRTUAL TABLE pages USING fts5("
        "  url UNINDEXED, title, content, fetched_at UNINDEXED,"
        "  tokenize='porter unicode61');"
        "CREATE TABLE page_cids("
        "  url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,"
        "  computed_at TEXT NOT NULL);"
    )
    migration.ensure_schema(conn)
    conn.commit()
    conn.close()


@pytest.fixture
def indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    (tmp_path / "wk").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    _seed(db)
    return db


def _make_bundle(*, pubkey: str, pages: list[dict], since: int = 0,
                 until: int | None = None) -> dict:
    until = until if until is not None else len(pages)
    return {
        "schema": "swf.index_pages.v1",
        "pubkey": pubkey,
        "since": since,
        "until": until,
        "pages": pages,
        "merkle_root": peer_scraper.merkle_root(pages),
        "sig": "x" * 88,
        "epoch_id": "epoch-test",
        "page_count": len(pages),
    }


def _patch_verify_ok(monkeypatch):
    from swf.peer_scraper import VerifyResult
    monkeypatch.setattr(
        peer_scraper, "verify_bundle",
        lambda b, *, expected_pubkey: VerifyResult(
            ok=True, reason="ok",
            since=b.get("since", 0), until=b.get("until", 0),
            page_count=len(b.get("pages") or []),
            declared_root=b.get("merkle_root", ""),
            computed_root=b.get("merkle_root", ""),
        ),
    )


# ── add_contributor / list_contributors ───────────────────────────

def test_add_contributor_creates_row(indrex):
    conn = sqlite3.connect(str(indrex))
    try:
        new = migration.add_contributor(
            conn, "https://x.example/1",
            source_pubkey="PEER_A",
            source_label="alice",
            scraped_at="2026-05-04T00:00:00Z",
            bundle_root="root", bundle_sig="sig",
        )
        assert new is True
        rows = migration.list_contributors(conn, "https://x.example/1")
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0]["source_pubkey"] == "PEER_A"
    assert rows[0]["source_label"] == "alice"


def test_add_contributor_idempotent_per_pubkey(indrex):
    conn = sqlite3.connect(str(indrex))
    try:
        migration.add_contributor(
            conn, "https://x.example/1", source_pubkey="PEER_A",
            scraped_at="2026-05-04T00:00:00Z",
        )
        new = migration.add_contributor(
            conn, "https://x.example/1", source_pubkey="PEER_A",
            scraped_at="2026-05-04T00:01:00Z",
            source_label="alice-updated",
        )
        assert new is False
        rows = migration.list_contributors(conn, "https://x.example/1")
    finally:
        conn.close()
    assert len(rows) == 1
    assert rows[0]["source_label"] == "alice-updated"
    assert rows[0]["scraped_at"] == "2026-05-04T00:01:00Z"


def test_add_contributor_distinct_pubkeys_create_distinct_rows(indrex):
    conn = sqlite3.connect(str(indrex))
    try:
        migration.add_contributor(
            conn, "https://x.example/1", source_pubkey="PEER_A",
            scraped_at="2026-05-04T00:00:00Z",
        )
        migration.add_contributor(
            conn, "https://x.example/1", source_pubkey="PEER_B",
            scraped_at="2026-05-04T00:00:01Z",
        )
        rows = migration.list_contributors(conn, "https://x.example/1")
    finally:
        conn.close()
    pks = {r["source_pubkey"] for r in rows}
    assert pks == {"PEER_A", "PEER_B"}


# ── ingest_bundle attribution ─────────────────────────────────────

def test_ingest_bundle_records_contributor_for_existing_url(indrex, monkeypatch):
    """Headline #65 case. Local node has the URL via user_fetched. A
    peer pulls a bundle containing the same URL. After ingest, the
    peer's attribution is in `page_contributors` even though `pages`
    deduped and `pages_meta.source_pubkey` was preserved."""
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) "
        "VALUES(?, ?, ?, ?)",
        ("https://shared.example/p", "Shared", "", "2026-05-01"),
    )
    migration.set_meta(
        conn, "https://shared.example/p",
        source_type="user_fetched",
    )
    conn.commit()
    assert migration.list_contributors(conn, "https://shared.example/p") == []
    conn.close()

    _patch_verify_ok(monkeypatch)
    bundle = _make_bundle(
        pubkey="PEER_A",
        pages=[{
            "url": "https://shared.example/p",
            "title": "Shared",
            "fetched_at": "2026-05-04T00:00:00Z",
        }],
    )
    stored = peer_scraper.ingest_bundle(indrex, bundle, source_label="alice")
    assert stored == 0

    conn = sqlite3.connect(str(indrex))
    try:
        contribs = migration.list_contributors(
            conn, "https://shared.example/p",
        )
        meta_row = conn.execute(
            "SELECT source_type, source_pubkey FROM pages_meta "
            "WHERE url=?", ("https://shared.example/p",),
        ).fetchone()
    finally:
        conn.close()
    assert [c["source_pubkey"] for c in contribs] == ["PEER_A"]
    assert meta_row[0] == "user_fetched"
    assert meta_row[1] is None


def test_ingest_bundle_records_contributor_for_new_url(indrex, monkeypatch):
    """For a brand-new URL, BOTH pages_meta.source_pubkey AND
    page_contributors record the peer."""
    _patch_verify_ok(monkeypatch)
    bundle = _make_bundle(
        pubkey="PEER_A",
        pages=[{
            "url": "https://new.example/p",
            "title": "New",
            "fetched_at": "2026-05-04T00:00:00Z",
        }],
    )
    stored = peer_scraper.ingest_bundle(indrex, bundle, source_label="alice")
    assert stored == 1

    conn = sqlite3.connect(str(indrex))
    try:
        contribs = migration.list_contributors(conn, "https://new.example/p")
        meta = conn.execute(
            "SELECT source_type, source_pubkey FROM pages_meta WHERE url=?",
            ("https://new.example/p",),
        ).fetchone()
    finally:
        conn.close()
    assert [c["source_pubkey"] for c in contribs] == ["PEER_A"]
    assert meta[0] == "peer_ingest"
    assert meta[1] == "PEER_A"


def test_ingest_bundle_two_peers_same_url(indrex, monkeypatch):
    """Two peers each contributing the same URL → both land in
    page_contributors. Primary attribution stays with the first writer
    (peer_ingest source_type guards override)."""
    _patch_verify_ok(monkeypatch)
    bundle_a = _make_bundle(
        pubkey="PEER_A",
        pages=[{"url": "https://o.example/p", "title": "Overlap Test Page",
                "fetched_at": "2026-05-04T00:00:00Z"}],
    )
    bundle_b = _make_bundle(
        pubkey="PEER_B",
        pages=[{"url": "https://o.example/p", "title": "Overlap Test Page",
                "fetched_at": "2026-05-04T00:00:01Z"}],
    )
    peer_scraper.ingest_bundle(indrex, bundle_a, source_label="alice")
    peer_scraper.ingest_bundle(indrex, bundle_b, source_label="bob")

    conn = sqlite3.connect(str(indrex))
    try:
        contribs = migration.list_contributors(conn, "https://o.example/p")
        meta = conn.execute(
            "SELECT source_pubkey FROM pages_meta WHERE url=?",
            ("https://o.example/p",),
        ).fetchone()
    finally:
        conn.close()
    pks = {c["source_pubkey"] for c in contribs}
    assert pks == {"PEER_A", "PEER_B"}
    assert meta[0] == "PEER_A"
