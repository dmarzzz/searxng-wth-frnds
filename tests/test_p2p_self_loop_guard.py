"""Belt-and-suspenders coverage for the self-pull-loop bug (#64) and the
orphan-cursor recovery path that shipped alongside it.

The seed-side guards are covered by `test_peer_manager.py`. This file
exercises the runtime / startup defenses:

  - `_tick` skips a self-row even if it somehow ended up in `peers`
    (legacy data, manual `swf-peer add`, future regression).
  - `purge_self_peer_row` deletes a legacy self-row at startup.
  - `reset_orphan_cursors` resets `last_pull_cursor` for peers that
    advanced past the producer HWM with no `pages_meta` rows on disk.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.peer_scraper import (
    list_peers,
    purge_self_peer_row,
    reset_orphan_cursors,
    upsert_peer,
)
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


# ── runtime self-skip in _tick ────────────────────────────────────

def test_tick_skips_self_row_at_runtime(indrex, monkeypatch):
    """If a self-row somehow sits in peers, `_tick` MUST skip it
    without ever calling `pull_from_peer`. Belt-and-suspenders for
    the seed-side guard."""
    own_pk = "MY_OWN_PUBKEY_b64"
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: own_pk)
    upsert_peer(indrex, pubkey=own_pk, nickname="self")
    upsert_peer(indrex, pubkey="REAL_PEER", nickname="alice")

    called: list[str] = []

    def _spy_pull(db, peer, **_):
        called.append(peer.pubkey)
        return (0, "ok")

    monkeypatch.setattr(peer_scraper, "pull_from_peer", _spy_pull)
    monkeypatch.setattr(peer_scraper, "_resolve_peer_url",
                        lambda p: "http://x:7777")
    # Disable the once-per-process bootstraps so they don't perturb
    # the test (we already populated peers manually).
    monkeypatch.setattr(peer_scraper, "_orphan_reset_once", lambda db: 0)
    monkeypatch.setattr(peer_scraper, "_self_purge_once", lambda db: 0)
    monkeypatch.setattr(peer_scraper, "_bootstrap_once_from_yaml",
                        lambda db: 0)
    monkeypatch.setattr(peer_scraper, "_seed_peers_from_discovery",
                        lambda db: 0)
    # Tick #1 also runs `prune_stale_peers`, which evicts our freshly
    # upserted test peers as "never seen". Stub it out for this test.
    monkeypatch.setattr(peer_scraper, "prune_stale_peers",
                        lambda db: {"stale": 0, "broken": 0, "kept": 0})

    peer_scraper._tick(indrex)
    assert called == ["REAL_PEER"]


# ── one-shot self-row purge ───────────────────────────────────────

def test_purge_self_peer_row_removes_legacy_self(indrex, monkeypatch):
    own_pk = "MY_OWN_PUBKEY_b64"
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: own_pk)
    upsert_peer(indrex, pubkey=own_pk, nickname="self")
    upsert_peer(indrex, pubkey="REAL_PEER", nickname="alice")
    assert {r.pubkey for r in list_peers(indrex)} == {own_pk, "REAL_PEER"}

    n = purge_self_peer_row(indrex)
    assert n == 1
    assert {r.pubkey for r in list_peers(indrex)} == {"REAL_PEER"}


def test_purge_self_peer_row_no_op_when_clean(indrex, monkeypatch):
    own_pk = "MY_OWN_PUBKEY_b64"
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: own_pk)
    upsert_peer(indrex, pubkey="REAL_PEER", nickname="alice")
    assert purge_self_peer_row(indrex) == 0
    assert {r.pubkey for r in list_peers(indrex)} == {"REAL_PEER"}


# ── orphan-cursor recovery ────────────────────────────────────────

def test_reset_orphan_cursors_resets_stuck_peer(indrex):
    """Cursor=931 + zero peer_ingest pages_meta rows = stuck.
    Recovery resets cursor=0, last_seen_epoch=''."""
    upsert_peer(indrex, pubkey="STUCK", nickname="ghost")
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET last_pull_cursor=?, last_seen_epoch=? "
        "WHERE pubkey=?",
        (931, "abc123def456", "STUCK"),
    )
    conn.commit()
    conn.close()

    n = reset_orphan_cursors(indrex)
    assert n == 1
    rows = list_peers(indrex)
    assert rows[0].last_pull_cursor == 0
    assert rows[0].last_seen_epoch == ""


def test_reset_orphan_cursors_leaves_healthy_peer_alone(indrex):
    """A peer with peer_ingest pages on disk is healthy; its cursor
    must NOT be reset."""
    upsert_peer(indrex, pubkey="HEALTHY", nickname="bob")
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET last_pull_cursor=? WHERE pubkey=?",
        (500, "HEALTHY"),
    )
    # Mark a peer-ingest page on disk for HEALTHY.
    migration.set_meta(
        conn, "https://example.com/p",
        source_type="peer_ingest",
        content_hash=None,
        source_pubkey="HEALTHY",
        source_label="bob",
        scraped_at="2026-05-04T00:00:00Z",
        bundle_root="r",
        bundle_sig="s",
    )
    conn.commit()
    conn.close()

    n = reset_orphan_cursors(indrex)
    assert n == 0
    rows = list_peers(indrex)
    assert rows[0].last_pull_cursor == 500


def test_reset_orphan_cursors_skips_cursor_zero(indrex):
    """A peer at cursor=0 hasn't pulled anything yet; not orphaned."""
    upsert_peer(indrex, pubkey="FRESH", nickname="new")
    n = reset_orphan_cursors(indrex)
    assert n == 0
    assert list_peers(indrex)[0].last_pull_cursor == 0
