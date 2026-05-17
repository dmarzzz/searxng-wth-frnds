"""Issue #43 PR B — indrex-backed graph + event bus tests."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import event_bus, indrex_graph, peer_scraper
from swf.search import migration


@pytest.fixture(autouse=True)
def _liveness_passes(monkeypatch):
    monkeypatch.setattr(peer_scraper, "liveness_check",
                        lambda url, timeout_s=None: True)


@pytest.fixture
def isolated_indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    db = tmp_path / "index.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE VIRTUAL TABLE pages USING fts5(
            url UNINDEXED, title, content, fetched_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE VIRTUAL TABLE search_results USING fts5(
            query_hash UNINDEXED, query UNINDEXED, url UNINDEXED,
            title, snippet, engines UNINDEXED, seen_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE TABLE page_cids(
            url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        """
    )
    migration.ensure_schema(conn)
    conn.commit()
    conn.close()
    return db


def _add_page(db: Path, url: str, title: str, content: str = "x",
              fetched: str = "2026-04-01T00:00:00Z",
              source_pubkey: str | None = None,
              source_label: str | None = None,
              source_type: str = "user_fetched") -> None:
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
        (url, title, content, fetched),
    )
    migration.set_meta(
        conn, url,
        source_type=source_type,
        source_pubkey=source_pubkey,
        source_label=source_label,
    )
    conn.commit()
    conn.close()


# ── empty / missing ─────────────────────────────────────────────────

def test_snapshot_on_missing_db_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "missing"))
    snap = indrex_graph.snapshot()
    assert snap["nodes"] == []
    assert snap["edges"] == []
    assert snap["stats"]["nodes"] == 0


def test_snapshot_on_empty_indrex(isolated_indrex):
    snap = indrex_graph.snapshot()
    assert snap["nodes"] == []
    assert snap["peers"] == []
    assert snap["lens"] == "topic"
    assert "lens_options" in snap


# ── self-attribution coloring ───────────────────────────────────────

def test_node_emits_primary_contributor_alias(isolated_indrex):
    """Back-compat for the legacy wall: each node carries
    `primary_contributor` (= source_pubkey) and a single-element
    `contributors` list. PR D's wall changes will read source_pubkey
    directly; until then this keeps the existing UI lighting up."""
    peer_scraper.upsert_peer(
        isolated_indrex, pubkey="pk_alice", nickname="alice",
    )
    _add_page(
        isolated_indrex, "https://a/1", "A",
        source_pubkey="pk_alice", source_type="peer_ingest",
    )
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    n = snap["nodes"][0]
    assert n["primary_contributor"] == "pk_alice"
    assert n["contributors"] == ["pk_alice"]


def test_self_pages_get_self_color_and_is_self(isolated_indrex):
    _add_page(isolated_indrex, "https://a.example/p1", "A")
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    assert len(snap["nodes"]) == 1
    n = snap["nodes"][0]
    assert n["is_self"] is True
    assert n["source_color"] == indrex_graph.SELF_COLOR


def test_legacy_rows_without_source_pubkey_count_as_self(isolated_indrex):
    """Pre-#43 rows have NULL source_pubkey. The graph treats them as
    self so the wall doesn't strand them as orphans."""
    _add_page(isolated_indrex, "https://a.example/legacy", "Legacy")
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    assert snap["nodes"][0]["is_self"] is True


def test_peer_pages_get_peer_color_and_label(isolated_indrex):
    peer_scraper.upsert_peer(
        isolated_indrex, pubkey="pk_alice", nickname="alice",
        signature_color="#ff8a5b", signature_freq=440.0,
    )
    _add_page(
        isolated_indrex, "https://alice.example/p1", "Alice's Page",
        source_pubkey="pk_alice", source_label="alice",
        source_type="peer_ingest",
    )
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    n = snap["nodes"][0]
    assert n["is_self"] is False
    assert n["source_pubkey"] == "pk_alice"
    assert n["source_label"] == "alice"
    assert n["source_color"] == "#ff8a5b"


def test_peer_with_no_color_uses_stable_hue(isolated_indrex):
    """A peer row without signature_color falls back to a deterministic
    color derived from the pubkey — never raises, never returns None."""
    peer_scraper.upsert_peer(
        isolated_indrex, pubkey="pk_bob", nickname="bob",
    )
    _add_page(
        isolated_indrex, "https://b.example/p1", "Bob",
        source_pubkey="pk_bob", source_type="peer_ingest",
    )
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    color = snap["nodes"][0]["source_color"]
    assert color.startswith("#")
    assert len(color) == 7


# ── peers list ──────────────────────────────────────────────────────

def test_peers_list_includes_self_when_pubkey_provided(isolated_indrex):
    _add_page(isolated_indrex, "https://x/1", "X")
    _add_page(isolated_indrex, "https://x/2", "X2")
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    pks = [p["pubkey"] for p in snap["peers"]]
    assert "my_pk" in pks
    self_row = next(p for p in snap["peers"] if p["pubkey"] == "my_pk")
    assert self_row["is_self"] is True
    # 2 self pages.
    assert self_row["page_count"] == 2


def test_peers_list_per_peer_page_count(isolated_indrex):
    peer_scraper.upsert_peer(
        isolated_indrex, pubkey="pk_alice", nickname="alice",
    )
    _add_page(
        isolated_indrex, "https://a/1", "A1",
        source_pubkey="pk_alice", source_type="peer_ingest",
    )
    _add_page(
        isolated_indrex, "https://a/2", "A2",
        source_pubkey="pk_alice", source_type="peer_ingest",
    )
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    alice_row = next(p for p in snap["peers"] if p["pubkey"] == "pk_alice")
    assert alice_row["page_count"] == 2


# ── tombstones ─────────────────────────────────────────────────────

def test_deleted_rows_dropped_from_graph(isolated_indrex):
    _add_page(isolated_indrex, "https://a/1", "live")
    _add_page(isolated_indrex, "https://a/2", "dead")
    conn = sqlite3.connect(str(isolated_indrex))
    migration.set_meta(conn, "https://a/2", deleted_at_ms=999)
    conn.commit()
    conn.close()
    snap = indrex_graph.snapshot(own_pubkey="my_pk")
    urls = [n["id"] for n in snap["nodes"]]
    assert urls == ["https://a/1"]


# ── edges from search_results co-occurrence ────────────────────────

def test_edges_built_from_search_result_cooccurrence(isolated_indrex):
    """Two URLs landing under the same query_hash get a weighted edge.
    Edges below weight 2 are dropped."""
    _add_page(isolated_indrex, "https://a/1", "A")
    _add_page(isolated_indrex, "https://b/1", "B")
    conn = sqlite3.connect(str(isolated_indrex))
    # Both URLs co-occur under two distinct queries → weight=2 → kept.
    for q in ("q1", "q2"):
        for url, title in [("https://a/1", "A"), ("https://b/1", "B")]:
            conn.execute(
                "INSERT INTO search_results(query_hash, query, url, "
                "title, snippet, engines, seen_at) "
                "VALUES(?,?,?,?,?,?,?)",
                (q, q, url, title, "s", "ddg", "2026-04-01T00:00:00Z"),
            )
    conn.commit()
    conn.close()
    snap = indrex_graph.snapshot()
    assert len(snap["edges"]) == 1
    e = snap["edges"][0]
    assert {e["source"], e["target"]} == {"https://a/1", "https://b/1"}
    assert e["weight"] == 2


# ── event bus ──────────────────────────────────────────────────────

def test_event_bus_emit_then_recent(isolated_indrex):
    event_bus.emit("page_added", {"url": "https://x/1", "host": "x"})
    rows = event_bus.recent(kind="page_added", limit=10)
    assert len(rows) == 1
    assert rows[0]["kind"] == "page_added"
    assert rows[0]["payload"] == {"url": "https://x/1", "host": "x"}


def test_event_bus_recent_filters_by_kind(isolated_indrex):
    event_bus.emit("a", {"k": 1})
    event_bus.emit("b", {"k": 2})
    event_bus.emit("a", {"k": 3})
    a_rows = event_bus.recent(kind="a", limit=10)
    assert [r["payload"]["k"] for r in a_rows] == [3, 1]
    b_rows = event_bus.recent(kind="b", limit=10)
    assert [r["payload"]["k"] for r in b_rows] == [2]


def test_event_bus_recent_unfiltered_returns_all(isolated_indrex):
    for i in range(3):
        event_bus.emit("k", {"i": i})
    rows = event_bus.recent(limit=10)
    assert len(rows) == 3
    # Most-recent first.
    assert [r["payload"]["i"] for r in rows] == [2, 1, 0]


# ── scraper emits page_added + peer_pull_* through the bus ──────────

def test_ingest_bundle_emits_page_added_per_page(isolated_indrex):
    """Each ingested page fires one `page_added` event with the
    expected fields. The wall consumes this stream."""
    bundle = {
        "schema": "swf.index_pages.v1",
        "pubkey": "pk_alice",
        "since": 0, "until": 2,
        "pages": [
            {"url": "https://a/1", "title": "A1", "host": "a", "topic": "",
             "fetched_at": "", "content_cid": ""},
            {"url": "https://a/2", "title": "A2", "host": "a", "topic": "",
             "fetched_at": "", "content_cid": ""},
        ],
        "merkle_root": "deadbeef",
        "sig": "AAAA",
    }
    n = peer_scraper.ingest_bundle(
        isolated_indrex, bundle, source_label="alice",
    )
    assert n == 2
    rows = event_bus.recent(kind="page_added", limit=10)
    assert len(rows) == 2
    by_url = {r["payload"]["url"]: r["payload"] for r in rows}
    assert by_url["https://a/1"]["source_pubkey"] == "pk_alice"
    assert by_url["https://a/1"]["source_label"] == "alice"


def test_pull_from_peer_emits_started_and_failed_on_http_error(
    isolated_indrex, monkeypatch,
):
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: None)
    peer = peer_scraper.Peer(
        pubkey="pk", nickname="p", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        base_url="http://offline.local:1",
    )
    peer_scraper.pull_from_peer(isolated_indrex, peer)
    started = event_bus.recent(kind="peer_pull_started", limit=10)
    failed = event_bus.recent(kind="peer_pull_failed", limit=10)
    assert len(started) == 1 and started[0]["payload"]["pubkey"] == "pk"
    assert len(failed) == 1 and failed[0]["payload"]["reason"] == "http_error"
