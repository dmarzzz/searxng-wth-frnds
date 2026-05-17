"""P2P-review #5 + #6 — peer-model unification + signature_for move.

Pins:
  - `swf.peer_scraper.IndrexPeer` is the canonical scraper-side model
  - `Peer` remains as a back-compat alias
  - peers.yaml entries with a pubkey are bootstrap-migrated into
    `indrex.peers` on first scraper tick (idempotent across runs)
  - `swf.peer_signature.signature_for` is importable without
    `community_full` extras
  - `community_full.db.signature_for` re-exports the new module so
    legacy callers keep working
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper, peer_signature
from swf.peer_scraper import (
    IndrexPeer,
    Peer,
    _bootstrap_from_peers_yaml,
    _bootstrap_once_from_yaml,
    list_peers,
    upsert_peer,
)
from swf.search import migration


def _seed_indrex(db: Path) -> None:
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE VIRTUAL TABLE pages USING fts5(
            url UNINDEXED, title, content, fetched_at UNINDEXED,
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


@pytest.fixture
def indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    (tmp_path / "wk").mkdir(parents=True)
    (tmp_path / "cfg").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    _seed_indrex(db)
    # Reset the module-level once-flag so each test exercises it.
    peer_scraper._yaml_bootstrap_done = False
    return db


# ── #5 IndrexPeer rename + back-compat alias ───────────────────────

def test_peer_alias_points_at_indrex_peer():
    assert Peer is IndrexPeer


def test_indrex_peer_carries_full_state():
    """IndrexPeer holds the runtime fields that peers.yaml's `Peer`
    does not (cursor, epoch, trust). Pin the dataclass shape."""
    p = IndrexPeer(
        pubkey="pk", nickname="alice",
        last_seen_at=None, last_pull_cursor=42,
        trust_level="known",
    )
    assert hasattr(p, "last_pull_cursor")
    assert hasattr(p, "trust_level")
    assert hasattr(p, "last_seen_epoch")
    assert hasattr(p, "base_url")


# ── #5 yaml bootstrap migration ────────────────────────────────────

def test_bootstrap_from_yaml_imports_pubkey_entries(indrex, tmp_path,
                                                     monkeypatch):
    """A peers.yaml entry with a pubkey lands in indrex.peers with
    a deterministic signature_color and Hz."""
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.write_text(
        "peers:\n"
        "  - name: alice-laptop\n"
        "    url: http://10.0.0.2:7777\n"
        "    pubkey: pk_alice\n"
        "  - name: bob-no-pubkey\n"
        "    url: http://10.0.0.3:7777\n"
    )
    n = _bootstrap_from_peers_yaml(indrex)
    # Only alice has a pubkey → only alice gets imported.
    assert n == 1
    rows = list_peers(indrex)
    assert len(rows) == 1
    assert rows[0].pubkey == "pk_alice"
    assert rows[0].nickname == "alice-laptop"
    # Color matches signature_for.
    color, _ = peer_signature.signature_for("pk_alice")
    conn = sqlite3.connect(str(indrex))
    stored_color = conn.execute(
        "SELECT signature_color FROM peers WHERE pubkey=?",
        ("pk_alice",),
    ).fetchone()[0]
    conn.close()
    assert stored_color == color


def test_bootstrap_skips_existing_pubkeys(indrex, tmp_path):
    """If alice is already in indrex.peers, the yaml entry doesn't
    overwrite. Idempotent across runs."""
    upsert_peer(indrex, pubkey="pk_alice", nickname="manually_added")
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.write_text(
        "peers:\n"
        "  - name: from-yaml\n"
        "    url: http://x:7777\n"
        "    pubkey: pk_alice\n"
    )
    n = _bootstrap_from_peers_yaml(indrex)
    assert n == 0
    rows = list_peers(indrex)
    assert rows[0].nickname == "manually_added"


def test_bootstrap_once_runs_once_per_process(indrex, tmp_path):
    """The bootstrap fires on first call and never again — even if
    new yaml entries appear. Operators add new peers via
    `swf-peer add` (or the auto-discovery path), not yaml edits."""
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.write_text(
        "peers:\n  - name: a\n    url: http://x\n    pubkey: pk_a\n"
    )
    n1 = _bootstrap_once_from_yaml(indrex)
    assert n1 == 1
    # Even if yaml grows, second call is a no-op.
    yaml_path.write_text(
        "peers:\n"
        "  - name: a\n    url: http://x\n    pubkey: pk_a\n"
        "  - name: b\n    url: http://y\n    pubkey: pk_b\n"
    )
    n2 = _bootstrap_once_from_yaml(indrex)
    assert n2 == 0


# ── #6 signature_for moved to its own module ──────────────────────

def test_signature_for_in_new_module():
    """The canonical home is `swf.peer_signature` (no DB dependency,
    no community_full extras needed)."""
    color, freq = peer_signature.signature_for("pk_test")
    assert color.startswith("#") and len(color) == 7
    assert 220.0 <= freq <= 880.0


def test_signature_for_back_compat_via_community_full_db():
    """Old callers that imported from `community_full.db` still work
    — re-exported for compat."""
    from swf.community_full.db import signature_for as legacy
    color1, freq1 = legacy("pk_test")
    color2, freq2 = peer_signature.signature_for("pk_test")
    assert (color1, freq1) == (color2, freq2)


def test_signature_for_deterministic():
    """Same pubkey → same color/freq forever. The wall relies on
    this stability across sessions."""
    a = peer_signature.signature_for("alice-pubkey")
    b = peer_signature.signature_for("alice-pubkey")
    c = peer_signature.signature_for("bob-pubkey")
    assert a == b
    assert a != c


def test_signature_for_uses_palette():
    """The 12-color palette is hand-picked for distinctness. Confirm
    every output is in that palette."""
    palette = set(peer_signature._PALETTE)
    for i in range(50):
        color, _ = peer_signature.signature_for(f"pk_{i}")
        assert color in palette
