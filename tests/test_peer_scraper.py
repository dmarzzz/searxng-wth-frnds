"""Issue #43 PR A — peer indrex scraper tests.

Pins the contract:
  - bundle merkle root is RFC-6962 deterministic (leaves canonically
    encoded; tree built bottom-up with odd-promote)
  - signing payload is domain-separated and covers
    `merkle_root || since || until || pubkey`
  - `verify_bundle` rejects: wrong schema, pubkey mismatch (no peer
    impersonation), tampered page bytes (merkle mismatch), forged
    signature (sig_mismatch)
  - `ingest_bundle` is first-write-wins and tags peer-ingest rows with
    `source_pubkey` / `bundle_root` / `bundle_sig` so the wall can
    color and a future audit can re-prove provenance
  - end-to-end: build → serve → pull → verify → ingest works on a
    real sqlite indrex
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from swf import identity, peer_scraper
from swf.peer_scraper import (
    BUNDLE_SCHEMA,
    Peer,
    build_bundle,
    ingest_bundle,
    latest_cursor,
    list_peers,
    merkle_root,
    signing_payload,
    update_pull_cursor,
    upsert_peer,
    verify_bundle,
)
from swf.search import migration

# ── helpers ─────────────────────────────────────────────────────────

def _seed_indrex(db: Path, rows: list[tuple[str, str, str, str]],
                 share_scope: str = "friends") -> None:
    """Build an indrex with FTS5 `pages` plus the migration sidecar.
    Each row: (url, title, content, fetched_at).

    Default `share_scope='friends'` so seeded rows land in the bundle —
    after pass-5 finding #7 fix, build_bundle filters out the
    `private` default and these tests would all return empty bundles."""
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
    for u, t, c, f in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (u, t, c, f),
        )
        conn.execute(
            "INSERT INTO page_cids(url, content_cid, computed_at) VALUES(?,?,?)",
            (u, f"cid:{u[-4:]}", "2026-01-01T00:00:00Z"),
        )
        migration.set_meta(conn, u, share_scope=share_scope)
    conn.commit()
    conn.close()


@pytest.fixture
def peer_indrex(tmp_path, monkeypatch):
    """Build an indrex DB with three pages and a fresh ed25519 identity
    pinned to a tmp directory."""
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    (tmp_path / "wk").mkdir(parents=True, exist_ok=True)
    db = tmp_path / "wk" / "index.db"
    _seed_indrex(db, [
        ("https://a.example/p1", "Alice page one", "alpha", "2026-04-01"),
        ("https://b.example/p2", "Bob page two", "beta",  "2026-04-02"),
        ("https://c.example/p3", "Carol page three", "gamma", "2026-04-03"),
    ])
    return db


# ── merkle root determinism ─────────────────────────────────────────

def test_merkle_root_empty_is_empty_string():
    assert merkle_root([]) == ""


def test_merkle_root_single_leaf_is_leaf_hash():
    p = {"url": "u", "title": "t", "host": "h",
         "topic": "", "fetched_at": "f", "content_cid": "c"}
    root = merkle_root([p])
    assert len(root) == 64  # sha256 hex
    # Identical input → identical root.
    assert merkle_root([p]) == root


def test_merkle_root_changes_with_any_field():
    p = {"url": "u", "title": "t", "host": "h",
         "topic": "", "fetched_at": "f", "content_cid": "c"}
    base = merkle_root([p])
    for field in ("url", "title", "host", "topic", "fetched_at", "content_cid"):
        mut = dict(p)
        mut[field] = "DIFFERENT"
        assert merkle_root([mut]) != base, \
            f"flipping {field} did not change the root"


def test_merkle_root_handles_odd_count():
    """RFC-6962 odd-promote: a 3-leaf tree must produce a stable root.
    The middle leaf is NOT duplicated; the lone right leaf at level-1
    is promoted directly."""
    pages = [
        {"url": f"u{i}", "title": f"t{i}", "host": "", "topic": "",
         "fetched_at": "", "content_cid": ""} for i in range(3)
    ]
    r = merkle_root(pages)
    assert len(r) == 64
    # Not equal to the 2-leaf or 4-leaf variant.
    assert r != merkle_root(pages[:2])


# ── signing payload domain separation ───────────────────────────────

def test_signing_payload_includes_all_fields():
    a = signing_payload(merkle_root_hex="aa", since=1, until=2,
                        pubkey_b64="pk", page_count=3,
                        epoch_id="ep_abc")
    assert b"swf.index_pages.v1" in a
    assert b"\naa\n" in a
    assert b"\n1\n" in a
    assert b"\n2\n" in a
    assert b"\npk\n" in a
    assert b"\n3\n" in a
    # P2P-review #2: epoch_id is the trailing field
    assert a.endswith(b"ep_abc")


def test_signing_payload_changes_with_each_field():
    base = signing_payload(merkle_root_hex="aa", since=1, until=2, pubkey_b64="pk")
    assert signing_payload(merkle_root_hex="bb", since=1, until=2, pubkey_b64="pk") != base
    assert signing_payload(merkle_root_hex="aa", since=9, until=2, pubkey_b64="pk") != base
    assert signing_payload(merkle_root_hex="aa", since=1, until=9, pubkey_b64="pk") != base
    assert signing_payload(merkle_root_hex="aa", since=1, until=2, pubkey_b64="other") != base


# ── build_bundle / latest_cursor on a real indrex ──────────────────

def test_build_bundle_returns_all_three_pages(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    assert bundle["schema"] == BUNDLE_SCHEMA
    assert len(bundle["pages"]) == 3
    assert bundle["since"] == 0
    assert bundle["until"] == 3
    assert bundle["merkle_root"]
    assert bundle["sig"]


def test_build_bundle_respects_since_cursor(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=2, limit=100)
    # Only the third page (rowid=3) is past cursor 2.
    assert len(bundle["pages"]) == 1
    assert bundle["pages"][0]["url"] == "https://c.example/p3"
    assert bundle["since"] == 2
    assert bundle["until"] == 3


def test_build_bundle_respects_limit(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=2)
    assert len(bundle["pages"]) == 2
    # Cursor advances to the largest rowid actually emitted.
    assert bundle["until"] == 2


def test_build_bundle_empty_when_nothing_new(peer_indrex):
    """Past the last rowid, the bundle is empty but still signed —
    callers can advance their cursor without an http error."""
    bundle = build_bundle(db_path=peer_indrex, since=999, limit=100)
    assert bundle["pages"] == []
    assert bundle["merkle_root"] == ""
    assert bundle["sig"]   # still signed
    assert bundle["until"] == 999


def test_build_bundle_includes_host_and_cid(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    a = next(p for p in bundle["pages"] if p["url"] == "https://a.example/p1")
    assert a["host"] == "a.example"
    assert a["content_cid"] == "cid:e/p1"  # last 4 chars of url


def test_latest_cursor_matches_max_rowid(peer_indrex):
    assert latest_cursor(peer_indrex) == 3


def test_latest_cursor_zero_when_db_missing(tmp_path):
    assert latest_cursor(tmp_path / "missing.db") == 0


# ── verify_bundle: positive + every rejection path ──────────────────

def test_verify_bundle_happy_path(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    pubkey = bundle["pubkey"]
    v = verify_bundle(bundle, expected_pubkey=pubkey)
    assert v.ok, v.reason


def test_verify_bundle_wrong_schema(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["schema"] = "swf.someone_else.v1"
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "wrong_schema"


def test_verify_bundle_pubkey_mismatch(peer_indrex):
    """Critical safety: a peer cannot impersonate another. If the
    bundle declares pubkey X but the puller expected Y, reject."""
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    v = verify_bundle(bundle, expected_pubkey="some_other_pubkey")
    assert not v.ok and v.reason == "pubkey_mismatch"


def test_verify_bundle_merkle_mismatch(peer_indrex):
    """Flip a single byte in any page → recomputed root differs from
    declared root → rejected as merkle_mismatch."""
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["pages"][0]["title"] = "TAMPERED"
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "merkle_mismatch"


def test_verify_bundle_forged_signature(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["sig"] = "AAAA" * 16  # garbage of the right length
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "sig_mismatch"


def test_verify_bundle_inverted_cursor(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["since"] = 10
    bundle["until"] = 0
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "cursor_inverted"


def test_verify_bundle_pages_not_a_list(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["pages"] = {"oops": True}
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "pages_not_a_list"


def test_verify_bundle_missing_sig(peer_indrex):
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    bundle["sig"] = ""
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok and v.reason == "missing_sig"


def test_verify_bundle_not_a_dict():
    v = verify_bundle("not-a-bundle", expected_pubkey="pk")  # type: ignore[arg-type]
    assert not v.ok and v.reason == "not_a_dict"


# ── ingest_bundle into a fresh local indrex ────────────────────────

def test_ingest_bundle_writes_pages_and_attribution(peer_indrex, tmp_path):
    """Build a bundle from peer_indrex, ingest it into a fresh local
    indrex. The local indrex now has the peer's pages with full
    attribution columns set."""
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    local_db = tmp_path / "local.db"
    # Bootstrap the local indrex with empty `pages` + `page_cids`.
    conn = sqlite3.connect(str(local_db))
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
    conn.commit()
    conn.close()

    n = ingest_bundle(local_db, bundle, source_label="alice")
    assert n == 3

    # Pages landed.
    conn = sqlite3.connect(str(local_db))
    urls = [r[0] for r in conn.execute("SELECT url FROM pages").fetchall()]
    assert sorted(urls) == [
        "https://a.example/p1",
        "https://b.example/p2",
        "https://c.example/p3",
    ]
    # Attribution sidecar populated.
    rows = conn.execute(
        "SELECT url, source_type, source_pubkey, source_label, "
        "       bundle_root, bundle_sig FROM pages_meta"
    ).fetchall()
    by_url = {r[0]: r for r in rows}
    a_row = by_url["https://a.example/p1"]
    assert a_row[1] == "peer_ingest"
    assert a_row[2] == bundle["pubkey"]
    assert a_row[3] == "alice"
    assert a_row[4] == bundle["merkle_root"]
    assert a_row[5] == bundle["sig"]
    conn.close()


def test_ingest_bundle_first_write_wins(peer_indrex, tmp_path):
    """If a page URL already exists in the local indrex, the peer's
    copy is silently skipped — no overwrite, no exception."""
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    local_db = tmp_path / "local.db"
    _seed_indrex(local_db, [
        ("https://a.example/p1", "MINE", "my-content", "self-fetched"),
    ])
    n = ingest_bundle(local_db, bundle, source_label="alice")
    # 2 stored (b and c); the existing https://a.example/p1 is skipped.
    assert n == 2
    conn = sqlite3.connect(str(local_db))
    title = conn.execute(
        "SELECT title FROM pages WHERE url=?",
        ("https://a.example/p1",),
    ).fetchone()[0]
    assert title == "MINE"   # not overwritten by peer's "Alice page one"
    conn.close()


def test_ingest_bundle_empty_returns_zero(peer_indrex, tmp_path):
    bundle = build_bundle(db_path=peer_indrex, since=999, limit=10)
    local_db = tmp_path / "local.db"
    _seed_indrex(local_db, [])
    assert ingest_bundle(local_db, bundle) == 0


# ── peers table CRUD ────────────────────────────────────────────────

def test_upsert_peer_then_list(peer_indrex):
    upsert_peer(peer_indrex, pubkey="pk_alice", nickname="alice",
                signature_color="#ff0", signature_freq=440.0,
                trust_level="trusted")
    rows = list_peers(peer_indrex)
    assert len(rows) == 1
    assert rows[0].pubkey == "pk_alice"
    assert rows[0].nickname == "alice"
    assert rows[0].trust_level == "trusted"
    assert rows[0].last_pull_cursor == 0


def test_upsert_peer_idempotent_on_pubkey(peer_indrex):
    upsert_peer(peer_indrex, pubkey="pk_x", nickname="first")
    upsert_peer(peer_indrex, pubkey="pk_x", nickname="second")
    rows = list_peers(peer_indrex)
    assert len(rows) == 1
    assert rows[0].nickname == "second"


def test_update_pull_cursor_advances(peer_indrex):
    upsert_peer(peer_indrex, pubkey="pk_x")
    update_pull_cursor(peer_indrex, pubkey="pk_x", cursor=42)
    rows = list_peers(peer_indrex)
    assert rows[0].last_pull_cursor == 42
    assert rows[0].last_seen_at  # not None


def test_upsert_peer_rejects_bad_trust_level(peer_indrex):
    with pytest.raises(ValueError):
        upsert_peer(peer_indrex, pubkey="pk_x", trust_level="god_mode")


# ── pull_from_peer end-to-end (in-memory transport) ────────────────

@pytest.fixture(autouse=True)
def _liveness_passes(monkeypatch):
    """Existing pull-from-peer tests assume bundle-fetch runs. After
    PR #62 we added a liveness probe before the fetch — stub it as
    pass-through so these tests cover the bundle path they were
    written to cover."""
    monkeypatch.setattr(peer_scraper, "liveness_check",
                        lambda url, timeout_s=None: True)


def test_pull_from_peer_full_round_trip(peer_indrex, tmp_path, monkeypatch):
    """Stub out _http_get_json with the peer's build_bundle directly:
    the puller serializes through verify+ingest+cursor-advance."""
    # Capture alice's identity (the producer's) and bundle BEFORE
    # repointing SWF_CONFIG_DIR — once we move it, get_or_create_identity()
    # would return the puller's identity instead.
    alice_ident = identity.get_or_create_identity()
    alice_pubkey = alice_ident.pub_b64
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100,
                          ident=alice_ident)

    # Spin up a *separate* local indrex on a different config dir
    # so the puller has its own identity.
    local_dir = tmp_path / "puller"
    local_dir.mkdir()
    monkeypatch.setenv("SWF_CONFIG_DIR", str(local_dir / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(local_dir / "wk"))
    (local_dir / "wk").mkdir()
    local_db = local_dir / "wk" / "index.db"
    _seed_indrex(local_db, [])
    upsert_peer(local_db, pubkey=alice_pubkey, nickname="alice")
    peer_pubkey = alice_pubkey

    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: bundle)
    peer = Peer(
        pubkey=peer_pubkey, nickname="alice",
        last_seen_at=None, last_pull_cursor=0,
        trust_level="known", base_url="http://alice.local:7777",
    )
    stored, status = peer_scraper.pull_from_peer(local_db, peer)
    assert status == "ok"
    assert stored == 3

    # Cursor advanced.
    rows = list_peers(local_db)
    assert rows[0].last_pull_cursor == 3


def test_pull_from_peer_rejects_pubkey_mismatch(peer_indrex, tmp_path, monkeypatch):
    """If the peer-row records pubkey X but the bundle declares Y,
    pull_from_peer must refuse — that's the impersonation guard."""
    monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=10)
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: bundle)
    local_db = tmp_path / "local.db"
    _seed_indrex(local_db, [])
    peer = Peer(
        pubkey="WRONG_PUBKEY", nickname="liar",
        last_seen_at=None, last_pull_cursor=0,
        trust_level="known", base_url="http://liar.local:7777",
    )
    stored, status = peer_scraper.pull_from_peer(local_db, peer)
    assert stored == 0
    assert status == "verify:pubkey_mismatch"


def test_pull_from_peer_skips_banned_only_when_trust_flag_set(monkeypatch):
    """Trust gating is opt-in via SWF_ENABLE_PEER_TRUST. Default off
    means every peer pulls regardless of trust_level."""
    monkeypatch.setenv("SWF_ENABLE_PEER_TRUST", "1")
    peer = Peer(
        pubkey="pk", nickname="bad", last_seen_at=None,
        last_pull_cursor=0, trust_level="banned",
        base_url="http://x:1",
    )
    n, status = peer_scraper.pull_from_peer(Path("/dev/null"), peer)
    assert (n, status) == (0, "banned")


def test_pull_from_peer_default_ignores_trust_level(monkeypatch):
    """Without the trust flag, a `banned` peer is still pulled (it
    just hits the http_error path because the URL is bogus). The
    point: trust_level is stored but inert."""
    monkeypatch.delenv("SWF_ENABLE_PEER_TRUST", raising=False)
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: None)
    peer = Peer(
        pubkey="pk", nickname="bad", last_seen_at=None,
        last_pull_cursor=0, trust_level="banned",
        base_url="http://x:1",
    )
    n, status = peer_scraper.pull_from_peer(Path("/dev/null"), peer)
    # NOT "banned" — we attempted the pull and got http_error from
    # the stub. Confirms the trust check was skipped.
    assert status == "http_error"


def test_pull_from_peer_skips_no_url():
    peer = Peer(
        pubkey="pk", nickname="x", last_seen_at=None,
        last_pull_cursor=0, trust_level="known", base_url="",
    )
    n, status = peer_scraper.pull_from_peer(Path("/dev/null"), peer)
    assert (n, status) == (0, "no_url")


def test_pull_from_peer_handles_http_error(monkeypatch):
    monkeypatch.setattr(peer_scraper, "_http_get_json",
                        lambda url, timeout=None: None)
    peer = Peer(
        pubkey="pk", nickname="x", last_seen_at=None,
        last_pull_cursor=0, trust_level="known",
        base_url="http://offline.local:1",
    )
    n, status = peer_scraper.pull_from_peer(Path("/dev/null"), peer)
    assert (n, status) == (0, "http_error")
