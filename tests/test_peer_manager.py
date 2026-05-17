"""geth/reth-inspired peer-table robustness:

  - self-loop guard (nodeID self-check): never seed our own pubkey
  - prune_stale_peers: evict by age (last_seen_at) AND quality
    (never-worked + repeatedly-broken, like a bad bootnode)
  - liveness_check: cheap /health probe before full bundle pull
  - successful_pulls counter: positive score for ranking/eviction
  - periodic prune from _tick (cleanupInterval-style)
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.peer_scraper import (
    EVICT_AFTER_FAILURES,
    PEER_STALE_DAYS,
    PRUNE_EVERY_TICKS,
    list_peers,
    liveness_check,
    prune_stale_peers,
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


# ── self-loop guard ───────────────────────────────────────────────

def test_seed_from_discovery_skips_own_pubkey(indrex, monkeypatch):
    """If our own mDNS broadcast is picked up by discover_all_peers,
    we MUST NOT add ourselves to the peers table."""
    own_pk = "MY_OWN_PUBKEY_b64"
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: own_pk)

    class _DP:
        def __init__(self, pk):
            self.name = "x"
            self.url = "http://x:7777"
            self.pubkey = pk

    import swf.discovery
    monkeypatch.setattr(swf.discovery, "discover_all_peers", lambda: [
        _DP(own_pk),                 # us — must skip
        _DP("OTHER_PUBKEY"),         # real peer — should land
    ])
    n = peer_scraper._seed_peers_from_discovery(indrex)
    assert n == 1
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"OTHER_PUBKEY"}


def test_bootstrap_yaml_skips_own_pubkey(indrex, tmp_path, monkeypatch):
    """peers.yaml accidentally listing our own pubkey shouldn't cause
    a self-pull deadlock."""
    own_pk = "MY_OWN_PUBKEY_b64"
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: own_pk)
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(
        "peers:\n"
        f"  - name: self-typo\n    url: http://x:7777\n    pubkey: {own_pk}\n"
        "  - name: alice\n    url: http://10.0.0.2:7777\n    pubkey: pk_a\n"
    )
    n = peer_scraper._bootstrap_from_peers_yaml(indrex)
    assert n == 1
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"pk_a"}


# ── successful_pulls counter ──────────────────────────────────────

def test_record_pull_success_bumps_counter(indrex):
    upsert_peer(indrex, pubkey="pk", nickname="x")
    peer_scraper._record_pull_success(indrex, pubkey="pk")
    peer_scraper._record_pull_success(indrex, pubkey="pk")
    rows = list_peers(indrex)
    assert rows[0].successful_pulls == 2
    assert rows[0].consecutive_failures == 0


def test_record_pull_success_unaffected_by_unknown_pubkey(indrex):
    """Unknown pubkey doesn't error and doesn't insert a row."""
    peer_scraper._record_pull_success(indrex, pubkey="ghost")
    assert list_peers(indrex) == []


# ── prune_stale_peers: time-based ────────────────────────────────

def test_prune_evicts_peers_with_old_last_seen(indrex):
    upsert_peer(indrex, pubkey="pk_old", nickname="old")
    upsert_peer(indrex, pubkey="pk_recent", nickname="recent")
    # Backdate one peer's last_seen_at past the threshold.
    from datetime import datetime, timedelta, timezone
    long_ago = (datetime.now(timezone.utc) - timedelta(days=PEER_STALE_DAYS + 5)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
    just_now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn = sqlite3.connect(str(indrex))
    conn.execute("UPDATE peers SET last_seen_at=? WHERE pubkey=?",
                 (long_ago, "pk_old"))
    conn.execute("UPDATE peers SET last_seen_at=? WHERE pubkey=?",
                 (just_now, "pk_recent"))
    conn.commit()
    conn.close()

    stats = prune_stale_peers(indrex)
    assert stats["stale"] == 1
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"pk_recent"}


def test_prune_evicts_peers_never_seen(indrex):
    """A peer with last_seen_at IS NULL counts as stale once we've
    failed enough times — defensive against a peer that was added
    but never reached."""
    upsert_peer(indrex, pubkey="pk", nickname="x")
    # NULL last_seen_at by default. Immediately stale.
    stats = prune_stale_peers(indrex)
    assert stats["stale"] == 1
    assert list_peers(indrex) == []


# ── prune_stale_peers: quality-based ─────────────────────────────

def test_prune_evicts_never_worked_and_repeatedly_broken(indrex):
    """A peer with successful_pulls=0 and many consecutive failures
    is a bad bootnode — evict regardless of last_seen_at."""
    upsert_peer(indrex, pubkey="pk_broken", nickname="broken")
    upsert_peer(indrex, pubkey="pk_working", nickname="working")
    from datetime import datetime, timezone
    just_now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn = sqlite3.connect(str(indrex))
    # broken: NEVER worked, 25 failures → evict by quality rule
    # (would also be evicted by the stale rule since last_seen_at is
    # NULL — but we explicitly set last_seen_at=now to isolate the
    # quality path).
    conn.execute(
        "UPDATE peers SET successful_pulls=0, "
        "consecutive_failures=25, last_seen_at=? WHERE pubkey=?",
        (just_now, "pk_broken"),
    )
    # working: had 5 pulls, 3 current failures → keep
    conn.execute(
        "UPDATE peers SET successful_pulls=5, "
        "consecutive_failures=3, last_seen_at=? WHERE pubkey=?",
        (just_now, "pk_working"),
    )
    conn.commit()
    conn.close()
    stats = prune_stale_peers(indrex)
    assert stats["broken"] == 1
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"pk_working"}


def test_prune_keeps_a_working_peer_with_recent_failures(indrex):
    """A peer that's worked (successful_pulls > 0) but currently has
    failures should NOT be quality-evicted — backoff handles them."""
    upsert_peer(indrex, pubkey="pk", nickname="x")
    from datetime import datetime, timezone
    just_now = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn = sqlite3.connect(str(indrex))
    conn.execute(
        "UPDATE peers SET successful_pulls=10, "
        "consecutive_failures=100, last_seen_at=? WHERE pubkey=?",
        (just_now, "pk"),
    )
    conn.commit()
    conn.close()
    stats = prune_stale_peers(indrex)
    assert stats["broken"] == 0
    assert len(list_peers(indrex)) == 1


def test_prune_handles_missing_db(tmp_path):
    """Defensive: missing DB returns zeroes, doesn't raise."""
    stats = prune_stale_peers(tmp_path / "nope.db")
    assert stats == {"stale": 0, "broken": 0, "kept": 0}


# ── liveness_check ────────────────────────────────────────────────

def test_liveness_check_accepts_ok_response(monkeypatch):
    """A peer responding 200 with {ok: true} is alive."""
    class _R:
        status = 200
        def __init__(self, body): self._b = body
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None):
            return self._b
    monkeypatch.setattr(
        peer_scraper._no_redirect_opener, "open",
        lambda req, timeout=None: _R(b'{"ok": true, "version": "x"}'),
    )
    assert liveness_check("http://peer:7777") is True


def test_liveness_check_rejects_non_200(monkeypatch):
    class _R:
        status = 500
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return b'{"ok": false}'
    monkeypatch.setattr(
        peer_scraper._no_redirect_opener, "open",
        lambda req, timeout=None: _R(),
    )
    assert liveness_check("http://peer:7777") is False


def test_liveness_check_rejects_ok_false(monkeypatch):
    class _R:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n=None): return b'{"ok": false}'
    monkeypatch.setattr(
        peer_scraper._no_redirect_opener, "open",
        lambda req, timeout=None: _R(),
    )
    assert liveness_check("http://peer:7777") is False


def test_liveness_check_rejects_non_http_scheme():
    """SSRF guard: file:// / ftp:// rejected without ever opening."""
    assert liveness_check("file:///etc/passwd") is False
    assert liveness_check("ftp://example.com/x") is False


def test_liveness_check_rejects_empty_url():
    assert liveness_check("") is False


def test_liveness_check_handles_network_error(monkeypatch):
    import urllib.error
    def _boom(req, timeout=None):
        raise urllib.error.URLError("connection refused")
    monkeypatch.setattr(peer_scraper._no_redirect_opener, "open", _boom)
    assert liveness_check("http://offline:1") is False


# ── pull_from_peer fast-fails on dead peer ───────────────────────

def test_pull_from_peer_skips_bundle_when_liveness_fails(
    indrex, monkeypatch,
):
    """A dead peer fails the cheap liveness probe and we don't pay
    the full bundle-fetch round-trip. Records as a pull failure."""
    monkeypatch.setattr(peer_scraper, "liveness_check",
                        lambda url, timeout_s=None: False)
    bundle_calls = {"n": 0}
    def _get(url, timeout=None):
        bundle_calls["n"] += 1
        return None
    monkeypatch.setattr(peer_scraper, "_http_get_json", _get)

    upsert_peer(indrex, pubkey="pk", nickname="x")
    rows = list_peers(indrex)
    p = rows[0]
    p.base_url = "http://offline:1"
    n, status = peer_scraper.pull_from_peer(indrex, p)
    assert (n, status) == (0, "liveness_check_failed")
    # Bundle fetch never happened.
    assert bundle_calls["n"] == 0
    # Failure recorded.
    rows_after = list_peers(indrex)
    assert rows_after[0].consecutive_failures == 1


# ── #100: bootstrap/seed peers must survive the first-tick prune ──
#
# `prune_stale_peers` fires on `_tick_count % PRUNE_EVERY_TICKS == 1`,
# which is true on the very first tick. It evicts any row where
# `last_seen_at IS NULL` as "ancient/never seen." Pre-fix, the
# yaml-bootstrap and mDNS-discovery seeders inserted rows with NULL
# `last_seen_at`, so on a fresh start the bootstrap/seed and the
# prune raced and the prune always won — the peers table ended up
# empty even though peers.yaml or mDNS clearly had entries. Fix:
# stamp `last_seen_at = now()` at insert time. These three tests
# pin the fix at three layers (bootstrap, seed, full _tick).

def test_bootstrap_yaml_survives_first_tick_prune(indrex, tmp_path):
    """#100: a yaml-configured peer must survive a `prune_stale_peers`
    call that runs immediately after `_bootstrap_from_peers_yaml` —
    the exact sequence inside the very first `_tick()`."""
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(
        "peers:\n"
        "  - name: alice\n    url: http://10.0.0.2:7777\n"
        "    pubkey: pk_alice\n"
    )
    n = peer_scraper._bootstrap_from_peers_yaml(indrex)
    assert n == 1
    # The bug: prune evicts NULL last_seen_at rows. The fix: bootstrap
    # stamps last_seen_at=now, so the prune leaves the row alone.
    stats = prune_stale_peers(indrex)
    assert stats["stale"] == 0
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"pk_alice"}


def test_seed_from_discovery_survives_first_tick_prune(indrex, monkeypatch):
    """#100, parallel to the yaml bootstrap: an mDNS-discovered peer
    must also survive the immediately-following prune. Without the
    last_seen_at stamp on the seed path, a freshly-discovered peer
    races the same prune the bootstrap does."""
    class _DP:
        def __init__(self, pk, name="alice"):
            self.name = name
            self.url = "http://x:7777"
            self.pubkey = pk

    import swf.discovery
    monkeypatch.setattr(
        swf.discovery, "discover_all_peers",
        lambda: [_DP("pk_alice")],
    )
    n = peer_scraper._seed_peers_from_discovery(indrex)
    assert n == 1
    stats = prune_stale_peers(indrex)
    assert stats["stale"] == 0
    rows = list_peers(indrex)
    assert {r.pubkey for r in rows} == {"pk_alice"}


def test_full_first_tick_keeps_yaml_peer(indrex, tmp_path, monkeypatch):
    """#100, end-to-end: a full `_tick()` (not bootstrap+prune in
    isolation) on a fresh node with a populated peers.yaml MUST
    leave the yaml peer in the table. This is the exact scenario
    that surfaced the bug — bundle-propagation E2E with mDNS not
    routing on the test machine, peers.yaml was the fallback, and
    the fallback silently evaporated."""
    # peers.yaml with one peer.
    yaml_path = tmp_path / "cfg" / "peers.yaml"
    yaml_path.parent.mkdir(parents=True, exist_ok=True)
    yaml_path.write_text(
        "peers:\n"
        "  - name: alice\n    url: http://10.0.0.2:7777\n"
        "    pubkey: pk_alice\n"
    )
    # mDNS discovery: empty (the bug surfaced when mDNS wasn't
    # surfacing advertisements; yaml was the escape hatch).
    import swf.discovery
    monkeypatch.setattr(swf.discovery, "discover_all_peers", lambda: [])
    # No self-loop interference.
    monkeypatch.setattr(peer_scraper, "_self_pubkey", lambda: "")
    # Hermetic: stub out anything that would HTTP-pull.
    monkeypatch.setattr(
        peer_scraper, "pull_from_peer",
        lambda db, peer, **_: (0, "ok"),
    )
    monkeypatch.setattr(
        peer_scraper, "liveness_check",
        lambda url, timeout_s=None: True,
    )
    monkeypatch.setattr(
        peer_scraper, "_resolve_peer_url",
        lambda peer: "http://10.0.0.2:7777",
    )
    # Force the first-tick prune branch. PRUNE_EVERY_TICKS == 10 and
    # the prune fires on `_tick_count % 10 == 1`. Reset to 0 so that
    # after `_tick` increments, we land on 1 — the precise branch
    # the bug lives on.
    monkeypatch.setattr(peer_scraper, "_tick_count", 0)
    # Reset the once-per-process bootstrap gate so this test sees
    # a real first-process boot.
    monkeypatch.setattr(peer_scraper, "_yaml_bootstrap_done", False)

    # Sanity: peers table starts empty.
    assert list_peers(indrex) == []
    peer_scraper._tick(indrex)
    rows = list_peers(indrex)
    # Bug repro: pre-fix this would be empty (bootstrap inserted
    # then prune deleted within the same tick).
    assert {r.pubkey for r in rows} == {"pk_alice"}, (
        f"yaml peer evicted by first-tick prune (#100 regression). "
        f"rows={rows!r}"
    )
