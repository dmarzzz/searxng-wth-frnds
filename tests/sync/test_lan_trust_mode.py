"""Tests for LAN-trust mode (spec §11; `SWF_TRUST_LAN_PEERS=1`).

When the env var is set, the daemon:

  1. Bypasses the cohort-keys gate in `POST /sync/local_record`.
  2. Skips single-writer-pinning in `apply_envelope` — multiple
     author_pubkeys per `record_id` are valid; no fork is emitted.
  3. Bypasses the cohort-keys whitelist for incoming sync (pull path).

What is NOT bypassed: ed25519 signature verification. A tampered
envelope is still rejected with `signature_invalid`.

See `docs/SYNC.md` §11 for the operator-facing description.
"""
from __future__ import annotations

import json
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from swf.sync import (
    SYNC_MAGIC,
    CohortKeys,
    apply_envelope,
    build_manifest,
    content_hash,
    ensure_schema,
    is_lan_trust_mode,
    is_record_forked,
    latest_envelope,
    sign_envelope,
)
from swf.sync.sync_loop import sync_with_peer

# ── helpers ───────────────────────────────────────────────────────────


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ── env-var helper coverage ───────────────────────────────────────────


def test_is_lan_trust_mode_truthy_values(monkeypatch):
    """`SWF_TRUST_LAN_PEERS` accepts `1`, `true`, `yes`, `on` (any
    case). Anything else is off."""
    monkeypatch.delenv("SWF_TRUST_LAN_PEERS", raising=False)
    assert not is_lan_trust_mode()
    for v in ("1", "true", "TRUE", "Yes", "YES", "on", "ON"):
        monkeypatch.setenv("SWF_TRUST_LAN_PEERS", v)
        assert is_lan_trust_mode(), f"{v!r} should be truthy"
    for v in ("0", "false", "no", "off", "", "maybe", "2"):
        monkeypatch.setenv("SWF_TRUST_LAN_PEERS", v)
        assert not is_lan_trust_mode(), f"{v!r} should be falsy"


# ── #2 single-writer-pinning is relaxed ───────────────────────────────


def test_lan_trust_allows_two_authors_on_same_record_id(
    sync_conn, make_envelope, make_keypair, monkeypatch,
):
    """In LAN-trust mode, two different cohort-keys-less authors can
    both write to the same `record_id`. Both envelopes are stored, the
    record is NOT marked forked, and LWW picks the higher wall_ts_ms."""
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")

    k1 = make_keypair()
    k2 = make_keypair()
    # Empty cohort — neither key is in it. LAN-trust bypasses the
    # whitelist anyway.
    cohort = CohortKeys()

    e1 = make_envelope(
        record_id="amiller", wall_ts_ms=1000,
        content={"v": 1, "by": "k1"},
        priv=k1.priv, pubkey_str=k1.pubkey_str,
    )
    e2 = make_envelope(
        record_id="amiller", wall_ts_ms=2000,
        content={"v": 2, "by": "k2"},
        priv=k2.priv, pubkey_str=k2.pubkey_str,
    )

    r1 = apply_envelope(sync_conn, e1, cohort_keys=cohort)
    r2 = apply_envelope(sync_conn, e2, cohort_keys=cohort)

    assert r1.ok and r1.was_new
    assert r2.ok and r2.was_new
    assert not r1.fork_detected
    assert not r2.fork_detected
    # Both rows persisted.
    n = sync_conn.execute(
        "SELECT COUNT(*) FROM sync_records WHERE record_id=?", ("amiller",),
    ).fetchone()[0]
    assert n == 2
    # No fork flag set.
    assert not is_record_forked(sync_conn, "amiller")
    # LWW: the higher-ts envelope wins.
    latest = latest_envelope(sync_conn, "amiller")
    assert latest["wall_ts_ms"] == 2000
    assert latest["content"] == {"v": 2, "by": "k2"}
    assert latest["author_pubkey"] == k2.pubkey_str
    # Manifest includes the record (no fork suppression).
    manifest = build_manifest(sync_conn)
    assert "amiller" in manifest["records"]


def test_lan_trust_bypasses_author_whitelist(
    sync_conn, sync_keypair, make_envelope, monkeypatch,
):
    """Without LAN-trust, an unknown author is rejected with
    `author_not_in_cohort`. With LAN-trust, the same envelope is
    accepted."""
    # Cohort that doesn't include our keypair.
    cohort = CohortKeys(
        members={"other": "ed25519:" + "00" * 32},
        cohort_id="test-cohort",
        path=Path("/tmp/sync-tests/cohort-keys.json"),
        mtime_ns=0,
    )
    env = make_envelope(record_id="amiller", wall_ts_ms=1000)

    # Off: rejected.
    monkeypatch.delenv("SWF_TRUST_LAN_PEERS", raising=False)
    r_off = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r_off.ok
    assert r_off.reason == "author_not_in_cohort"

    # On: accepted.
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")
    r_on = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert r_on.ok
    assert r_on.was_new


def test_lan_trust_does_not_emit_fork_for_sibling_writes(
    sync_conn, sync_keypair, make_envelope, monkeypatch,
):
    """Spec §11: fork detection is suspended in LAN-trust mode. Two
    same-author sibling envelopes (same prev_hash, different
    content_hash) are accepted as a chain rather than flagged
    `RECORD_FORK_DETECTED`."""
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")
    cohort = CohortKeys()

    e1 = make_envelope(
        record_id="amiller", wall_ts_ms=1000,
        content={"v": 1}, prev_hash=None,
    )
    e2 = make_envelope(
        record_id="amiller", wall_ts_ms=2000,
        content={"v": 2}, prev_hash=None,  # sibling of e1
    )
    apply_envelope(sync_conn, e1, cohort_keys=cohort)
    r2 = apply_envelope(sync_conn, e2, cohort_keys=cohort)
    assert r2.ok
    assert not r2.fork_detected
    assert not is_record_forked(sync_conn, "amiller")
    # Manifest still advertises the record (no fork suppression).
    assert "amiller" in build_manifest(sync_conn)["records"]


# ── #4 signature verification is NEVER skipped ────────────────────────


def test_lan_trust_still_rejects_tampered_envelope(
    sync_conn, sync_keypair, make_envelope, monkeypatch,
):
    """Wire-integrity check is non-negotiable: a tampered envelope is
    rejected with `signature_invalid` even under LAN-trust."""
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")
    cohort = CohortKeys()

    env = make_envelope(record_id="amiller", wall_ts_ms=1000)
    # Tamper wall_ts but keep the signature, content, and content_hash
    # bits intact so we get past shape + content_hash checks and reach
    # the signature gate.
    env["wall_ts_ms"] = env["wall_ts_ms"] + 1
    r = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r.ok
    assert r.reason == "signature_invalid"


# ── #1 / regression: existing strict-mode behavior is unchanged ───────


def test_without_lan_trust_unknown_author_still_rejected(
    sync_conn, sync_keypair, make_envelope, monkeypatch,
):
    """No regression: when `SWF_TRUST_LAN_PEERS` is unset the existing
    cohort-keys gate stays in force."""
    monkeypatch.delenv("SWF_TRUST_LAN_PEERS", raising=False)
    cohort = CohortKeys(
        members={"other": "ed25519:" + "00" * 32},
        cohort_id="test-cohort",
        path=Path("/tmp/sync-tests/cohort-keys.json"),
        mtime_ns=0,
    )
    env = make_envelope(record_id="amiller")
    r = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r.ok
    assert r.reason == "author_not_in_cohort"


def test_without_lan_trust_two_authors_still_collide(
    sync_conn, make_envelope, make_keypair,
    cohort_keys_with, monkeypatch,
):
    """No regression: §9.6 single-writer-pinning still rejects a
    different author when LAN-trust is off."""
    monkeypatch.delenv("SWF_TRUST_LAN_PEERS", raising=False)
    k1 = make_keypair()
    k2 = make_keypair()
    cohort = cohort_keys_with(amiller=k1.pubkey_str, halcyon=k2.pubkey_str)

    e1 = make_envelope(
        record_id="amiller", wall_ts_ms=1000,
        priv=k1.priv, pubkey_str=k1.pubkey_str,
    )
    e2 = make_envelope(
        record_id="amiller", wall_ts_ms=2000,
        priv=k2.priv, pubkey_str=k2.pubkey_str,
    )
    r1 = apply_envelope(sync_conn, e1, cohort_keys=cohort)
    r2 = apply_envelope(sync_conn, e2, cohort_keys=cohort)
    assert r1.ok
    assert not r2.ok
    assert r2.reason == "record_id_owned_by_other_author"


# ── #1 POST /sync/local_record: cohort-keys gate bypassed ─────────────


def test_post_local_record_works_without_cohort_keys_under_lan_trust(
    tmp_path, monkeypatch,
):
    """POST /sync/local_record with no cohort-keys file + LAN_TRUST=1
    → 201 (created) instead of 503 (no_cohort_keys)."""
    from swf import peer_server

    # Isolated config + knowledge dirs.
    knowledge = tmp_path / "knowledge"
    config = tmp_path / "config"
    knowledge.mkdir()
    config.mkdir()
    # No cohort-keys file written anywhere.
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))
    monkeypatch.delenv("SWF_COHORT_KEYS_FILE", raising=False)
    # Point HOME at tmp so the default `~/.config/swf/cohort-keys.json`
    # candidate doesn't resolve to a populated file on the dev box.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    # No agent token required → loopback bypass.
    monkeypatch.delenv("SWF_AGENT_TOKEN", raising=False)
    # Force LAN-trust on.
    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")

    # Reset the cohort-keys cache so we don't get a leftover cohort
    # from a previous test.
    from swf.sync import reset_cohort_keys_cache_for_tests
    reset_cohort_keys_cache_for_tests()

    # Refresh the cached `_DB_PATH` so the new env wins.
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        # Wait for boot.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get_json(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer did not come up")

        body = json.dumps({
            "record_id": "alpha",
            "record_type": "person",
            "content": {"name": "Alpha", "geo": "NYC"},
            "prev_hash": None,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/local_record",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            status = resp.status
            payload = json.loads(resp.read().decode("utf-8"))
        assert status == 201
        assert payload["was_new"]
        env = payload["envelope"]
        # The envelope is self-signed by the local identity.
        assert env["record_id"] == "alpha"
        assert env["author_pubkey"].startswith("ed25519:")
        assert env["signature"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_post_local_record_503_without_lan_trust_when_no_cohort(
    tmp_path, monkeypatch,
):
    """Regression baseline: without LAN-trust, POST /sync/local_record
    returns 503 `no_cohort_keys` when no cohort-keys file exists."""
    from swf import peer_server

    knowledge = tmp_path / "knowledge"
    config = tmp_path / "config"
    knowledge.mkdir()
    config.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))
    monkeypatch.delenv("SWF_COHORT_KEYS_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SWF_AGENT_TOKEN", raising=False)
    monkeypatch.delenv("SWF_TRUST_LAN_PEERS", raising=False)

    from swf.sync import reset_cohort_keys_cache_for_tests
    reset_cohort_keys_cache_for_tests()

    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get_json(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer did not come up")

        body = json.dumps({
            "record_id": "alpha",
            "record_type": "person",
            "content": {"name": "Alpha"},
            "prev_hash": None,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/local_record",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=5.0)
            pytest.fail("expected 503")
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
            payload = json.loads(exc.read().decode("utf-8"))
            assert payload["error"] == "no_cohort_keys"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


# ── #5 two-peer integration under LAN-trust ───────────────────────────


def test_two_peer_sync_works_without_cohort_keys_under_lan_trust(
    tmp_path, monkeypatch,
):
    """Integration scenario: two peers with different identities and
    NO shared cohort-keys successfully sync a record under LAN-trust.

    This is the headline use-case for `SWF_TRUST_LAN_PEERS=1`: a single
    user has SROS installed on two laptops on the same WiFi, each with
    its own keypair, and they want autodiscover-and-sync without
    standing up cohort-keys.
    """
    from swf import peer_server
    from swf.identity import get_or_create_identity

    monkeypatch.setenv("SWF_TRUST_LAN_PEERS", "1")
    # No cohort-keys file anywhere.
    monkeypatch.delenv("SWF_COHORT_KEYS_FILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    # ── Peer A: knowledge dir + identity ────────────────────────────
    a_knowledge = tmp_path / "a" / "knowledge"
    a_config = tmp_path / "a" / "config"
    a_knowledge.mkdir(parents=True)
    a_config.mkdir(parents=True)

    monkeypatch.setenv("SWF_CONFIG_DIR", str(a_config))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(a_knowledge))
    a_ident = get_or_create_identity()
    a_pub_raw = a_ident.pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    a_pubkey_str = "ed25519:" + a_pub_raw.hex()

    # ── Peer B: knowledge dir + identity ────────────────────────────
    b_knowledge = tmp_path / "b" / "knowledge"
    b_config = tmp_path / "b" / "config"
    b_knowledge.mkdir(parents=True)
    b_config.mkdir(parents=True)

    monkeypatch.setenv("SWF_CONFIG_DIR", str(b_config))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(b_knowledge))
    # Force a fresh identity load by clearing any process cache.
    b_ident = get_or_create_identity()
    b_pub_raw = b_ident.pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    b_pubkey_str = "ed25519:" + b_pub_raw.hex()
    assert a_pubkey_str != b_pubkey_str

    # ── Write a record into A's DB ──────────────────────────────────
    a_db = a_knowledge / "index.db"
    a_db.parent.mkdir(parents=True, exist_ok=True)
    a_conn = sqlite3.connect(str(a_db))
    a_conn.row_factory = sqlite3.Row
    ensure_schema(a_conn)
    content = {"name": "Alpha", "geo": "Brooklyn"}
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "alpha",
        "author_pubkey": a_pubkey_str,
        "wall_ts_ms": int(time.time() * 1000),
        "prev_hash": None,
        "content": content,
        "content_hash": content_hash(content),
    }
    env["signature"] = sign_envelope(env, priv=a_ident.priv)
    # Empty cohort — LAN-trust bypasses the whitelist.
    result = apply_envelope(a_conn, env, cohort_keys=CohortKeys())
    assert result.ok and result.was_new
    a_conn.close()

    # ── Boot A's HTTP server, pointed at A's knowledge dir ─────────
    a_port = _free_port()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(a_knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(a_config))
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    a_server, a_thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=a_port,
    )
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get_json(f"http://127.0.0.1:{a_port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer A did not come up")

        # A's manifest already shows the record we wrote.
        a_manifest = _http_get_json(f"http://127.0.0.1:{a_port}/sync/manifest")
        assert "alpha" in a_manifest["records"]
        assert a_manifest["records"]["alpha"]["author_pubkey"] == a_pubkey_str

        # ── Run B's sync_with_peer against A's URL ─────────────────
        b_db = b_knowledge / "index.db"
        b_db.parent.mkdir(parents=True, exist_ok=True)
        b_conn = sqlite3.connect(str(b_db))
        b_conn.row_factory = sqlite3.Row
        ensure_schema(b_conn)

        # Pull. We pass an explicit empty cohort to mirror the
        # production sync_loop path under LAN-trust mode.
        pulled, applied = sync_with_peer(
            b_conn, peer_url=f"http://127.0.0.1:{a_port}",
            cohort_keys=CohortKeys(),
        )
        assert pulled >= 1
        assert applied >= 1

        # B's manifest now shows A's record (no cohort overlap).
        after = build_manifest(b_conn)
        assert "alpha" in after["records"]
        assert after["records"]["alpha"]["author_pubkey"] == a_pubkey_str
        assert after["records"]["alpha"]["latest_content_hash"] == env["content_hash"]
        b_conn.close()
    finally:
        a_server.shutdown()
        a_server.server_close()
        a_thread.join(timeout=2.0)
