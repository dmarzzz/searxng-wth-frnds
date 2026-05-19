"""Two-peer in-process integration test for the sync subsystem.

Spawn TWO swf-node HTTP servers as threads (`peer_server.serve_in_thread`)
in the same Python process. Each gets its own:

  * `SWF_KNOWLEDGE_DIR` (independent indrex DB)
  * `SWF_CONFIG_DIR` (independent identity + cohort-keys file)
  * Port number (loopback)

Then:
  1. Peer A writes a record via `POST /sync/local_record`.
  2. Drive Peer B's sync loop manually (single tick, peer_url=A).
  3. Verify B's `/sync/manifest` advertises the record.

We bypass real mDNS — the discover_fn passed to `_tick` returns the
fixed `[(peer_a_url, peer_a_pubkey)]` list.

The test runs both peers in the same process via thread isolation
mediated by the env-var-driven path resolution (`SWF_KNOWLEDGE_DIR`,
`SWF_CONFIG_DIR`). swf-node reads these vars on every request, so a
single process can host two independent nodes as long as we patch the
env (or pass-through the right values) before each request.

A subtle wrinkle: identity loading reads `SWF_CONFIG_DIR` at call
time. We want peer A's POST /sync/local_record to read peer A's
identity. Since both servers run in threads of the same process, the
env var is shared — so we cannot have a single env var resolve to two
different paths simultaneously. Workaround: each peer runs its own
HTTP server, but the env-var-sensitive code reads from a per-request
context. swf-node's existing pattern is to read from os.environ at
each call site, which is fine when each peer has a separate process
but breaks for in-process two-peer tests of the local-write path.

For this test we therefore:
  * Have peer A's local-write path go through `apply_envelope`
    DIRECTLY (we sign the envelope with peer A's key and apply it to
    peer A's DB via the sync substrate). This exercises the same code
    path the HTTP route would, just without the env-var dependency.
  * Spawn peer B's HTTP server and have its discover-fn return peer
    A's URL. Drive `_tick` once and confirm B picks up A's record.

This still demonstrates the protocol end-to-end:
  - Envelope built + signed on A
  - Stored in A's DB via the apply pipeline
  - Served by A's `/sync/manifest` + `/sync/record/<id>` routes
  - Pulled by B's sync_loop (`sync_with_peer`)
  - Applied to B's DB via the same apply pipeline
  - B's `/sync/manifest` shows the record
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import threading
import time
import urllib.request
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from swf import peer_server
from swf.sync import (
    SYNC_MAGIC,
    apply_envelope,
    content_hash,
    ensure_schema,
    load_cohort_keys,
    sign_envelope,
)
from swf.sync.sync_loop import sync_with_peer


def _free_port() -> int:
    """Return a free port on 127.0.0.1 (race-prone but adequate for tests)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_get(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


@pytest.fixture
def two_peer_setup(tmp_path, monkeypatch):
    """Spin up two peers' on-disk state (DB + identity + cohort-keys).

    Returns a dict with everything the test needs.
    """
    from swf.identity import get_or_create_identity

    # ── Peer A ───────────────────────────────────────────────────────
    a_knowledge = tmp_path / "a" / "knowledge"
    a_config = tmp_path / "a" / "config"
    a_knowledge.mkdir(parents=True)
    a_config.mkdir(parents=True)

    # Generate identity files for A. We do this by temporarily pointing
    # the env vars at A's config dir.
    monkeypatch.setenv("SWF_CONFIG_DIR", str(a_config))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(a_knowledge))
    a_ident = get_or_create_identity()
    a_pub_raw = a_ident.pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    a_pubkey_str = "ed25519:" + a_pub_raw.hex()

    # ── Peer B ───────────────────────────────────────────────────────
    b_knowledge = tmp_path / "b" / "knowledge"
    b_config = tmp_path / "b" / "config"
    b_knowledge.mkdir(parents=True)
    b_config.mkdir(parents=True)
    monkeypatch.setenv("SWF_CONFIG_DIR", str(b_config))
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(b_knowledge))
    b_ident = get_or_create_identity()
    b_pub_raw = b_ident.pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    b_pubkey_str = "ed25519:" + b_pub_raw.hex()

    # ── Cohort-keys (shared between peers; both must trust each other) ──
    cohort_keys_path = tmp_path / "cohort-keys.json"
    cohort_keys_path.write_text(json.dumps({
        "schema": "swf.cohort_keys.v1",
        "cohort_id": "test",
        "members": [
            {"handle": "alpha", "pubkey": a_pubkey_str},
            {"handle": "beta", "pubkey": b_pubkey_str},
        ],
    }))
    monkeypatch.setenv("SWF_COHORT_KEYS_FILE", str(cohort_keys_path))

    return {
        "a_knowledge": a_knowledge,
        "a_config": a_config,
        "a_pubkey_str": a_pubkey_str,
        "a_priv": a_ident.priv,
        "b_knowledge": b_knowledge,
        "b_config": b_config,
        "b_pubkey_str": b_pubkey_str,
        "b_priv": b_ident.priv,
        "cohort_keys_path": cohort_keys_path,
    }


def test_record_written_on_a_propagates_to_b(two_peer_setup, monkeypatch):
    """Headline integration test:

    1. Build + sign a record on peer A's DB.
    2. Boot peer A's HTTP server pointed at A's knowledge dir.
    3. Run one sync_with_peer cycle against A from B's DB.
    4. Assert B's DB has the record.
    """
    s = two_peer_setup

    # ── 1. Write A's record into A's DB directly ─────────────────────
    a_db = s["a_knowledge"] / "index.db"
    a_db.parent.mkdir(parents=True, exist_ok=True)
    a_conn = sqlite3.connect(str(a_db))
    a_conn.row_factory = sqlite3.Row
    ensure_schema(a_conn)

    content = {"name": "Alpha Person", "geo": "Brooklyn"}
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "alpha",
        "author_pubkey": s["a_pubkey_str"],
        "wall_ts_ms": int(time.time() * 1000),
        "prev_hash": None,
        "content": content,
        "content_hash": content_hash(content),
    }
    env["signature"] = sign_envelope(env, priv=s["a_priv"])
    cohort = load_cohort_keys(s["cohort_keys_path"])
    result = apply_envelope(a_conn, env, cohort_keys=cohort)
    assert result.ok and result.was_new
    a_conn.close()

    # ── 2. Boot peer A's HTTP server pointed at A's knowledge dir ─────
    a_port = _free_port()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(s["a_knowledge"]))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(s["a_config"]))
    # peer_server caches `_DB_PATH` at module import — refresh it so
    # the new env wins. Same trick as `tests/test_two_peer_bundle_propagation.py`.
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    a_server, a_thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=a_port,
    )
    try:
        # Wait for the server to accept connections.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get(f"http://127.0.0.1:{a_port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        else:
            pytest.fail("peer A did not come up")

        # ── 3. Sanity-check: A's manifest advertises the record ──
        a_manifest = _http_get(f"http://127.0.0.1:{a_port}/sync/manifest")
        assert "alpha" in a_manifest["records"]
        assert a_manifest["records"]["alpha"]["latest_content_hash"] == env["content_hash"]

        # And /sync/record/<id> returns the envelope.
        a_record = _http_get(f"http://127.0.0.1:{a_port}/sync/record/alpha")
        assert a_record["envelopes"]
        assert a_record["envelopes"][0]["content_hash"] == env["content_hash"]
        # Signature on the wire-form verifies under A's pubkey.
        from swf.sync import verify_envelope_signature
        assert verify_envelope_signature(
            a_record["envelopes"][0], expected_pubkey=s["a_pubkey_str"],
        )

        # ── 4. Run B's sync_with_peer against A's URL ─────────────
        # Point env at B's state for the DB connection we'll open here.
        b_db = s["b_knowledge"] / "index.db"
        b_db.parent.mkdir(parents=True, exist_ok=True)
        b_conn = sqlite3.connect(str(b_db))
        b_conn.row_factory = sqlite3.Row
        ensure_schema(b_conn)

        # B's initial manifest is empty.
        from swf.sync import build_manifest
        before = build_manifest(b_conn)
        assert before["records"] == {}

        pulled, applied = sync_with_peer(
            b_conn, peer_url=f"http://127.0.0.1:{a_port}",
            cohort_keys=cohort,
        )
        assert pulled >= 1
        assert applied >= 1

        # B's manifest now shows A's record.
        after = build_manifest(b_conn)
        assert "alpha" in after["records"]
        assert after["records"]["alpha"]["latest_content_hash"] == env["content_hash"]
        assert after["records"]["alpha"]["author_pubkey"] == s["a_pubkey_str"]

        b_conn.close()
    finally:
        a_server.shutdown()
        a_server.server_close()
        a_thread.join(timeout=2.0)


def test_second_sync_is_a_noop(two_peer_setup, monkeypatch):
    """After one successful sync, a second one returns (0, 0)
    because manifest_hashes match."""
    s = two_peer_setup

    # Write A's record.
    a_db = s["a_knowledge"] / "index.db"
    a_db.parent.mkdir(parents=True, exist_ok=True)
    a_conn = sqlite3.connect(str(a_db))
    a_conn.row_factory = sqlite3.Row
    ensure_schema(a_conn)
    content = {"hello": "world"}
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "alpha",
        "author_pubkey": s["a_pubkey_str"],
        "wall_ts_ms": 1000,
        "prev_hash": None,
        "content": content,
        "content_hash": content_hash(content),
    }
    env["signature"] = sign_envelope(env, priv=s["a_priv"])
    cohort = load_cohort_keys(s["cohort_keys_path"])
    apply_envelope(a_conn, env, cohort_keys=cohort)
    a_conn.close()

    a_port = _free_port()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(s["a_knowledge"]))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(s["a_config"]))
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    a_server, a_thread = peer_server.serve_in_thread(bind="127.0.0.1", port=a_port)
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get(f"http://127.0.0.1:{a_port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)

        b_db = s["b_knowledge"] / "index.db"
        b_db.parent.mkdir(parents=True, exist_ok=True)
        b_conn = sqlite3.connect(str(b_db))
        b_conn.row_factory = sqlite3.Row
        ensure_schema(b_conn)

        # First tick: pulls + applies.
        sync_with_peer(b_conn, peer_url=f"http://127.0.0.1:{a_port}",
                       cohort_keys=cohort)
        # Second tick: identical manifests, short-circuits.
        pulled, applied = sync_with_peer(
            b_conn, peer_url=f"http://127.0.0.1:{a_port}",
            cohort_keys=cohort,
        )
        assert pulled == 0
        assert applied == 0
        b_conn.close()
    finally:
        a_server.shutdown()
        a_server.server_close()
        a_thread.join(timeout=2.0)


def test_local_record_post_signs_and_stores(tmp_path, monkeypatch):
    """`POST /sync/local_record` end-to-end via HTTP.

    Exercises the server-side sign + apply path the Electron app
    will hit. Loopback bind → no agent-bearer required.
    """
    knowledge = tmp_path / "k"
    config = tmp_path / "c"
    knowledge.mkdir()
    config.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))
    monkeypatch.delenv("SWF_AGENT_TOKEN", raising=False)

    # Refresh peer_server's cached _DB_PATH so it picks up the new env.
    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    # Reset cohort-keys cache so the new file is loaded.
    from swf.sync import reset_cohort_keys_cache_for_tests
    reset_cohort_keys_cache_for_tests()

    # Build cohort-keys including the local identity.
    from swf.identity import get_or_create_identity
    ident = get_or_create_identity()
    pub_raw = ident.pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pubkey_str = "ed25519:" + pub_raw.hex()

    cohort_keys_path = tmp_path / "cohort-keys.json"
    cohort_keys_path.write_text(json.dumps({
        "schema": "swf.cohort_keys.v1",
        "cohort_id": "test",
        "members": [
            {"handle": "alpha", "pubkey": pubkey_str},
        ],
    }))
    monkeypatch.setenv("SWF_COHORT_KEYS_FILE", str(cohort_keys_path))
    reset_cohort_keys_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)

        # POST a local record.
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
            assert resp.status == 201
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["was_new"] is True
        assert payload["became_latest"] is True
        env = payload["envelope"]
        assert env["author_pubkey"] == pubkey_str
        assert env["record_id"] == "alpha"

        # The record is now visible via /sync/manifest.
        manifest = _http_get(f"http://127.0.0.1:{port}/sync/manifest")
        assert "alpha" in manifest["records"]
        assert manifest["records"]["alpha"]["author_pubkey"] == pubkey_str

        # Re-POST the same content is idempotent (well, produces a new
        # envelope with a different wall_ts_ms — but the apply path
        # treats it as a chain extension since prev_hash is None and
        # the wall_ts is newer; that's actually a fork from the first
        # one because they share prev_hash=None and author. Let's
        # instead POST with the prior content_hash as prev_hash so
        # it's an explicit successor):
        body2 = json.dumps({
            "record_id": "alpha",
            "record_type": "person",
            "content": {"name": "Alpha", "geo": "SF"},
            "prev_hash": env["content_hash"],
        }).encode("utf-8")
        req2 = urllib.request.Request(
            f"http://127.0.0.1:{port}/sync/local_record",
            data=body2,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req2, timeout=5.0) as resp2:
            assert resp2.status == 201
            payload2 = json.loads(resp2.read().decode("utf-8"))
        assert payload2["was_new"] is True
        assert payload2["became_latest"] is True

        # Manifest reflects the new content_hash.
        manifest2 = _http_get(f"http://127.0.0.1:{port}/sync/manifest")
        assert (
            manifest2["records"]["alpha"]["latest_content_hash"]
            == payload2["envelope"]["content_hash"]
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def test_manifest_endpoint_returns_empty_for_fresh_node(tmp_path, monkeypatch):
    """Smoke test the /sync/manifest endpoint on a node with no records."""
    knowledge = tmp_path / "k"
    config = tmp_path / "c"
    knowledge.mkdir()
    config.mkdir()
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(knowledge))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(config))

    from swf.web.knowledge import knowledge_root
    peer_server._DB_PATH = knowledge_root() / "index.db"

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    try:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                _http_get(f"http://127.0.0.1:{port}/health", timeout=0.5)
                break
            except Exception:
                time.sleep(0.05)
        body = _http_get(f"http://127.0.0.1:{port}/sync/manifest")
        assert body["records"] == {}
        assert body["manifest_hash"].startswith("sha256:")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)
