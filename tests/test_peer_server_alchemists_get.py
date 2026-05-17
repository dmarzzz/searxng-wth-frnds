"""HTTP integration tests for #108 ask 2: `GET /alchemists`.

Covers:
  - 200 happy path: returns the active roster, sorted by id, with
    `loaded_from` (absolute path) and ISO-8601 `loaded_at`.
  - 0.0.0.0 bind path-leak guard: `loaded_from` is null on a
    non-loopback bind so a LAN peer can't infer the operator's home dir.
  - No-auth posture: the route is public (alchemist pubkey list is the
    trust set; consumers verifying signatures need it).
  - Hot-reload integration (#109): editing the YAML behind the daemon
    (without restart) is reflected in subsequent `GET /alchemists`
    responses, and `loaded_at` advances.

Hits the routes through a real `serve_in_thread` server so we exercise
the full HTTP path (URL parsing, response framing, status codes), not
just the handler in isolation. Indrex DB is redirected at the per-test
tmp dir via `SWF_KNOWLEDGE_DIR` and `.alchemists.yml` is staged via
`SWF_ALCHEMISTS_FILE`.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request

import pytest

# ── HTTP test scaffolding ──────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str):
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def _write_alchemists_yml(path, *entries: tuple[str, str]) -> None:
    """Write `.alchemists.yml` listing (id, pubkey) pairs."""
    lines = ["schema_version: 1", "alchemists:"]
    for ident, pk in entries:
        lines.append(f"  - id: {ident}")
        lines.append(f'    pubkey: "{pk}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def loopback_server(tmp_path, monkeypatch):
    """Spin up a peer_server bound on 127.0.0.1, with a known
    `.alchemists.yml`. Yields (base_url, peer_server_module,
    alchemists_path)."""
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))

    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(
        alchemists_path,
        ("alchemist-01", "ed25519:" + "a" * 64),
        ("alchemist-02", "ed25519:" + "b" * 64),
    )
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    for mod in ["swf.peer_server", "swf.indrex"]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, peer_server, alchemists_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture
def lan_bind_server(tmp_path, monkeypatch):
    """Spin up a peer_server bound on 0.0.0.0 (LAN-reachable).
    Pinned to a specific bind IP so we can assert the path-leak
    guard kicks in (`loaded_from` should be null).
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))

    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(
        alchemists_path,
        ("alchemist-01", "ed25519:" + "a" * 64),
    )
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    for mod in ["swf.peer_server", "swf.indrex"]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    port = _free_port()
    # Bind on 0.0.0.0 so the path-leak guard (`bind not 127.x`) trips.
    # Tests still hit it via 127.0.0.1 — wildcard bind accepts both.
    server, thread = peer_server.serve_in_thread(bind="0.0.0.0", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, peer_server, alchemists_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


# ── tests ──────────────────────────────────────────────────────────────


def test_get_alchemists_happy_path(loopback_server):
    """200 with the active roster (sorted by id), absolute
    `loaded_from`, and an ISO-8601 `loaded_at`."""
    base, _peer_server, alchemists_path = loopback_server

    status, body = _get(base + "/alchemists")
    assert status == 200
    assert isinstance(body, dict)

    # alchemists[]: sorted by id; both entries present.
    assert body["alchemists"] == [
        {"id": "alchemist-01", "pubkey": "ed25519:" + "a" * 64},
        {"id": "alchemist-02", "pubkey": "ed25519:" + "b" * 64},
    ]
    # On a loopback bind, `loaded_from` echoes the absolute path.
    assert body["loaded_from"] == str(alchemists_path)
    # ISO-8601 UTC, `Z` suffix, second precision.
    assert isinstance(body["loaded_at"], str)
    assert re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
        body["loaded_at"],
    ), body["loaded_at"]


def test_get_alchemists_no_auth_required(loopback_server):
    """The route is public — no Authorization header, no 401/403."""
    base, _peer_server, _alch_path = loopback_server
    status, _body = _get(base + "/alchemists")
    assert status == 200


def test_get_alchemists_omits_path_on_lan_bind(lan_bind_server):
    """Privacy: `loaded_from` is filesystem-local information. On a
    non-loopback bind we omit it (null) so a LAN peer can't infer
    the operator's home dir layout. Pubkeys are part of the trust
    set and are intentionally public, so the `alchemists[]` list
    still appears."""
    base, _peer_server, _alch_path = lan_bind_server
    status, body = _get(base + "/alchemists")
    assert status == 200
    # Roster still visible (it's the trust set; consumers need it).
    assert body["alchemists"] == [
        {"id": "alchemist-01", "pubkey": "ed25519:" + "a" * 64},
    ]
    # But the path is suppressed.
    assert body["loaded_from"] is None
    # `loaded_at` is still present.
    assert isinstance(body["loaded_at"], str)


def test_get_alchemists_reflects_hot_reload(loopback_server):
    """#109 integration: editing `.alchemists.yml` while the daemon
    is running is reflected by the next `GET /alchemists` response.
    Confirms the route reads from the shared cache (which hot-reloads
    on mtime advance) rather than a stale in-handler snapshot."""
    base, _peer_server, alchemists_path = loopback_server

    s1, body1 = _get(base + "/alchemists")
    assert s1 == 200
    assert len(body1["alchemists"]) == 2
    first_loaded_at = body1["loaded_at"]

    # Add a third alchemist + bump mtime past the cached value.
    alchemists_path.write_text(
        "schema_version: 1\n"
        "alchemists:\n"
        f'  - id: alchemist-01\n    pubkey: "ed25519:{"a" * 64}"\n'
        f'  - id: alchemist-02\n    pubkey: "ed25519:{"b" * 64}"\n'
        f'  - id: alchemist-03\n    pubkey: "ed25519:{"c" * 64}"\n',
        encoding="utf-8",
    )
    st = alchemists_path.stat()
    os.utime(alchemists_path, (st.st_mtime + 5.0, st.st_mtime + 5.0))

    # Second-precision sleep so `loaded_at` (which has second
    # resolution) sees a different timestamp than the first call.
    # Without this the assertion that the timestamps differ would
    # be flaky on fast machines. Use os.utime side-channel instead
    # by waiting in real time — keep the wait minimal (~1.1s).
    import time
    time.sleep(1.1)

    s2, body2 = _get(base + "/alchemists")
    assert s2 == 200
    assert len(body2["alchemists"]) == 3
    # New entry visible.
    assert {"id": "alchemist-03", "pubkey": "ed25519:" + "c" * 64} in body2[
        "alchemists"
    ]
    # `loaded_at` advanced (the cache re-parsed, stamping a fresh ts).
    assert body2["loaded_at"] != first_loaded_at


def test_get_alchemists_missing_file_returns_empty_roster(
    tmp_path, monkeypatch,
):
    """If `.alchemists.yml` is missing at startup, `GET /alchemists`
    still returns 200 with an empty list — rather than crashing or
    404'ing — so the operator can detect the misconfiguration via the
    same endpoint they'd hit for a healthy node."""
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    # Point at a non-existent file.
    ghost = tmp_path / "nonexistent.yml"
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(ghost))
    monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)

    for mod in ["swf.peer_server", "swf.indrex"]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        status, body = _get(base + "/alchemists")
        assert status == 200
        assert body["alchemists"] == []
        # No file -> no path; even on loopback we report null.
        assert body["loaded_from"] is None
        # `loaded_at` is still stamped (the loader ran, just found no file).
        assert isinstance(body["loaded_at"], str)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
