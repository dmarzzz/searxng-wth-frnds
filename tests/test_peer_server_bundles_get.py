"""HTTP integration tests for #93 phase 2: bundle read API.

Covers:

  - GET /bundles                     → happy path, kind/record_id filters
  - GET /bundles?kind=garbage        → 400 invalid_kind with valid list
  - GET /bundles?record_id=&since=   → strict-greater pagination
  - GET /bundles (no record_id)      → ignores `since`, single page only
                                       (documented v1 quirk; see route docstring)
  - GET /bundles?limit=...           → cap enforcement
  - GET /bundles/by_cid/<valid>      → 200 with envelope
  - GET /bundles/by_cid/<unknown>    → 404 not_found
  - GET /bundles/by_cid/<malformed>  → 400 invalid_cid

Hits the routes through a real `serve_in_thread` server so we exercise
the full HTTP path (URL parsing, response framing, status codes), not
just the handler in isolation. Indrex DB is redirected at the per-test
tmp dir via `SWF_KNOWLEDGE_DIR`.
"""
from __future__ import annotations

import base64
import importlib
import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles

# ── local fixture helpers (mirror of tests/bundles/conftest.py) ─────────────
# Duplicated rather than imported because pytest's conftest.py only
# applies inside its own directory tree, and we want the bundle-test
# scaffolding alongside the existing top-level peer_server tests.


@dataclass
class _Keypair:
    priv: Ed25519PrivateKey
    pub_hex: str
    pubkey_str: str


def _make_keypair() -> _Keypair:
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _Keypair(priv=priv, pub_hex=pub_hex, pubkey_str=f"ed25519:{pub_hex}")


def _build_envelope(
    kp: _Keypair,
    *,
    kind: str = "cohort.surface",
    record_id: str = "alice",
    version: int = 0,
    signed_at: str = "2026-05-04T12:00:00Z",
    payload: bytes = b'{"hello":"world"}',
) -> dict:
    env: dict = {
        "magic": "swf-bundle-v1",
        "kind": kind,
        "record_id": record_id,
        "version": int(version),
        "author": {"pubkey": kp.pubkey_str, "signed_at": signed_at},
        "encryption": None,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    env["signature"] = bundles.sign_envelope(env, priv=kp.priv)
    return env


# ── HTTP test scaffolding ──────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(url: str):
    """GET `url`, return (status, parsed_json_body)."""
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, body


@pytest.fixture
def peer_server_running(tmp_path, monkeypatch):
    """Spin up a real peer_server on 127.0.0.1, redirected at a tmp
    indrex DB. Yields the base URL.

    We force a fresh import of `swf.peer_server` AFTER setting
    `SWF_KNOWLEDGE_DIR` because the module captures `_DB_PATH` at
    import time. Without the reload, every test would share the
    first-ever-imported DB path.
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    # Some helper modules also cache db paths — clear them.
    import sys
    for mod in [
        "swf.peer_server",
        "swf.indrex",
    ]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.fixture
def keypair():
    return _make_keypair()


@pytest.fixture
def seeded_bundles(peer_server_running, keypair):
    """Insert a small fixture set into the bundle store of the running
    server. Returns the list of inserted (cid, envelope) tuples.

    NOTE: must use the indrex DB the *running* server resolved, which
    is the one under `SWF_KNOWLEDGE_DIR` set in `peer_server_running`.
    `bundles.insert(envelope)` opens its own connection from
    `swf.indrex.db_path()`, which honors that env var.
    """
    seeded: list[tuple[str, dict]] = []
    for v in range(3):
        env = _build_envelope(keypair, record_id="alice", version=v)
        cid, _ = bundles.insert(env)
        seeded.append((cid, env))
    # One bundle of a different kind/record so we can test filtering.
    other = _build_envelope(
        keypair, kind="cohort.depth", record_id="bob-depth", version=0,
    )
    cid, _ = bundles.insert(other)
    seeded.append((cid, other))
    return seeded


# ── tests ──────────────────────────────────────────────────────────────────


def test_bundles_list_happy_path(peer_server_running, seeded_bundles):
    status, body = _get(peer_server_running + "/bundles")
    assert status == 200
    assert "bundles" in body
    assert "next_since" in body
    # Default limit is 100; we seeded 4. All four come back.
    assert len(body["bundles"]) == 4
    # Final page → next_since is null.
    assert body["next_since"] is None


def test_bundles_filter_by_kind(peer_server_running, seeded_bundles):
    status, body = _get(peer_server_running + "/bundles?kind=cohort.surface")
    assert status == 200
    assert all(b["kind"] == "cohort.surface" for b in body["bundles"])
    assert len(body["bundles"]) == 3  # only the alice/v0..v2 set


def test_bundles_filter_by_record_id(peer_server_running, seeded_bundles):
    status, body = _get(
        peer_server_running + "/bundles?kind=cohort.surface&record_id=alice"
    )
    assert status == 200
    versions = [b["version"] for b in body["bundles"]]
    # Spec §4.1: ascending version order per record_id.
    assert versions == [0, 1, 2]


def test_bundles_pagination_with_record_id(
    peer_server_running, seeded_bundles
):
    """Spec contract: when `record_id` is given, `since` paginates the
    single-record version stream. Strict-greater semantics — pass
    `since=N` to skip versions <= N."""
    # First page, limit=2 → versions [0, 1], next_since=1
    status, body = _get(
        peer_server_running
        + "/bundles?kind=cohort.surface&record_id=alice&limit=2"
    )
    assert status == 200
    assert [b["version"] for b in body["bundles"]] == [0, 1]
    assert body["next_since"] == 1

    # Resume with since=1 → versions [2], final page (next_since=None)
    status, body = _get(
        peer_server_running
        + "/bundles?kind=cohort.surface&record_id=alice&since=1&limit=2"
    )
    assert status == 200
    assert [b["version"] for b in body["bundles"]] == [2]
    assert body["next_since"] is None


def test_bundles_pagination_only_with_record_id(
    peer_server_running, seeded_bundles
):
    """Documented v1 quirk: `since` is meaningful only when paired
    with `record_id`. Without `record_id`, `since` is ignored and the
    response is the first page (newest-first by signed_at)."""
    # `since=999` would filter everything out if honored cross-record;
    # but without `record_id`, the route ignores `since` entirely.
    status, body = _get(peer_server_running + "/bundles?since=999")
    assert status == 200
    assert len(body["bundles"]) == 4
    # And next_since stays None because cross-record pagination is
    # not supported in v1.
    assert body["next_since"] is None


def test_bundles_invalid_kind_returns_400(peer_server_running):
    status, body = _get(peer_server_running + "/bundles?kind=garbage")
    assert status == 400
    assert body["error"] == "invalid_kind"
    assert "valid" in body
    assert "cohort.surface" in body["valid"]


def test_bundles_invalid_since_returns_400(peer_server_running):
    status, body = _get(
        peer_server_running + "/bundles?record_id=alice&since=notanumber"
    )
    assert status == 400
    assert body["error"] == "invalid_since"


def test_bundles_invalid_limit_returns_400(peer_server_running):
    status, body = _get(peer_server_running + "/bundles?limit=notanumber")
    assert status == 400
    assert body["error"] == "invalid_limit"


def test_bundles_limit_too_large_returns_400(peer_server_running):
    status, body = _get(peer_server_running + "/bundles?limit=99999")
    assert status == 400
    assert body["error"] == "limit_too_large"
    assert body["max"] == 1000


def test_bundles_empty_store_returns_empty_page(peer_server_running):
    """Even on a fresh node with no bundles ever written, the route
    must succeed (ensure_schema runs defensively)."""
    status, body = _get(peer_server_running + "/bundles")
    assert status == 200
    assert body == {"bundles": [], "next_since": None}


def test_by_cid_happy_path(peer_server_running, seeded_bundles):
    cid, envelope = seeded_bundles[0]
    status, body = _get(peer_server_running + f"/bundles/by_cid/{cid}")
    assert status == 200
    # The body IS the envelope (not wrapped).
    assert body["magic"] == "swf-bundle-v1"
    assert body["kind"] == envelope["kind"]
    assert body["record_id"] == envelope["record_id"]
    assert body["signature"] == envelope["signature"]


def test_by_cid_unknown_returns_404(peer_server_running, seeded_bundles):
    # Well-formed but never-seen CID.
    status, body = _get(peer_server_running + "/bundles/by_cid/" + "f" * 64)
    assert status == 404
    assert body["error"] == "not_found"
    assert body["cid"] == "f" * 64


def test_by_cid_malformed_returns_400(peer_server_running):
    status, body = _get(peer_server_running + "/bundles/by_cid/abc")
    assert status == 400
    assert body["error"] == "invalid_cid"


def test_by_cid_uppercase_hex_is_malformed(peer_server_running):
    """CIDs are sha256 lowercase hex per spec; uppercase is rejected
    so the address space stays single-canonical (no dual-spelling
    cache poisoning)."""
    status, body = _get(peer_server_running + "/bundles/by_cid/" + "F" * 64)
    assert status == 400
    assert body["error"] == "invalid_cid"


# ── #93 phase 6 follow-up: GET /bundles?received_since= ─────────────────────
# The pull-side replication puller paginates across all records by
# rowid, in insertion order. These tests exercise the new query
# parameter end-to-end through the same `serve_in_thread` server the
# rest of this file uses, so the cursor semantics are pinned at the
# wire level.


def test_received_since_zero_returns_everything_in_rowid_asc(
    peer_server_running, seeded_bundles,
):
    """`received_since=0` returns every bundle in the store, ordered
    by rowid ASC (insertion order). The seeded fixture inserts:
        rowid 1: cohort.surface alice v0
        rowid 2: cohort.surface alice v1
        rowid 3: cohort.surface alice v2
        rowid 4: cohort.depth bob-depth v0
    so the response order is fixed by insertion."""
    status, body = _get(peer_server_running + "/bundles?received_since=0")
    assert status == 200
    assert "bundles" in body
    assert "next_received_since" in body
    assert len(body["bundles"]) == 4
    # Insertion order: alice v0, v1, v2, then bob-depth v0.
    assert [b["record_id"] for b in body["bundles"]] == [
        "alice", "alice", "alice", "bob-depth",
    ]
    assert [b["version"] for b in body["bundles"]] == [0, 1, 2, 0]


def test_received_since_skips_consumed_rowids(
    peer_server_running, seeded_bundles,
):
    """`received_since=N` returns bundles with rowid > N. Strict-
    greater so a caller can use the response's `next_received_since`
    as the next request's `received_since` without dedup."""
    # Skip past the first 2 (rowids 1 and 2).
    status, body = _get(peer_server_running + "/bundles?received_since=2")
    assert status == 200
    # Rowid 3 (alice v2) and rowid 4 (bob-depth v0) remain.
    assert [b["record_id"] for b in body["bundles"]] == ["alice", "bob-depth"]
    assert [b["version"] for b in body["bundles"]] == [2, 0]


def test_next_received_since_is_max_rowid_in_page(
    peer_server_running, seeded_bundles,
):
    """When the page is non-empty, `next_received_since` is the
    largest rowid in this page — the next request should pass it as
    `received_since` to skip past these bundles."""
    # First page of 2 → bundles at rowid 1, 2; cursor is 2.
    status, body = _get(
        peer_server_running + "/bundles?received_since=0&limit=2"
    )
    assert status == 200
    assert len(body["bundles"]) == 2
    assert body["next_received_since"] == 2

    # Resume with that cursor → rowids 3, 4; cursor is 4.
    status, body = _get(
        peer_server_running + "/bundles?received_since=2&limit=2"
    )
    assert status == 200
    assert len(body["bundles"]) == 2
    assert body["next_received_since"] == 4


def test_next_received_since_is_null_on_empty_page(
    peer_server_running, seeded_bundles,
):
    """When no bundles match `received_since=<huge>`, the response
    is an empty list and `next_received_since` is null — the puller
    uses this to stop looping on this peer this tick."""
    status, body = _get(
        peer_server_running + "/bundles?received_since=99999"
    )
    assert status == 200
    assert body["bundles"] == []
    assert body["next_received_since"] is None


def test_received_since_combined_with_record_id_returns_400(
    peer_server_running,
):
    """The two cursor modes are mutually exclusive; combining them
    surfaces as 400 so a client bug doesn't silently mis-paginate."""
    status, body = _get(
        peer_server_running
        + "/bundles?received_since=0&record_id=alice"
    )
    assert status == 400
    assert body["error"] == "received_since_mutually_exclusive"


def test_received_since_combined_with_since_returns_400(peer_server_running):
    """`received_since` + `since` is also rejected — same rationale."""
    status, body = _get(
        peer_server_running + "/bundles?received_since=0&since=1"
    )
    assert status == 400
    assert body["error"] == "received_since_mutually_exclusive"


def test_received_since_invalid_value_returns_400(peer_server_running):
    """Non-integer `received_since` is a 400, like the legacy
    `since`/`limit` validators."""
    status, body = _get(
        peer_server_running + "/bundles?received_since=notanumber"
    )
    assert status == 400
    assert body["error"] == "invalid_received_since"

    # Negative is also rejected (rowids are >= 1, so a negative
    # cursor has no meaning).
    status, body = _get(peer_server_running + "/bundles?received_since=-5")
    assert status == 400
    assert body["error"] == "invalid_received_since"


def test_received_since_filters_by_kind(peer_server_running, seeded_bundles):
    """`received_since` composes with `kind` (the only filter still
    permitted in rowid mode) — useful when a caller only wants one
    bundle stream."""
    status, body = _get(
        peer_server_running
        + "/bundles?received_since=0&kind=cohort.depth"
    )
    assert status == 200
    assert len(body["bundles"]) == 1
    assert body["bundles"][0]["kind"] == "cohort.depth"
    assert body["bundles"][0]["record_id"] == "bob-depth"
