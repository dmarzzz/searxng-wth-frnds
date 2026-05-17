"""HTTP integration tests for #93 phase 3: bundle write API.

Covers the verifier-pipeline status mapping (§4.2 of SHAPE-ROTATOR-OS-SPEC.md):

  - 201 Created   on a fresh, well-signed envelope from a listed alchemist
  - 201 Created   on idempotent re-POST (same cid; no duplicate row)
  - 400           on malformed JSON, shape failures, unknown kind,
                  malformed pubkey, malformed encryption block
  - 403           on unlisted alchemist (`author_not_alchemist`)
  - 403           on tampered signature (`signature_invalid`)
  - 409           on stale version (`version_not_monotonic`)
  - 413           on body > 4 MiB
  - 415           on non-JSON Content-Type

Plus carve-outs:

  - `kind=search.result` bypasses the alchemist whitelist (per
    `swf.bundles.verify`'s carve-out, mirroring spec §4.1).
  - POST-then-GET-by-cid round-trip preserves the envelope.

Hits the routes through a real `serve_in_thread` server so we exercise
the full HTTP path (URL parsing, response framing, status codes), not
just the handler in isolation. Indrex DB is redirected at the per-test
tmp dir via `SWF_KNOWLEDGE_DIR` and `.alchemists.yml` is staged via
`SWF_ALCHEMISTS_FILE`.
"""
from __future__ import annotations

import base64
import importlib
import json
import socket
import sqlite3
import urllib.error
import urllib.request
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles

# ── keypair + envelope helpers (mirror of tests/test_peer_server_bundles_get.py) ──


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
    encryption: dict | None = None,
    pubkey_str: str | None = None,
) -> dict:
    env: dict = {
        "magic": "swf-bundle-v1",
        "kind": kind,
        "record_id": record_id,
        "version": int(version),
        "author": {
            "pubkey": pubkey_str or kp.pubkey_str,
            "signed_at": signed_at,
        },
        "encryption": encryption,
        "payload": base64.b64encode(payload).decode("ascii"),
    }
    env["signature"] = bundles.sign_envelope(env, priv=kp.priv)
    return env


# ── HTTP test scaffolding ──────────────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url: str, body: bytes | str, *, content_type: str = "application/json"):
    """POST `body` to `url`, return (status, parsed_json_body | str)."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": content_type},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


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


def _write_alchemists_yml(path, *pubkey_strings: str) -> None:
    """Write a `.alchemists.yml` listing the given canonical pubkeys."""
    lines = ["schema_version: 1", "alchemists:"]
    for i, pk in enumerate(pubkey_strings):
        lines.append(f"  - id: alc-{i}")
        lines.append(f'    pubkey: "{pk}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def keypair():
    return _make_keypair()


@pytest.fixture
def other_keypair():
    """A second keypair NOT listed in the alchemist YAML — used for
    the unlisted-alchemist test."""
    return _make_keypair()


@pytest.fixture
def peer_server_running(tmp_path, monkeypatch, keypair):
    """Spin up a real peer_server on 127.0.0.1, redirected at a tmp
    indrex DB AND a tmp `.alchemists.yml` containing `keypair`'s pubkey.

    Yields the base URL. Tests that need to override the alchemist
    list (e.g. unlisted-author cases) write their own YAML and call
    `peer_server._reset_alchemists_cache_for_tests()`.
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))

    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(alchemists_path, keypair.pubkey_str)
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    # Reload the module so module-level `_DB_PATH` honors SWF_KNOWLEDGE_DIR.
    import sys
    for mod in ["swf.peer_server", "swf.indrex"]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")

    # Each test gets a fresh alchemist load against THIS test's YAML.
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


# ── tests ──────────────────────────────────────────────────────────────────


def test_post_happy_path(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair)
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 201
    assert "cid" in body
    cid = body["cid"]
    # The bundle is durably in the store.
    stored = bundles.get_by_cid(_open_test_conn(), cid)
    assert stored is not None
    assert stored["signature"] == env["signature"]
    assert stored["record_id"] == "alice"


def test_post_then_get_by_cid_round_trip(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, record_id="round-trip")
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 201
    cid = body["cid"]

    status_g, env_g = _get(base + f"/bundles/by_cid/{cid}")
    assert status_g == 200
    assert env_g["magic"] == "swf-bundle-v1"
    assert env_g["record_id"] == "round-trip"
    assert env_g["signature"] == env["signature"]
    # Envelope equality (canonical form): every field round-trips.
    assert env_g == env


def test_post_idempotent_returns_same_cid_no_duplicate(
    peer_server_running, keypair,
):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, record_id="idem", version=0)

    s1, b1 = _post(base + "/bundles", json.dumps(env))
    s2, b2 = _post(base + "/bundles", json.dumps(env))
    assert s1 == 201 and s2 == 201
    assert b1["cid"] == b2["cid"]

    # Confirm exactly one row in the bundles table for this record_id.
    conn = _open_test_conn()
    n = conn.execute(
        "SELECT COUNT(*) FROM bundles WHERE record_id=?", ("idem",),
    ).fetchone()[0]
    conn.close()
    assert n == 1


def test_post_malformed_json_returns_400(peer_server_running):
    base, _peer_server, _alch_path = peer_server_running
    status, body = _post(base + "/bundles", b"not json")
    assert status == 400
    assert body["error"] == "malformed_json"
    # #108 ask 3: pre-verifier rejects carry stage="json" so clients
    # can distinguish "you sent garbage" from "your envelope was
    # malformed at the swf-bundle-v1 layer".
    assert body["stage"] == "json"


def test_post_non_object_json_returns_400(peer_server_running):
    """A bare list / string / number is well-formed JSON but the
    envelope MUST be a JSON object. We tag this `malformed_json`
    rather than `shape_invalid` because the verifier never sees it
    (we short-circuit before the verifier to keep the verifier's
    invariants — `envelope: dict` — strict)."""
    base, _peer_server, _alch_path = peer_server_running
    status, body = _post(base + "/bundles", b'["not", "an", "envelope"]')
    assert status == 400
    assert body["error"] == "malformed_json"
    assert body["stage"] == "json"


@pytest.mark.parametrize("breakage", [
    "missing_magic",
    "wrong_magic",
    "missing_signature",
    "missing_record_id",
    "missing_version",
    "negative_version",
])
def test_post_shape_failures_return_400(
    peer_server_running, keypair, breakage,
):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, record_id=f"shape-{breakage}")
    if breakage == "missing_magic":
        del env["magic"]
    elif breakage == "wrong_magic":
        env["magic"] = "swf-bundle-v0"
    elif breakage == "missing_signature":
        del env["signature"]
    elif breakage == "missing_record_id":
        del env["record_id"]
    elif breakage == "missing_version":
        del env["version"]
    elif breakage == "negative_version":
        env["version"] = -1
        # Re-sign so the signature doesn't dominate the rejection
        # reason; we want to confirm shape catches this first.
        env["signature"] = bundles.sign_envelope(env, priv=keypair.priv)

    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 400
    assert body["error"] == "shape_invalid"
    # #108 ask 3: shape-stage rejections carry stage="shape".
    assert body["stage"] == "shape"


def test_post_unknown_kind_returns_400(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair)
    env["kind"] = "nope.what"
    # Re-sign so the rejection is `kind_unknown` (shape stage), not a
    # signature mismatch.
    env["signature"] = bundles.sign_envelope(env, priv=keypair.priv)
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 400
    assert body["error"] == "kind_unknown"
    assert body["stage"] == "shape"


def test_post_malformed_pubkey_returns_400(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair)
    env["author"]["pubkey"] = "rsa:not-an-ed25519-key"
    # No need to re-sign — shape stage rejects on regex.
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 400
    assert body["error"] == "pubkey_malformed"
    assert body["stage"] == "shape"


def test_post_malformed_encryption_returns_400(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, kind="cohort.depth")
    # `recipients` must be a non-empty list of strings.
    env["encryption"] = {"alg": "age-v1", "recipients": []}
    env["signature"] = bundles.sign_envelope(env, priv=keypair.priv)
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 400
    assert body["error"] == "encryption_malformed"
    assert body["stage"] == "shape"


def test_post_unlisted_alchemist_returns_403(
    peer_server_running, other_keypair,
):
    """`other_keypair` is NOT in the alchemist list → 403 with the
    `author_not_alchemist` tag from VerifyReason."""
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(other_keypair, record_id="unlisted")
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 403
    assert body["error"] == "author_not_alchemist"
    # Folded into the signature stage: the author's identity is the
    # signature-side gate (you signed an envelope with a pubkey
    # nobody trusts).
    assert body["stage"] == "signature"


def test_post_tampered_signature_returns_403(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, record_id="tampered")
    # Flip a hex digit in the signature so it's still well-shaped
    # (passes the shape regex) but cryptographically invalid.
    sig = env["signature"]
    flipped_first = "0" if sig[0] != "0" else "1"
    env["signature"] = flipped_first + sig[1:]
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 403
    assert body["error"] == "signature_invalid"
    assert body["stage"] == "signature"


def test_post_stale_version_returns_409(peer_server_running, keypair):
    """v=2 lands first; then v=1 (the same record_id) is rejected
    409 `version_not_monotonic`. v=0 would also be rejected for the
    same reason — the verifier requires strictly greater than the
    highest seen."""
    base, _peer_server, _alch_path = peer_server_running

    env_v2 = _build_envelope(keypair, record_id="stale", version=2)
    s1, b1 = _post(base + "/bundles", json.dumps(env_v2))
    assert s1 == 201, b1

    env_v1 = _build_envelope(keypair, record_id="stale", version=1)
    s2, b2 = _post(base + "/bundles", json.dumps(env_v1))
    assert s2 == 409
    assert b2["error"] == "version_not_monotonic"
    assert b2["stage"] == "version"


def test_post_oversized_body_returns_413(peer_server_running):
    """Reject Content-Length > 4 MiB before reading the body. We send
    a 5 MiB blob; the server should respond 413 with the cap echoed
    in `max_bytes` so clients can tune their producers."""
    base, _peer_server, _alch_path = peer_server_running
    big = b"x" * (5 * 1024 * 1024)
    status, body = _post(base + "/bundles", big)
    assert status == 413
    assert body["error"] == "payload_too_large"
    assert body["max_bytes"] == 4 * 1024 * 1024
    assert body["stage"] == "payload_too_large"


def test_post_wrong_content_type_returns_415(peer_server_running, keypair):
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair)
    status, body = _post(
        base + "/bundles",
        json.dumps(env),
        content_type="text/plain",
    )
    assert status == 415
    assert body["error"] == "unsupported_media_type"
    assert body["stage"] == "content_type"


def test_post_content_type_with_charset_param_accepted(
    peer_server_running, keypair,
):
    """`Content-Type: application/json; charset=utf-8` is the JSON
    default in many HTTP libraries — must be accepted."""
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(keypair, record_id="charset-ok")
    status, body = _post(
        base + "/bundles",
        json.dumps(env),
        content_type="application/json; charset=utf-8",
    )
    assert status == 201
    assert "cid" in body


def test_post_accepts_bundle_with_recipient_outside_reservoir(
    tmp_path, monkeypatch, keypair,
):
    """Per #112, the POST handler does NOT pre-screen recipients
    against the locally-staged reservoir. swf-node is a relay over
    opaque ciphertext, so a recipient pubkey that's not in
    `.reservoir.yml` is accepted at 201 — the alchemist signature is
    the trust boundary, and a wrong recipient just produces ciphertext
    nobody can decrypt (identical in effect to honest delivery of an
    unknown recipient).

    This test pins the new contract: even with a reservoir loaded that
    explicitly does NOT contain the bundle's recipient, the POST
    succeeds. Pre-#112, the same POST returned 403
    (`encryption_recipient_not_in_reservoir`).

    Spun up here as a standalone fixture rather than reusing
    `peer_server_running` because that fixture does not stage a
    reservoir, and we want to exercise the "reservoir is loaded but
    its contents are irrelevant to the POST gate" case explicitly.
    """
    import sys

    import pyrage

    # 1. Stage SWF_KNOWLEDGE_DIR + alchemists.yml (mirrors the
    #    `peer_server_running` fixture's preamble).
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(alchemists_path, keypair.pubkey_str)
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    # 2. Stage a 2-key reservoir whose pubkey set does NOT contain the
    #    bogus recipient we'll POST below. Real X25519 pubkeys (so
    #    they pass the `age1...` shape check at envelope-validate time);
    #    the bogus one is also an `age1...` string but isn't in this
    #    reservoir. Pre-#112 this would have triggered the 403; now
    #    the reservoir is irrelevant to the POST verifier.
    idents = [pyrage.x25519.Identity.generate() for _ in range(2)]
    reservoir_pubkeys = [str(i.to_public()) for i in idents]
    bogus_ident = pyrage.x25519.Identity.generate()
    bogus_pubkey = str(bogus_ident.to_public())
    assert bogus_pubkey not in reservoir_pubkeys

    reservoir_path = tmp_path / ".reservoir.yml"
    lines = [
        "schema_version: 1",
        'generated_at: "2026-05-09T00:00:00Z"',
        "keys:",
    ]
    for i, pk in enumerate(reservoir_pubkeys):
        lines.append(f"  - id: alc-{i:03d}")
        lines.append(f'    pubkey: "{pk}"')
        lines.append("    distributed_to: null")
    reservoir_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("SWF_RESERVOIR_FILE", str(reservoir_path))

    # 3. Reload the modules so the per-test SWF_KNOWLEDGE_DIR is honored
    #    and reset all the bundle caches so they re-read THIS test's
    #    fixture files.
    for mod in ["swf.peer_server", "swf.indrex"]:
        sys.modules.pop(mod, None)
    import importlib as _importlib
    peer_server = _importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()
    bundles.reset_reservoir_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(bind="127.0.0.1", port=port)
    base = f"http://127.0.0.1:{port}"
    try:
        # Build a `cohort.depth` envelope (the kind that legitimately
        # carries an encryption block) with a SINGLE recipient that
        # isn't in the reservoir. Encryption block is otherwise
        # well-formed (`alg: age-v1`, recipients list non-empty) so
        # the shape stage of the verifier passes. Per #112, the POST
        # handler no longer asks the verifier to cross-check
        # recipients against the reservoir — so the bundle is accepted.
        env = _build_envelope(
            keypair,
            kind="cohort.depth",
            record_id="bogus-recipient",
            encryption={"alg": "age-v1", "recipients": [bogus_pubkey]},
        )
        status, body = _post(base + "/bundles", json.dumps(env))
        assert status == 201, body
        assert "cid" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        bundles.reset_reservoir_cache_for_tests()


def test_post_search_result_bypasses_alchemist(
    peer_server_running, other_keypair,
):
    """`kind=search.result` is a verifier carve-out (see
    `swf.bundles.verify`): those bundles are signed by peer pubkeys,
    not alchemist keys, and the alchemist whitelist check is skipped.
    Confirm that an envelope signed by a NON-alchemist key with
    `kind=search.result` lands at 201."""
    base, _peer_server, _alch_path = peer_server_running
    env = _build_envelope(
        other_keypair,
        kind="search.result",
        record_id="search-bypass",
    )
    status, body = _post(base + "/bundles", json.dumps(env))
    assert status == 201, body
    assert "cid" in body


# ── helpers ────────────────────────────────────────────────────────────────


def _open_test_conn() -> sqlite3.Connection:
    """Open a connection to the per-test indrex DB. Honors the
    `SWF_KNOWLEDGE_DIR` env var set by the `peer_server_running`
    fixture, so we read the same DB the running server is writing to.
    """
    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn
