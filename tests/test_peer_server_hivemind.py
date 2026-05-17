"""HTTP integration tests for #93 phase 5: hivemind sink.

Spec §4.3:
    POST /hivemind/transcripts

Voxterm posts an UNSIGNED transcript-batch payload; the convent box's
swf-node validates schema, wraps in a `kind: transcript.batch`
envelope, signs with the convent's alchemist Ed25519 key, runs the
phase-1 verifier, and persists via `bundles.insert`. Response is
`201 Created` with `{"cid": "..."}`.

Mirrors `tests/test_peer_server_bundles_post.py` for scaffolding —
real `serve_in_thread` server, tmp indrex DB redirected via
`SWF_KNOWLEDGE_DIR`, tmp `.alchemists.yml`, tmp signing-key seed file.
"""
from __future__ import annotations

import base64
import http.client
import importlib
import json
import socket
import sqlite3
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles

# ── keypair + payload helpers ──────────────────────────────────────────


@dataclass
class _Keypair:
    priv: Ed25519PrivateKey
    pub_hex: str
    pubkey_str: str
    seed: bytes


def _make_keypair() -> _Keypair:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw.hex()
    return _Keypair(
        priv=priv, pub_hex=pub_hex,
        pubkey_str=f"ed25519:{pub_hex}", seed=seed,
    )


def _make_payload(
    *,
    record_id: str = "transcript-2026-05-07-1430-room-a",
    batch_index: int | str = 0,
    started_at: str = "2026-05-07T14:30:00Z",
    ended_at: str = "2026-05-07T14:31:08Z",
    location: str | None = "convent-room-a",
    origin_device: str | None = "voxterm-uuid-abc",
    segments: list | None = None,
) -> dict:
    out: dict = {
        "record_id": record_id,
        "batch_index": batch_index,
        "started_at": started_at,
        "ended_at": ended_at,
        "segments": segments if segments is not None else [
            {"t": 0.0, "speaker": "Tina", "text": "hello"},
            {"t": 4.7, "speaker": "Andrew", "text": "world"},
        ],
    }
    if location is not None:
        out["location"] = location
    if origin_device is not None:
        out["origin_device"] = origin_device
    return out


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _post(url: str, body: bytes | str, *,
          content_type: str = "application/json"):
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


def _write_alchemists_yml(path, *pubkey_strings: str) -> None:
    lines = ["schema_version: 1", "alchemists:"]
    for i, pk in enumerate(pubkey_strings):
        lines.append(f"  - id: alc-{i}")
        lines.append(f'    pubkey: "{pk}"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── fixture: peer server with sink configured ─────────────────────────


@pytest.fixture
def keypair():
    return _make_keypair()


@pytest.fixture
def peer_server_with_sink(tmp_path, monkeypatch, keypair):
    """Spin up a peer_server with the convent signing key + alchemist
    YAML pre-staged. Yields `(base_url, peer_server_module, keypair)`.

    The sink HTTP route is registered unconditionally — we don't need
    `--hivemind-sink` to test the POST handler — but we DO need the
    signing key + alchemist YAML so the sink can build a valid
    SinkConfig on first POST.
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))

    seed_path = tmp_path / "convent.seed"
    seed_path.write_bytes(keypair.seed)
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(seed_path))

    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(alchemists_path, keypair.pubkey_str)
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    # Reload to pick up env-driven module-level state.
    import sys
    for mod in [
        "swf.peer_server",
        "swf.indrex",
        "swf.event_bus",
        "swf.hivemind",
        "swf.hivemind.sink",
        "swf.hivemind.route",
        "swf.hivemind.mdns",
    ]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_signing_key_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=port,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, peer_server, keypair
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        _sink_mod.reset_signing_key_cache_for_tests()


def _open_test_conn() -> sqlite3.Connection:
    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


# ── tests ──────────────────────────────────────────────────────────────


def test_happy_path_returns_201_and_stores_signed_envelope(
    peer_server_with_sink,
):
    base, _peer_server, kp = peer_server_with_sink
    payload = _make_payload(record_id="record-http-A")
    status, body = _post(base + "/hivemind/transcripts", json.dumps(payload))
    assert status == 201, body
    assert "cid" in body

    # Bundle is in the store, signed with the convent key.
    conn = _open_test_conn()
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    assert env is not None
    assert env["kind"] == "transcript.batch"
    assert env["record_id"] == "record-http-A"
    assert env["author"]["pubkey"] == kp.pubkey_str
    assert bundles.verify_envelope_signature(env)


def test_payload_round_trips_through_inner_b64(peer_server_with_sink):
    """The voxterm payload survives the wrap unaltered (sink folds
    `record_type` and `schema_version` in but everything else passes
    through)."""
    base, _peer_server, _kp = peer_server_with_sink
    payload = _make_payload(record_id="rt-A", batch_index=3)
    status, body = _post(base + "/hivemind/transcripts", json.dumps(payload))
    assert status == 201

    conn = _open_test_conn()
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    inner = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    assert inner["batch_index"] == 3
    assert inner["record_type"] == "transcript"
    assert inner["schema_version"] == 1
    assert inner["segments"] == payload["segments"]
    assert env["version"] == 3


def test_missing_field_returns_400(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    payload = _make_payload()
    payload.pop("started_at")
    status, body = _post(base + "/hivemind/transcripts", json.dumps(payload))
    assert status == 400
    assert body["error"] == "invalid_payload"
    assert body["reason"] == "missing_started_at"


def test_bad_segment_returns_400(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    payload = _make_payload()
    payload["segments"] = [{"t": "not-a-float", "speaker": "X", "text": "Y"}]
    status, body = _post(base + "/hivemind/transcripts", json.dumps(payload))
    assert status == 400
    assert body["reason"] == "bad_segment"


def test_redacted_with_empty_segments_returns_201(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    payload = _make_payload(
        record_id="record-redact-http",
        batch_index="redacted",
        segments=[],
    )
    status, body = _post(base + "/hivemind/transcripts", json.dumps(payload))
    assert status == 201, body


def test_oversized_body_returns_413(peer_server_with_sink):
    """A 2 MiB blob exceeds the 1 MiB hivemind cap."""
    base, *_ = peer_server_with_sink
    big = b"x" * (2 * 1024 * 1024)
    status, body = _post(base + "/hivemind/transcripts", big)
    assert status == 413
    assert body["error"] == "payload_too_large"
    assert body["max_bytes"] == 1 * 1024 * 1024


def test_wrong_content_type_returns_415(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    status, body = _post(
        base + "/hivemind/transcripts",
        json.dumps(_make_payload()),
        content_type="text/plain",
    )
    assert status == 415
    assert body["error"] == "unsupported_media_type"


def test_malformed_json_returns_400(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    status, body = _post(base + "/hivemind/transcripts", b"not json")
    assert status == 400
    assert body["error"] == "malformed_json"


def test_non_object_json_returns_400(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    status, body = _post(base + "/hivemind/transcripts", b'["nope"]')
    assert status == 400
    assert body["error"] == "malformed_json"


@pytest.fixture
def peer_server_with_sink_and_reservoir(tmp_path, monkeypatch, keypair):
    """Like `peer_server_with_sink`, plus a staged `.reservoir.yml`
    holding three fresh X25519 keypairs. Returns the base URL, the
    server module, the convent keypair, the reservoir Identity list
    (so tests can decrypt the produced ciphertext), and the recipient
    pubkey strings."""
    import pyrage

    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    seed_path = tmp_path / "convent.seed"
    seed_path.write_bytes(keypair.seed)
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(seed_path))

    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(alchemists_path, keypair.pubkey_str)
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    # Stage a 3-key reservoir. Three is enough to prove "encrypted to
    # all" without slowing the suite with a full 20-key generation.
    idents = [pyrage.x25519.Identity.generate() for _ in range(3)]
    pubkeys = [str(i.to_public()) for i in idents]
    reservoir_path = tmp_path / ".reservoir.yml"
    lines = [
        "schema_version: 1",
        'generated_at: "2026-05-07T00:00:00Z"',
        "keys:",
    ]
    for i, pk in enumerate(pubkeys):
        lines.append(f"  - id: alc-{i:03d}")
        lines.append(f'    pubkey: "{pk}"')
        lines.append("    distributed_to: null")
    reservoir_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setenv("SWF_RESERVOIR_FILE", str(reservoir_path))

    import sys
    for mod in [
        "swf.peer_server",
        "swf.indrex",
        "swf.event_bus",
        "swf.hivemind",
        "swf.hivemind.sink",
        "swf.hivemind.route",
        "swf.hivemind.mdns",
    ]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_signing_key_cache_for_tests()
    _sink_mod.reset_reservoir_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=port,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, peer_server, keypair, idents, pubkeys
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        _sink_mod.reset_signing_key_cache_for_tests()
        _sink_mod.reset_reservoir_cache_for_tests()


def test_encrypt_query_param_with_reservoir_returns_201(
    peer_server_with_sink_and_reservoir,
):
    """Phase 7 happy path: the sink encrypts the inner voxterm
    payload to every reservoir pubkey. The stored envelope's
    `encryption.recipients` matches the reservoir, and the ciphertext
    decrypts back to the original inner JSON with any reservoir key."""
    import pyrage

    base, _peer, _kp, idents, pubkeys = peer_server_with_sink_and_reservoir

    payload = _make_payload(record_id="record-enc-A")
    status, body = _post(
        base + "/hivemind/transcripts?encrypt=true",
        json.dumps(payload),
    )
    assert status == 201, body
    cid = body["cid"]

    conn = _open_test_conn()
    try:
        env = bundles.get_by_cid(conn, cid)
    finally:
        conn.close()
    assert env is not None
    assert env["kind"] == "transcript.batch"

    # Encryption block matches the reservoir exactly.
    assert env["encryption"] == {
        "alg": "age-v1",
        "recipients": pubkeys,
    }

    # The envelope `payload` is base64(age-v1 ciphertext). It must
    # decrypt with any reservoir privkey back to the inner JSON.
    ct = base64.b64decode(env["payload"])
    assert ct.startswith(b"age-encryption.org/v")
    inner_bytes = pyrage.decrypt(ct, [idents[0]])
    inner = json.loads(inner_bytes.decode("utf-8"))
    assert inner["record_id"] == "record-enc-A"
    assert inner["batch_index"] == 0
    assert inner["segments"] == payload["segments"]

    # Same ciphertext decrypts with any other reservoir key — the
    # spec invariant that lets each alchemist hold a different key.
    inner_bytes_2 = pyrage.decrypt(ct, [idents[2]])
    assert inner_bytes_2 == inner_bytes


def test_encrypt_body_field_with_reservoir_returns_201(
    peer_server_with_sink_and_reservoir,
):
    """`{"encrypt": true}` in the body triggers the same path. The
    flag is stripped before signing — a decrypted inner payload must
    NOT carry an `encrypt` field."""
    import pyrage

    base, _peer, _kp, idents, _pubkeys = peer_server_with_sink_and_reservoir

    payload = _make_payload(record_id="record-enc-body")
    payload["encrypt"] = True
    status, body = _post(
        base + "/hivemind/transcripts",
        json.dumps(payload),
    )
    assert status == 201, body

    conn = _open_test_conn()
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    ct = base64.b64decode(env["payload"])
    inner_bytes = pyrage.decrypt(ct, [idents[1]])
    inner = json.loads(inner_bytes.decode("utf-8"))
    assert "encrypt" not in inner
    assert inner["record_id"] == "record-enc-body"


def test_encrypt_with_no_reservoir_returns_503(peer_server_with_sink):
    """Phase 7: with no `.reservoir.yml` staged, `?encrypt=true`
    returns 503 — the operator can stage the file and retry. Replaces
    the phase-5 stubbed 501."""
    base, *_ = peer_server_with_sink
    # The fixture doesn't stage a reservoir, so the loader's lookup
    # chain finds nothing and the sink reports the empty-reservoir
    # 503. Reset cache between this test's two scenarios.
    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_reservoir_cache_for_tests()

    payload = _make_payload(record_id="enc-no-res")
    status, body = _post(
        base + "/hivemind/transcripts?encrypt=true",
        json.dumps(payload),
    )
    assert status == 503
    assert body["error"] == "encryption_not_configured"
    assert body["reason"] == "reservoir_empty_or_missing"


def test_concurrent_batch_collision_returns_409(peer_server_with_sink):
    base, *_ = peer_server_with_sink
    rid = "record-collide-http"
    s0, _ = _post(
        base + "/hivemind/transcripts",
        json.dumps(_make_payload(record_id=rid, batch_index=2)),
    )
    assert s0 == 201
    s1, b1 = _post(
        base + "/hivemind/transcripts",
        json.dumps(_make_payload(
            record_id=rid, batch_index=2,
            started_at="2026-05-07T14:32:00Z",
            ended_at="2026-05-07T14:33:08Z",
        )),
    )
    assert s1 == 409
    assert b1["error"] == "version_not_monotonic"


# ── end-to-end: sink → SSE subscriber sees transcript.batch ────────────


def test_sink_post_propagates_to_sse_subscriber(peer_server_with_sink):
    """A voxterm POST → sink wraps + signs → bundle in store →
    `/bundles/subscribe` SSE subscriber sees the `transcript.batch` event.
    Closes the loop between phase 4 (SSE) and phase 5 (sink)."""
    base, _peer_server, _kp = peer_server_with_sink
    # Parse host/port from base URL.
    import urllib.parse as _up
    parts = _up.urlparse(base)
    host = parts.hostname
    port = parts.port

    conn = http.client.HTTPConnection(host, port, timeout=3.0)
    conn.request(
        "GET", "/bundles/subscribe?kind=transcript.batch", headers={},
    )
    resp = conn.getresponse()
    try:
        assert resp.status == 200

        # Now POST a transcript via the sink.
        payload = _make_payload(record_id="record-e2e")
        status, body = _post(
            base + "/hivemind/transcripts", json.dumps(payload),
        )
        assert status == 201
        cid_expected = body["cid"]

        # Drain SSE bytes until we have a full event block.
        deadline = time.monotonic() + 3.0
        buf = b""
        block: str | None = None
        while time.monotonic() < deadline and block is None:
            try:
                chunk = resp.read1(4096)
            except TimeoutError:
                chunk = b""
            if not chunk:
                time.sleep(0.02)
                continue
            buf += chunk
            while b"\n\n" in buf:
                head, _, rest = buf.partition(b"\n\n")
                buf = rest
                text = head.decode("utf-8", errors="replace") + "\n\n"
                non_comment = [
                    ln for ln in text.splitlines()
                    if ln.strip() and not ln.startswith(":")
                ]
                if non_comment:
                    block = text
                    break
        assert block is not None, "no SSE event arrived within 3s"

        evt: dict = {}
        for line in block.strip().splitlines():
            if ":" not in line:
                continue
            field, _, val = line.partition(":")
            if val.startswith(" "):
                val = val[1:]
            evt[field] = val
        assert evt["event"] == "bundle"
        assert evt["id"] == cid_expected
        envelope = json.loads(evt["data"])
        assert envelope["kind"] == "transcript.batch"
        assert envelope["record_id"] == "record-e2e"
    finally:
        conn.close()


# ── sink misconfiguration: no signing key ──────────────────────────────


def test_sink_misconfigured_returns_500(tmp_path, monkeypatch, keypair):
    """If `SWF_CONVENT_SIGNING_KEY` points at nothing, the route
    returns 500 + sink_misconfigured. The HTTP endpoint exists; it's
    just not in a state to sign.
    """
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    monkeypatch.setenv(
        "SWF_CONVENT_SIGNING_KEY", str(tmp_path / "absent.seed"),
    )
    alchemists_path = tmp_path / "alchemists.yml"
    _write_alchemists_yml(alchemists_path, keypair.pubkey_str)
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(alchemists_path))

    import sys
    for mod in [
        "swf.peer_server",
        "swf.indrex",
        "swf.event_bus",
        "swf.hivemind",
        "swf.hivemind.sink",
        "swf.hivemind.route",
    ]:
        sys.modules.pop(mod, None)
    peer_server = importlib.import_module("swf.peer_server")
    peer_server._reset_alchemists_cache_for_tests()

    from swf.hivemind import sink as _sink_mod
    _sink_mod.reset_signing_key_cache_for_tests()

    port = _free_port()
    server, thread = peer_server.serve_in_thread(
        bind="127.0.0.1", port=port,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        status, body = _post(
            base + "/hivemind/transcripts",
            json.dumps(_make_payload()),
        )
        assert status == 500
        assert body["error"] == "sink_misconfigured"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
