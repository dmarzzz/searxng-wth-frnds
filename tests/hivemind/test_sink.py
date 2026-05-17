"""Tests for the hivemind sink core (#93 phase 5).

Hits `swf.hivemind.sink` directly — no HTTP layer. Covers:
  - `validate_payload` rejects every documented schema breakage
  - happy path produces a valid envelope; cid is in the store
  - `batch_index="redacted"` works with empty segments and lands at
    a version strictly greater than every prior batch
  - `batch_index = N` produces an envelope with `version = N`
  - two batches for the same record_id chain via `prev_cid`
  - `encrypt=True` short-circuits with 501 (phase 5 stub)
"""
from __future__ import annotations

import base64
import json

import pytest

from swf import bundles
from swf.hivemind import sink as _sink

from .conftest import make_payload

# ── schema validation (no I/O) ──────────────────────────────────────────


@pytest.mark.parametrize(
    "mutator, expected_reason",
    [
        (lambda p: p.__setitem__("record_id", ""), "empty_record_id"),
        (lambda p: p.pop("record_id"), "missing_record_id"),
        (lambda p: p.__setitem__("record_id", 123), "missing_record_id"),
        (lambda p: p.__setitem__("batch_index", "nope"), "bad_batch_index"),
        (lambda p: p.__setitem__("batch_index", -1), "bad_batch_index"),
        (lambda p: p.__setitem__("batch_index", True), "bad_batch_index"),
        (lambda p: p.__setitem__("started_at", ""), "missing_started_at"),
        (lambda p: p.pop("started_at"), "missing_started_at"),
        (lambda p: p.__setitem__("ended_at", ""), "missing_ended_at"),
        (lambda p: p.__setitem__("location", 7), "bad_location"),
        (lambda p: p.__setitem__("origin_device", []), "bad_origin_device"),
        (lambda p: p.pop("segments"), "missing_segments"),
        (lambda p: p.__setitem__("segments", "not a list"), "missing_segments"),
        (lambda p: p.__setitem__(
            "segments", [{"t": "nope", "speaker": "A", "text": "B"}]
        ), "bad_segment"),
        (lambda p: p.__setitem__(
            "segments", [{"speaker": "A", "text": "B"}]
        ), "bad_segment"),
        (lambda p: p.__setitem__(
            "segments", [{"t": 0.0, "speaker": "A"}]
        ), "bad_segment"),
        (lambda p: p.__setitem__(
            "segments", [{"t": 0.0, "speaker": 1, "text": "B"}]
        ), "bad_segment"),
    ],
)
def test_validate_payload_rejects(mutator, expected_reason):
    p = make_payload()
    mutator(p)
    ok, reason = _sink.validate_payload(p)
    assert not ok
    assert reason == expected_reason


def test_validate_payload_top_level_must_be_object():
    ok, reason = _sink.validate_payload(["not", "a", "dict"])
    assert not ok
    assert reason == "not_object"


def test_validate_payload_happy():
    ok, reason = _sink.validate_payload(make_payload())
    assert ok
    assert reason == ""


def test_validate_payload_redacted_with_empty_segments_ok():
    p = make_payload(batch_index="redacted", segments=[])
    ok, reason = _sink.validate_payload(p)
    assert ok, reason


def test_validate_payload_optional_fields_can_be_omitted():
    p = make_payload(location=None, origin_device=None)
    p.pop("location", None)
    p.pop("origin_device", None)
    ok, reason = _sink.validate_payload(p)
    assert ok, reason


# ── happy-path persist ─────────────────────────────────────────────────


def test_persist_happy_returns_201_and_stores_envelope(sink_environment):
    payload = make_payload(record_id="record-A", batch_index=0)
    status, body = _sink.persist_transcript_batch(
        payload, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 201, body
    cid = body["cid"]

    # Bundle is in the store; round-trips via `get_by_cid`.
    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, cid)
    finally:
        conn.close()
    assert env is not None
    assert env["magic"] == bundles.BUNDLE_MAGIC
    assert env["kind"] == "transcript.batch"
    assert env["record_id"] == "record-A"
    assert env["version"] == 0
    assert env["author"]["pubkey"] == sink_environment.keypair.pubkey_str
    # Signature is hex of the right length and verifies.
    assert isinstance(env["signature"], str) and len(env["signature"]) == 128
    assert bundles.verify_envelope_signature(env)


def test_persist_inner_payload_round_trips(sink_environment):
    payload = make_payload(
        record_id="record-rt", batch_index=0,
        location="convent-room-z",
        origin_device="voxterm-rt-uuid",
    )
    status, body = _sink.persist_transcript_batch(
        payload, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 201

    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    assert env is not None

    inner = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
    assert inner["record_id"] == "record-rt"
    assert inner["record_type"] == "transcript"
    assert inner["schema_version"] == 1
    assert inner["batch_index"] == 0
    assert inner["location"] == "convent-room-z"
    assert inner["origin_device"] == "voxterm-rt-uuid"
    assert inner["segments"] == payload["segments"]


def test_persist_invalid_payload_returns_400(sink_environment):
    bad = make_payload()
    bad["record_id"] = ""
    status, body = _sink.persist_transcript_batch(
        bad, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 400
    assert body["error"] == "invalid_payload"
    assert body["reason"] == "empty_record_id"


# ── version + chaining semantics ────────────────────────────────────────


def test_version_equals_batch_index_for_int(sink_environment):
    payload = make_payload(record_id="record-v", batch_index=5)
    status, body = _sink.persist_transcript_batch(
        payload, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 201

    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    assert env["version"] == 5


def test_two_batches_chain_via_prev_cid(sink_environment):
    """Posting batch 0 then batch 1 for the same record_id: the second
    envelope's `prev_cid` MUST equal the cid of the first."""
    p0 = make_payload(record_id="record-chain", batch_index=0)
    s0, b0 = _sink.persist_transcript_batch(
        p0, sink_cfg=sink_environment.sink_cfg,
    )
    assert s0 == 201
    cid0 = b0["cid"]

    p1 = make_payload(
        record_id="record-chain", batch_index=1,
        started_at="2026-05-07T14:32:00Z",
        ended_at="2026-05-07T14:33:08Z",
        segments=[{"t": 0.0, "speaker": "Andrew", "text": "again"}],
    )
    s1, b1 = _sink.persist_transcript_batch(
        p1, sink_cfg=sink_environment.sink_cfg,
    )
    assert s1 == 201
    cid1 = b1["cid"]

    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env1 = bundles.get_by_cid(conn, cid1)
    finally:
        conn.close()
    assert env1["prev_cid"] == cid0


def test_first_batch_has_no_prev_cid(sink_environment):
    payload = make_payload(record_id="record-first", batch_index=0)
    status, body = _sink.persist_transcript_batch(
        payload, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 201
    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    # Either absent or explicitly None — both are spec-legal.
    assert env.get("prev_cid") is None


def test_redacted_lands_strictly_after_prior_batches(sink_environment):
    """Spec §3.5 retroactive seal. A `batch_index="redacted"` envelope
    must get a version strictly greater than every existing version
    for `(transcript.batch, record_id)`."""
    cfg = sink_environment.sink_cfg
    rid = "record-redact"

    s0, _ = _sink.persist_transcript_batch(
        make_payload(record_id=rid, batch_index=0), sink_cfg=cfg,
    )
    s1, _ = _sink.persist_transcript_batch(
        make_payload(
            record_id=rid, batch_index=2,
            started_at="2026-05-07T14:32:00Z",
            ended_at="2026-05-07T14:33:08Z",
        ),
        sink_cfg=cfg,
    )
    assert s0 == 201 and s1 == 201

    redact = make_payload(
        record_id=rid, batch_index="redacted", segments=[],
    )
    s2, b2 = _sink.persist_transcript_batch(redact, sink_cfg=cfg)
    assert s2 == 201

    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, b2["cid"])
    finally:
        conn.close()
    # The two prior bundles had versions 0 and 2; the redact must be 3.
    assert env["version"] == 3


def test_redacted_with_no_prior_starts_at_zero(sink_environment):
    """Edge case: operator redacts a record that was never recorded.
    Odd but legal — version starts at 0."""
    redact = make_payload(
        record_id="never-recorded", batch_index="redacted", segments=[],
    )
    status, body = _sink.persist_transcript_batch(
        redact, sink_cfg=sink_environment.sink_cfg,
    )
    assert status == 201
    import sqlite3

    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        env = bundles.get_by_cid(conn, body["cid"])
    finally:
        conn.close()
    assert env["version"] == 0


def test_concurrent_batch_collision_returns_409(sink_environment):
    """A producer that posts batch_index=N twice (e.g. retry after a
    network blip) gets 409 on the second post — the verifier's
    monotonicity check rejects equal-or-lower."""
    cfg = sink_environment.sink_cfg
    rid = "record-collide"

    s0, _ = _sink.persist_transcript_batch(
        make_payload(record_id=rid, batch_index=2), sink_cfg=cfg,
    )
    assert s0 == 201

    s1, b1 = _sink.persist_transcript_batch(
        make_payload(
            record_id=rid, batch_index=2,
            started_at="2026-05-07T14:32:00Z",
            ended_at="2026-05-07T14:33:08Z",
            segments=[{"t": 0.0, "speaker": "X", "text": "Y"}],
        ),
        sink_cfg=cfg,
    )
    assert s1 == 409
    assert b1["error"] == "version_not_monotonic"


# ── encryption: empty-reservoir path ────────────────────────────────────


def test_encrypt_true_with_empty_reservoir_returns_503(
    sink_environment, tmp_path, monkeypatch,
):
    """Operator hasn't staged a `.reservoir.yml` (or it's empty).
    `?encrypt=true` returns 503 with `encryption_not_configured` so a
    cooperating client can retry once the file is in place.
    """
    # Point the loader at an explicit absent path to keep the lookup
    # chain from picking up an unrelated reservoir on the dev box.
    monkeypatch.setenv(
        "SWF_RESERVOIR_FILE", str(tmp_path / "missing-reservoir.yml"),
    )
    _sink.reset_reservoir_cache_for_tests()

    payload = make_payload(record_id="enc-empty")
    status, body = _sink.persist_transcript_batch(
        payload, sink_cfg=sink_environment.sink_cfg, encrypt=True,
    )
    assert status == 503
    assert body["error"] == "encryption_not_configured"
    assert body["reason"] == "reservoir_empty_or_missing"


# ── signing-key loading ────────────────────────────────────────────────


def test_load_signing_key_missing_file_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(tmp_path / "absent"))
    _sink.reset_signing_key_cache_for_tests()
    with pytest.raises(FileNotFoundError):
        _sink.load_signing_key()


def test_load_signing_key_wrong_size_raises(tmp_path, monkeypatch):
    bad = tmp_path / "bad.seed"
    bad.write_bytes(b"\x00" * 16)  # 16 bytes — wrong
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(bad))
    _sink.reset_signing_key_cache_for_tests()
    with pytest.raises(ValueError):
        _sink.load_signing_key()


def test_load_signing_key_caches_per_path(tmp_path, monkeypatch):
    """Calling `load_signing_key` twice with the same env var hits
    the cache; pointing the env var at a NEW path triggers a reload."""
    import secrets
    seed_a = tmp_path / "a.seed"
    seed_a.write_bytes(secrets.token_bytes(32))
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(seed_a))
    _sink.reset_signing_key_cache_for_tests()
    k1 = _sink.load_signing_key()
    k2 = _sink.load_signing_key()
    assert k1 is k2  # same cached instance

    seed_b = tmp_path / "b.seed"
    seed_b.write_bytes(secrets.token_bytes(32))
    monkeypatch.setenv("SWF_CONVENT_SIGNING_KEY", str(seed_b))
    k3 = _sink.load_signing_key()
    assert k3 is not k1
