"""Unit tests for `swf.sync.envelope`.

Covers (spec §3 + §9.10):
  - canonicalize: golden bytes for a known envelope; signature field
    is always stripped; deterministic across re-runs.
  - content_hash: stable across re-runs; sensitive to content edits.
  - sign + verify: round-trip; tamper detection; pin mismatch rejection.
  - validate_shape: every rejection path triggered (missing field,
    bad regex, oversized envelope, deep content, content_hash mismatch).
"""
from __future__ import annotations

import json

import pytest

from swf.sync import (
    MAX_ENVELOPE_BYTES,
    SYNC_MAGIC,
    canonicalize,
    content_hash,
    envelope_hash,
    sign_envelope,
    verify_envelope_signature,
)
from swf.sync.envelope import validate_shape

# ── canonicalize ──────────────────────────────────────────────────────


def test_canonicalize_drops_signature_by_default(make_envelope):
    env = make_envelope()
    assert "signature" in env
    canon = canonicalize(env)
    assert b'"signature"' not in canon


def test_canonicalize_full_envelope_includes_signature(make_envelope):
    env = make_envelope()
    canon = canonicalize(env, drop_signature=False)
    assert b'"signature"' in canon


def test_canonicalize_is_deterministic(make_envelope):
    env = make_envelope()
    # Permute key insertion order — canonical form should still match.
    permuted = {k: env[k] for k in reversed(list(env.keys()))}
    assert canonicalize(env) == canonicalize(permuted)


def test_canonicalize_golden_bytes():
    """Lock the canonical bytes for a fixed envelope. If this test
    breaks, the wire-format on-disk has changed — fail loudly so the
    spec author can decide whether the change is intentional."""
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "amiller",
        "author_pubkey": "ed25519:" + "ab" * 32,
        "wall_ts_ms": 1716345678000,
        "prev_hash": None,
        "content": {"name": "Andrew", "geo": "NYC"},
        "content_hash": "sha256:" + "cd" * 32,
        "signature": "ff" * 64,
    }
    canon = canonicalize(env)
    expected = (
        b'{"author_pubkey":"ed25519:'
        + b"ab" * 32
        + b'","content":{"geo":"NYC","name":"Andrew"},'
        + b'"content_hash":"sha256:'
        + b"cd" * 32
        + b'","kind":"person",'
        + b'"magic":"swf-sync-v1",'
        + b'"prev_hash":null,'
        + b'"record_id":"amiller",'
        + b'"wall_ts_ms":1716345678000}'
    )
    assert canon == expected


# ── content_hash ──────────────────────────────────────────────────────


def test_content_hash_format():
    h = content_hash({"a": 1})
    assert h.startswith("sha256:")
    assert len(h) == len("sha256:") + 64


def test_content_hash_stable_across_call():
    content = {"name": "Andrew", "geo": "NYC"}
    assert content_hash(content) == content_hash(content)


def test_content_hash_sensitive_to_value_change():
    a = content_hash({"name": "Andrew"})
    b = content_hash({"name": "Bob"})
    assert a != b


def test_content_hash_insensitive_to_key_order():
    a = content_hash({"a": 1, "b": 2})
    b = content_hash({"b": 2, "a": 1})
    assert a == b


# ── sign / verify ─────────────────────────────────────────────────────


def test_sign_verify_round_trip(make_envelope):
    env = make_envelope()
    assert verify_envelope_signature(env) is True


def test_verify_rejects_tampered_content(make_envelope):
    env = make_envelope()
    env["content"]["geo"] = "SF"  # mutate without re-signing
    assert verify_envelope_signature(env) is False


def test_verify_rejects_tampered_wall_ts(make_envelope):
    env = make_envelope()
    env["wall_ts_ms"] = env["wall_ts_ms"] + 1
    assert verify_envelope_signature(env) is False


def test_verify_with_matching_pin(make_envelope, sync_keypair):
    env = make_envelope()
    assert verify_envelope_signature(env, expected_pubkey=sync_keypair.pubkey_str)


def test_verify_with_wrong_pin(make_envelope):
    env = make_envelope()
    wrong = "ed25519:" + "00" * 32
    assert not verify_envelope_signature(env, expected_pubkey=wrong)


def test_verify_rejects_malformed_signature():
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "x",
        "author_pubkey": "ed25519:" + "00" * 32,
        "wall_ts_ms": 1,
        "prev_hash": None,
        "content": {},
        "content_hash": content_hash({}),
        "signature": "not-hex",
    }
    assert not verify_envelope_signature(env)


def test_verify_rejects_missing_signature():
    env = {
        "magic": SYNC_MAGIC,
        "kind": "person",
        "record_id": "x",
        "author_pubkey": "ed25519:" + "00" * 32,
        "wall_ts_ms": 1,
        "prev_hash": None,
        "content": {},
        "content_hash": content_hash({}),
    }
    assert not verify_envelope_signature(env)


# ── envelope_hash ─────────────────────────────────────────────────────


def test_envelope_hash_strips_signature(make_envelope):
    env = make_envelope()
    h1 = envelope_hash(env)
    env["signature"] = "ff" * 64  # different signature, same content
    h2 = envelope_hash(env)
    assert h1 == h2
    assert h1.startswith("sha256:")


# ── validate_shape ────────────────────────────────────────────────────


def test_validate_shape_accepts_signed_envelope(make_envelope):
    env = make_envelope()
    ok, reason = validate_shape(env)
    assert ok, reason


def test_validate_shape_rejects_bad_magic(make_envelope):
    env = make_envelope()
    env["magic"] = "swf-bundle-v1"
    ok, _ = validate_shape(env)
    assert not ok


def test_validate_shape_rejects_unknown_kind(make_envelope, sync_keypair):
    env = make_envelope()
    env["kind"] = "unknown"
    # re-sign so signature passes; shape stage should still reject.
    env["signature"] = sign_envelope(env, priv=sync_keypair.priv)
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "kind_unknown"


def test_validate_shape_rejects_bad_record_id(make_envelope):
    env = make_envelope()
    env["record_id"] = "Has Uppercase"
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "shape_invalid"


def test_validate_shape_rejects_negative_ts(make_envelope):
    env = make_envelope()
    env["wall_ts_ms"] = -1
    ok, _ = validate_shape(env)
    assert not ok


def test_validate_shape_rejects_deep_content(make_envelope):
    # 9-deep nested dict — depth cap is 8.
    deep = {}
    cur = deep
    for _ in range(10):
        cur["x"] = {}
        cur = cur["x"]
    env = make_envelope(content=deep)
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "content_too_deep"


def test_validate_shape_rejects_content_hash_mismatch(make_envelope):
    env = make_envelope()
    env["content_hash"] = "sha256:" + "00" * 32
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "content_hash_mismatch"


def test_validate_shape_rejects_oversize(make_envelope):
    # Push past 64 KiB by stuffing the content. The canonical bytes
    # add ~150 bytes of envelope framing; 70 KiB content trips the cap.
    huge = {"blob": "x" * (70 * 1024)}
    env = make_envelope(content=huge)
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "envelope_too_large"


def test_validate_shape_rejects_missing_field(make_envelope):
    env = make_envelope()
    del env["wall_ts_ms"]
    ok, reason = validate_shape(env)
    assert not ok
    assert reason == "shape_invalid"


def test_envelope_size_under_cap(make_envelope):
    """A reasonably-sized person record fits comfortably."""
    env = make_envelope(content={
        "name": "Andrew Miller",
        "geo": "Brooklyn, NY",
        "handles": {"github": "amiller", "matrix": "@amiller:matrix.org"},
        "bio": "Long bio paragraph " * 50,
    })
    canon = canonicalize(env)
    assert len(canon) < MAX_ENVELOPE_BYTES
    ok, _ = validate_shape(env)
    assert ok
