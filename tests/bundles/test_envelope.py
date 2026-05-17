"""Envelope-level invariants: canonicalization determinism, CID
stability, shape validation accept/reject paths."""
from __future__ import annotations

import base64
import json

import pytest

from swf.bundles import (
    BUNDLE_KINDS,
    BUNDLE_MAGIC,
    canonicalize,
    cid_for,
    validate_shape,
)

# ── canonicalize ────────────────────────────────────────────────────────────


class TestCanonicalize:
    def test_sorted_keys_no_whitespace(self):
        env = {
            "z": 1,
            "a": {"y": 2, "x": 1},
            "m": [3, 1, 2],
            "signature": "deadbeef",
        }
        out = canonicalize(env)
        # signature dropped by default
        assert b"signature" not in out
        # keys sorted at every nesting level
        assert out == b'{"a":{"x":1,"y":2},"m":[3,1,2],"z":1}'
        # no whitespace separators
        assert b": " not in out
        assert b", " not in out

    def test_canonicalize_is_deterministic_under_key_reordering(self):
        a = {"kind": "cohort.surface", "version": 1, "magic": "swf-bundle-v1"}
        b = {"version": 1, "magic": "swf-bundle-v1", "kind": "cohort.surface"}
        assert canonicalize(a) == canonicalize(b)

    def test_drop_signature_false_keeps_signature(self):
        env = {"a": 1, "signature": "ff"}
        out = canonicalize(env, drop_signature=False)
        assert b'"signature":"ff"' in out

    def test_round_trip_through_json(self, make_envelope):
        env = make_envelope()
        c1 = canonicalize(env)
        # json.loads + re-canonicalize is a fixed point (canonical
        # bytes are stable across decode/encode)
        decoded = json.loads(c1.decode("utf-8") + b'}'.decode() if False else c1)
        c2 = canonicalize(decoded)
        assert c1 == c2


# ── cid_for ─────────────────────────────────────────────────────────────────


class TestCidFor:
    def test_cid_is_64_hex(self, make_envelope):
        cid = cid_for(make_envelope())
        assert len(cid) == 64
        int(cid, 16)  # valid hex

    def test_cid_independent_of_signature(self, make_envelope, alchemist_keypair):
        env = make_envelope()
        before = cid_for(env)
        env_no_sig = {k: v for k, v in env.items() if k != "signature"}
        after = cid_for(env_no_sig)
        # Same bytes either way — signature is dropped before hashing.
        assert before == after

    def test_cid_changes_when_payload_changes(self, make_envelope):
        a = make_envelope(payload=b"alpha")
        b = make_envelope(payload=b"beta")
        assert cid_for(a) != cid_for(b)


# ── validate_shape: accept ──────────────────────────────────────────────────


class TestValidateShapeAccept:
    def test_known_good_envelope_accepted(self, make_envelope):
        ok, reason = validate_shape(make_envelope())
        assert ok, reason
        assert reason == ""

    def test_each_kind_accepted(self, make_envelope):
        for kind in BUNDLE_KINDS:
            env = make_envelope(kind=kind)
            ok, reason = validate_shape(env)
            assert ok, f"{kind}: {reason}"

    def test_encryption_block_accepted(self, make_envelope):
        env = make_envelope(
            kind="cohort.depth",
            encryption={"alg": "age-v1", "recipients": ["age1abc", "age1xyz"]},
        )
        ok, reason = validate_shape(env)
        assert ok, reason

    def test_prev_cid_optional(self, make_envelope):
        # Both with and without prev_cid pass.
        ok, _ = validate_shape(make_envelope(prev_cid="a" * 64))
        assert ok
        ok, _ = validate_shape(make_envelope())
        assert ok


# ── validate_shape: reject ──────────────────────────────────────────────────


class TestValidateShapeReject:
    def test_not_a_dict(self):
        ok, reason = validate_shape("not a dict")
        assert not ok
        assert reason == "shape_invalid"

    def test_missing_required_field(self, make_envelope):
        env = make_envelope()
        del env["payload"]
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_wrong_magic(self, make_envelope):
        env = make_envelope()
        env["magic"] = "swf-bundle-v0"
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_unknown_kind(self, make_envelope):
        env = make_envelope()
        env["kind"] = "not.a.real.kind"
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "kind_unknown"

    def test_empty_record_id(self, make_envelope):
        env = make_envelope()
        env["record_id"] = ""
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_negative_version(self, make_envelope):
        env = make_envelope()
        env["version"] = -1
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_bool_version_rejected(self, make_envelope):
        # booleans are int subclasses — make sure the validator
        # explicitly excludes them so True doesn't sneak through as 1.
        env = make_envelope()
        env["version"] = True
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_pubkey_missing_prefix(self, make_envelope):
        env = make_envelope()
        # Wipe the prefix.
        env["author"]["pubkey"] = "f" * 64
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "pubkey_malformed"

    def test_pubkey_wrong_curve(self, make_envelope):
        env = make_envelope()
        env["author"]["pubkey"] = "x25519:" + ("a" * 64)
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "pubkey_malformed"

    def test_pubkey_bad_hex(self, make_envelope):
        env = make_envelope()
        env["author"]["pubkey"] = "ed25519:" + ("z" * 64)
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "pubkey_malformed"

    def test_encryption_unknown_alg(self, make_envelope):
        env = make_envelope(
            kind="cohort.depth",
            encryption={"alg": "rot13", "recipients": ["age1xx"]},
        )
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "encryption_malformed"

    def test_encryption_empty_recipients(self, make_envelope):
        env = make_envelope(
            kind="cohort.depth",
            encryption={"alg": "age-v1", "recipients": []},
        )
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "encryption_malformed"

    def test_payload_not_base64(self, make_envelope):
        env = make_envelope()
        env["payload"] = "not!valid!base64!"
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_signature_wrong_length(self, make_envelope):
        env = make_envelope()
        env["signature"] = "ab" * 30   # 60 chars, not 128
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"

    def test_signature_non_hex(self, make_envelope):
        env = make_envelope()
        env["signature"] = "z" * 128
        ok, reason = validate_shape(env)
        assert not ok
        assert reason == "shape_invalid"


# ── module-level constants ──────────────────────────────────────────────────


def test_constants_match_locked_contract():
    assert BUNDLE_MAGIC == "swf-bundle-v1"
    assert frozenset({
        "cohort.surface",
        "cohort.depth",
        "transcript.batch",
        "search.result",
    }) == BUNDLE_KINDS
