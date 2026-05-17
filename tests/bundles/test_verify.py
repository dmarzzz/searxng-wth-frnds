"""End-to-end verifier tests covering every VerifyReason path."""
from __future__ import annotations

import sqlite3

import pytest

from swf.bundles import (
    VerifyReason,
    ensure_schema,
    insert,
    sign_envelope,
    verify_bundle,
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    c = sqlite3.connect(str(tmp_path / "index.db"))
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


# ── Happy path ──────────────────────────────────────────────────────────────


class TestHappyPath:
    def test_known_good_envelope_verifies(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        env = make_envelope()
        al = alchemists_with(alchemist_keypair.pubkey_str)
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert result.ok, result.reason
        assert result.reason == ""
        assert len(result.cid) == 64

    def test_cid_populated_even_on_failure(
        self, conn, make_envelope, alchemists_with,
    ):
        # Empty alchemist list -> author_not_alchemist; but the CID
        # should still be computed.
        env = make_envelope()
        al = alchemists_with()  # empty
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.AUTHOR_NOT_ALCHEMIST
        assert len(result.cid) == 64


# ── Reject paths, one per reason tag ────────────────────────────────────────


class TestRejectShape:
    def test_not_a_dict(self, conn, alchemists_with):
        result = verify_bundle("not a bundle", alchemists=alchemists_with(),
                               conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.SHAPE_INVALID
        # CID is empty for non-dict envelopes (can't canonicalize).
        assert result.cid == ""

    def test_missing_field(self, conn, make_envelope, alchemists_with):
        env = make_envelope()
        del env["payload"]
        result = verify_bundle(env, alchemists=alchemists_with(), conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.SHAPE_INVALID

    def test_unknown_kind(self, conn, make_envelope, alchemists_with):
        env = make_envelope()
        env["kind"] = "unknown.thing"
        result = verify_bundle(env, alchemists=alchemists_with(), conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.KIND_UNKNOWN

    def test_pubkey_malformed(self, conn, make_envelope, alchemists_with):
        env = make_envelope()
        env["author"]["pubkey"] = "not-a-pubkey"
        result = verify_bundle(env, alchemists=alchemists_with(), conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.PUBKEY_MALFORMED

    def test_encryption_malformed(self, conn, make_envelope, alchemists_with):
        env = make_envelope(
            kind="cohort.depth",
            encryption={"alg": "rot13", "recipients": ["age1xx"]},
        )
        result = verify_bundle(env, alchemists=alchemists_with(), conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.ENCRYPTION_MALFORMED


class TestRejectAlchemist:
    def test_unlisted_pubkey(
        self, conn, make_envelope, alchemists_with, make_keypair,
    ):
        env = make_envelope()
        # The list contains some OTHER alchemist; not the signer.
        other = make_keypair()
        al = alchemists_with(other.pubkey_str)
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.AUTHOR_NOT_ALCHEMIST

    def test_search_result_bypasses_alchemist_check(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        # search.result envelopes are signed by peer pubkeys per the
        # legacy swf-node convention. The verifier must NOT consult
        # the alchemist list for them — only signature + monotonicity.
        env = make_envelope(kind="search.result", record_id="q-12345")
        # Empty alchemist list; should still verify if signature is good.
        result = verify_bundle(env, alchemists=alchemists_with(), conn=conn)
        assert result.ok, result.reason


class TestRejectSignature:
    def test_tampered_signature(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        env = make_envelope()
        # Replace last few hex chars to break the sig (still
        # well-formed hex of right length, so shape passes).
        sig = env["signature"]
        env["signature"] = sig[:-4] + ("0000" if sig[-4:] != "0000" else "1111")
        al = alchemists_with(alchemist_keypair.pubkey_str)
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.SIGNATURE_INVALID

    def test_payload_tampered_after_sign(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        env = make_envelope(payload=b"original")
        # Re-encode a different payload without re-signing.
        import base64
        env["payload"] = base64.b64encode(b"tampered").decode("ascii")
        al = alchemists_with(alchemist_keypair.pubkey_str)
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.SIGNATURE_INVALID

    def test_signed_by_wrong_key(
        self, conn, make_envelope, alchemists_with, alchemist_keypair, make_keypair,
    ):
        # Build an envelope with author=alchemist_keypair but signed
        # by SOME OTHER key. Both keys are listed as alchemists, so
        # the alchemist check passes; the verifier must catch the
        # signature mismatch.
        impostor = make_keypair()
        env = make_envelope()  # signed correctly first
        # Re-sign with the impostor's key, leaving author.pubkey
        # pointing at the legitimate alchemist.
        env["signature"] = sign_envelope(
            {k: v for k, v in env.items() if k != "signature"},
            priv=impostor.priv,
        )
        al = alchemists_with(alchemist_keypair.pubkey_str, impostor.pubkey_str)
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.SIGNATURE_INVALID


class TestRejectMonotonicity:
    def test_replay_same_version(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        al = alchemists_with(alchemist_keypair.pubkey_str)
        env_v0 = make_envelope(version=0)
        # Insert v0 into the store first.
        insert(env_v0, conn=conn)
        conn.commit()
        # Replaying v0 must be rejected.
        result = verify_bundle(env_v0, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.VERSION_NOT_MONOTONIC

    def test_lower_version_rejected(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        al = alchemists_with(alchemist_keypair.pubkey_str)
        # Latest accepted version is 5.
        insert(make_envelope(version=5), conn=conn)
        conn.commit()
        # Incoming version=3 -> reject.
        env_v3 = make_envelope(version=3)
        result = verify_bundle(env_v3, alchemists=al, conn=conn)
        assert not result.ok
        assert result.reason == VerifyReason.VERSION_NOT_MONOTONIC

    def test_strictly_greater_version_accepted(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        al = alchemists_with(alchemist_keypair.pubkey_str)
        insert(make_envelope(version=5), conn=conn)
        conn.commit()
        env_v6 = make_envelope(version=6)
        result = verify_bundle(env_v6, alchemists=al, conn=conn)
        assert result.ok, result.reason

    def test_first_version_for_record_id_accepted(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        # No prior bundle for "alice" -> any version >= 0 is fine.
        al = alchemists_with(alchemist_keypair.pubkey_str)
        env = make_envelope(version=42, record_id="alice")
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert result.ok, result.reason

    def test_monotonicity_scoped_per_record(
        self, conn, make_envelope, alchemists_with, alchemist_keypair,
    ):
        al = alchemists_with(alchemist_keypair.pubkey_str)
        insert(make_envelope(version=99, record_id="alice"), conn=conn)
        conn.commit()
        # Different record_id -> independent counter.
        env = make_envelope(version=0, record_id="bob")
        result = verify_bundle(env, alchemists=al, conn=conn)
        assert result.ok, result.reason
