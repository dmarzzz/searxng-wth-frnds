"""Pure-crypto signing/verification tests."""
from __future__ import annotations

import re

from swf.bundles import (
    canonicalize,
    sign_envelope,
    verify_envelope_signature,
)


def _envelope_minus_signature(env: dict) -> dict:
    return {k: v for k, v in env.items() if k != "signature"}


class TestSignEnvelope:
    def test_signature_is_128_hex(self, make_envelope):
        env = make_envelope()
        assert re.match(r"^[0-9a-f]{128}$", env["signature"])

    def test_signature_round_trips(self, make_envelope):
        env = make_envelope()
        assert verify_envelope_signature(env)

    def test_signature_is_deterministic_per_message(
        self, make_envelope, alchemist_keypair,
    ):
        # Ed25519 signatures are deterministic — same priv, same msg
        # bytes -> same signature. (Useful invariant; it means signing
        # twice during build pipelines won't desync caches.)
        env = make_envelope()
        env_no_sig = _envelope_minus_signature(env)
        sig1 = sign_envelope(env_no_sig, priv=alchemist_keypair.priv)
        sig2 = sign_envelope(env_no_sig, priv=alchemist_keypair.priv)
        assert sig1 == sig2

    def test_signature_canonicalizes_input(self, make_envelope, alchemist_keypair):
        # Re-arranging keys before signing must produce the same sig
        # (canonicalize sorts keys).
        env = make_envelope()
        env_no_sig = _envelope_minus_signature(env)
        rearranged = dict(reversed(list(env_no_sig.items())))
        sig1 = sign_envelope(env_no_sig, priv=alchemist_keypair.priv)
        sig2 = sign_envelope(rearranged, priv=alchemist_keypair.priv)
        assert sig1 == sig2


class TestVerifyEnvelopeSignature:
    def test_tampered_payload_rejected(self, make_envelope):
        env = make_envelope()
        # Flip a byte in the payload AFTER signing — sig no longer matches.
        env["payload"] = env["payload"][:-2] + ("AB" if env["payload"][-2:] != "AB" else "CD")
        assert not verify_envelope_signature(env)

    def test_tampered_record_id_rejected(self, make_envelope):
        env = make_envelope()
        env["record_id"] = "alice-impersonator"
        assert not verify_envelope_signature(env)

    def test_tampered_version_rejected(self, make_envelope):
        env = make_envelope()
        env["version"] = env["version"] + 1
        assert not verify_envelope_signature(env)

    def test_wrong_pubkey_rejected(self, make_envelope, make_keypair):
        env = make_envelope()
        # Swap in a different alchemist's pubkey post-sign.
        other = make_keypair()
        env["author"]["pubkey"] = other.pubkey_str
        assert not verify_envelope_signature(env)

    def test_missing_signature_returns_false(self, make_envelope):
        env = make_envelope()
        del env["signature"]
        assert not verify_envelope_signature(env)

    def test_missing_pubkey_returns_false(self, make_envelope):
        env = make_envelope()
        del env["author"]["pubkey"]
        assert not verify_envelope_signature(env)

    def test_garbage_signature_returns_false(self, make_envelope):
        env = make_envelope()
        env["signature"] = "z" * 128
        assert not verify_envelope_signature(env)

    def test_truncated_signature_returns_false(self, make_envelope):
        env = make_envelope()
        env["signature"] = env["signature"][:-2]  # 126 chars
        assert not verify_envelope_signature(env)

    def test_canonical_bytes_independent_of_signature(self, make_envelope):
        # The bytes the signer signs should be the same as the bytes
        # the verifier verifies — i.e. canonicalize(env) without
        # signature is byte-identical pre/post-sign.
        env = make_envelope()
        post = canonicalize(env)
        env_pre = {k: v for k, v in env.items() if k != "signature"}
        pre = canonicalize(env_pre)
        assert pre == post
