"""Producer-side age-v1 encryption tests (#93 phase 7).

These are the only tests in the suite that exercise the *decrypt* path
— and they only do so to assert the producer-side encrypt path
produces well-formed ciphertext. swf-node itself never decrypts (per
spec §3.6); the consumer apps own that. We use pyrage's identity API
purely to round-trip in tests.
"""
from __future__ import annotations

import pyrage
import pytest

from swf.bundles import build_encryption_block, encrypt_payload
from swf.bundles.encryption import ENCRYPTION_ALG


@pytest.fixture
def keypair():
    """Fresh X25519 keypair via pyrage. Returns `(identity, recipient_str)`."""
    ident = pyrage.x25519.Identity.generate()
    return ident, str(ident.to_public())


@pytest.fixture
def keypairs(keypair):
    """Three fresh keypairs to exercise the encrypt-to-all path."""
    ident2 = pyrage.x25519.Identity.generate()
    ident3 = pyrage.x25519.Identity.generate()
    return [
        keypair,
        (ident2, str(ident2.to_public())),
        (ident3, str(ident3.to_public())),
    ]


# ── encrypt_payload ─────────────────────────────────────────────────────


def test_encrypt_payload_round_trips_with_first_recipient(keypairs):
    """Spec §3.6: any reservoir key can decrypt. Test the first one."""
    plaintext = b"the secret transcript bytes"
    recipients = [pk for _, pk in keypairs]
    ct = encrypt_payload(plaintext, recipients)
    assert isinstance(ct, bytes)
    assert ct.startswith(b"age-encryption.org/v"), (
        "ciphertext should be an age-v1 binary block"
    )
    pt = pyrage.decrypt(ct, [keypairs[0][0]])
    assert pt == plaintext


def test_encrypt_payload_round_trips_with_any_recipient(keypairs):
    """Every recipient privkey in the set can decrypt the same
    ciphertext — the spec invariant that lets us hand keys to
    different alchemists."""
    plaintext = b"shared by all"
    recipients = [pk for _, pk in keypairs]
    ct = encrypt_payload(plaintext, recipients)
    for ident, _ in keypairs:
        assert pyrage.decrypt(ct, [ident]) == plaintext


def test_encrypt_payload_unknown_identity_cannot_decrypt(keypairs):
    """A privkey that wasn't in the recipients list MUST NOT decrypt."""
    plaintext = b"private"
    recipients = [pk for _, pk in keypairs]
    ct = encrypt_payload(plaintext, recipients)
    outsider = pyrage.x25519.Identity.generate()
    with pytest.raises(pyrage.DecryptError):
        pyrage.decrypt(ct, [outsider])


def test_encrypt_payload_empty_recipients_raises():
    with pytest.raises(ValueError, match="non-empty"):
        encrypt_payload(b"x", [])


def test_encrypt_payload_malformed_recipient_string_raises():
    """Bad bech32 -> ValueError, not pyrage's RecipientError leaking
    through."""
    with pytest.raises(ValueError, match="age-v1"):
        encrypt_payload(b"x", ["not-a-recipient"])


def test_encrypt_payload_wrong_prefix_raises():
    with pytest.raises(ValueError, match="age1"):
        encrypt_payload(b"x", ["ed25519:abc"])


def test_encrypt_payload_non_string_recipient_raises():
    with pytest.raises(ValueError):
        encrypt_payload(b"x", [12345])  # type: ignore[list-item]


def test_encrypt_payload_non_bytes_plaintext_raises(keypair):
    _, pk = keypair
    with pytest.raises(TypeError):
        encrypt_payload("not bytes", [pk])  # type: ignore[arg-type]


def test_encrypt_payload_empty_plaintext_ok(keypair):
    """An empty plaintext is legitimate — `batch_index="redacted"`
    with no segments could plausibly canonicalize to an empty inner
    if the schema ever allowed it. Confirm the path doesn't crash."""
    ident, pk = keypair
    ct = encrypt_payload(b"", [pk])
    assert pyrage.decrypt(ct, [ident]) == b""


# ── build_encryption_block ──────────────────────────────────────────────


def test_build_encryption_block_shape(keypairs):
    recipients = [pk for _, pk in keypairs]
    block = build_encryption_block(recipients)
    assert block == {"alg": ENCRYPTION_ALG, "recipients": recipients}
    assert ENCRYPTION_ALG == "age-v1"


def test_build_encryption_block_copies_list(keypairs):
    """The block's `recipients` is a fresh list, not aliased to the
    caller's input — so a later mutation of the source doesn't bleed
    into the envelope."""
    recipients = [pk for _, pk in keypairs]
    block = build_encryption_block(recipients)
    recipients.append("age1mutation")
    assert "age1mutation" not in block["recipients"]


def test_build_encryption_block_empty_raises():
    with pytest.raises(ValueError, match="non-empty"):
        build_encryption_block([])
