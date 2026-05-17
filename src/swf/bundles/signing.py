"""Pure-crypto signing/verification for bundle envelopes.

Phase 1 of #93. Spec §3.7: signatures are Ed25519 over the canonical
bytes of the envelope minus the `signature` field. The signing key is
held by an alchemist (not the local node identity) — this module
takes the private key as bytes and stays free of identity / file I/O
so it's easy to drive from tests with fixed keypairs.

Public surface:
    - sign_envelope(envelope, *, priv) -> str   # hex-encoded signature
    - verify_envelope_signature(envelope) -> bool

Both functions consume `swf.bundles.envelope.canonicalize` so the
canonicalization rule lives in exactly one place.
"""
from __future__ import annotations

from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .envelope import canonicalize


def sign_envelope(envelope: dict[str, Any], *, priv: Ed25519PrivateKey) -> str:
    """Compute the hex-encoded Ed25519 signature for `envelope`.

    Caller is expected to supply an envelope that has every field EXCEPT
    `signature` populated (or with a stale `signature` that will be
    dropped by `canonicalize`). Returns the 128-char hex string suitable
    for assigning to `envelope["signature"]`.

    Note: `priv` is an `Ed25519PrivateKey` from `cryptography` — the
    same type returned by `swf.identity.get_or_create_identity().priv`,
    but the alchemist-key case constructs it directly from raw seed
    bytes via `Ed25519PrivateKey.from_private_bytes(seed)`.
    """
    msg = canonicalize(envelope, drop_signature=True)
    return priv.sign(msg).hex()


def verify_envelope_signature(envelope: dict[str, Any]) -> bool:
    """Verify the envelope's signature against `author.pubkey`.

    Returns True on a valid signature, False on:
      - missing `signature` or `author.pubkey`
      - malformed pubkey / signature hex
      - Ed25519 verify failure (tampered envelope or wrong key)

    Does NOT raise — this is a boolean predicate. Shape errors that the
    full pipeline cares about are reported separately by
    `swf.bundles.envelope.validate_shape`.

    Pubkey format per §3.7: `ed25519:<hex>` — the prefix is stripped
    here. We tolerate the prefix being absent (raw hex) for
    forward-compatibility with future signers, but the verifier
    pipeline rejects non-prefixed pubkeys at the shape stage.
    """
    sig_hex = envelope.get("signature")
    author = envelope.get("author") or {}
    pub_str = author.get("pubkey") if isinstance(author, dict) else None
    if not isinstance(sig_hex, str) or not isinstance(pub_str, str):
        return False

    # `ed25519:<hex>` per §3.7. Strip the prefix; raw hex also tolerated.
    pub_hex = pub_str.removeprefix("ed25519:")
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)
    except ValueError:
        return False
    if len(pub_bytes) != 32 or len(sig_bytes) != 64:
        return False

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception:
        return False

    msg = canonicalize(envelope, drop_signature=True)
    try:
        pub.verify(sig_bytes, msg)
        return True
    except InvalidSignature:
        return False
