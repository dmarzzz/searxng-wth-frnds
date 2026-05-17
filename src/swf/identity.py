"""Peer identity: Ed25519 keypair per node.

One keypair per deployment, persisted at `~/.config/swf/identity.key`
(private seed, 0600) and `~/.config/swf/identity.pub` (base64url pubkey).
The public key is the peer's stable identifier across sessions; use the
short fingerprint (`pubkey_fingerprint(pk)`) in human-visible places.

Public surface:
    - get_or_create_identity() -> Identity
    - sign(data: bytes) -> bytes
    - verify(pubkey: bytes|str, data: bytes, sig: bytes|str) -> bool
    - pubkey_fingerprint(pk) -> str  (first 8 bytes blake2b hex)
    - load_public(pk) -> Ed25519PublicKey     (decodes b64url-or-hex)
    - pubkey_to_b64(pk: bytes) -> str

Spec ref: INDREX.md section B, escalation stage v2 base (transport) and
the handshake shape described in section D's service-record schema.

v0.4 scope: keypair, sign, verify, fingerprint, TOFU on `swf-peer add`.
Noise KK handshake and Double-Ratchet forward secrecy are v0.7.
"""

from __future__ import annotations

import base64
import contextlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import BLAKE2b, Hash


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _identity_dir() -> Path:
    """Identity dir is the same as `swf.paths.config_dir()` — mode 0700.

    SWF_CONFIG_DIR override goes through `ensure_dir` so an explicit
    path also gets the owner-only enforcement."""
    from swf.paths import config_dir, ensure_dir
    env = os.environ.get("SWF_CONFIG_DIR")
    if env:
        return ensure_dir(Path(env))
    return config_dir()


def private_key_path() -> Path:
    return _identity_dir() / "identity.key"


def public_key_path() -> Path:
    return _identity_dir() / "identity.pub"


@dataclass
class Identity:
    """Holds an in-memory Ed25519 keypair plus its base64url-encoded pubkey."""

    priv: Ed25519PrivateKey
    pub: Ed25519PublicKey
    pub_b64: str

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data)

    def sign_b64(self, data: bytes) -> str:
        return _b64url_encode(self.sign(data))

    def fingerprint(self) -> str:
        return pubkey_fingerprint(self.pub_b64)


def _load_priv_from_seed(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def _pub_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def get_or_create_identity() -> Identity:
    """Load the persistent identity, creating it on first call.

    The private key is written with mode 0600. On systems without POSIX
    perms this falls back to "whatever the OS gives us" with a warning
    comment in the file.
    """
    priv_path = private_key_path()
    pub_path = public_key_path()

    if priv_path.exists():
        raw = priv_path.read_bytes()
        # File format: raw 32-byte seed (binary). No PEM ceremony; this
        # is a local secret, not an X.509 artifact.
        if len(raw) != 32:
            raise RuntimeError(
                f"identity file {priv_path} has length {len(raw)}, expected 32-byte seed"
            )
        priv = _load_priv_from_seed(raw)
    else:
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_path.write_bytes(seed)
        with contextlib.suppress(OSError):  # non-POSIX; best-effort
            os.chmod(priv_path, 0o600)

    pub = priv.public_key()
    pub_b64 = _b64url_encode(_pub_bytes(pub))

    # Keep a human-readable pubkey file in sync (used by CLI tools).
    if not pub_path.exists() or pub_path.read_text().strip() != pub_b64:
        pub_path.write_text(pub_b64 + "\n")

    return Identity(priv=priv, pub=pub, pub_b64=pub_b64)


# ── Verification / helpers ─────────────────────────────────────────────────


def pubkey_fingerprint(pub_b64: str) -> str:
    """Short, stable fingerprint of a pubkey (16 hex chars, blake2b-64)."""
    raw = _b64url_decode(pub_b64.strip())
    h = Hash(BLAKE2b(64))
    h.update(raw)
    return h.finalize()[:8].hex()


def load_public(pub_b64_or_hex: str) -> Ed25519PublicKey:
    s = (pub_b64_or_hex or "").strip()
    # Accept either 43-char b64url (32 bytes) or 64-char hex.
    try:
        if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
            raw = bytes.fromhex(s)
        else:
            raw = _b64url_decode(s)
    except Exception as exc:
        raise ValueError(f"cannot parse pubkey {s!r}: {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def verify(
    pubkey: bytes | str | Ed25519PublicKey,
    data: bytes,
    sig: bytes | str,
) -> bool:
    """Verify an Ed25519 signature. Returns False on any failure rather
    than raising so callers can use this as a gate without try/except.
    """
    try:
        if isinstance(pubkey, Ed25519PublicKey):
            pk = pubkey
        elif isinstance(pubkey, (bytes, bytearray)):
            pk = Ed25519PublicKey.from_public_bytes(bytes(pubkey))
        else:
            pk = load_public(str(pubkey))

        if isinstance(sig, str):
            sig_bytes = _b64url_decode(sig)
        else:
            sig_bytes = bytes(sig)

        pk.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def pubkey_to_b64(pub: bytes | Ed25519PublicKey) -> str:
    if isinstance(pub, Ed25519PublicKey):
        return _b64url_encode(_pub_bytes(pub))
    return _b64url_encode(bytes(pub))


# ── Canonical signing payloads ─────────────────────────────────────────────
#
# All signatures in the protocol cover canonical byte strings built from
# the operation and arguments. Keep these helpers here so verifier and
# signer stay in lockstep.


def canonical_indrex_response(*, pubkey_b64: str, node: str, ts: str, body_hash: str) -> bytes:
    """Payload signed by /.well-known/indrex:
        b"indrex-v1\n" + pubkey_b64 + "\n" + node + "\n" + ts + "\n" + body_hash
    """
    return "\n".join(
        ["indrex-v1", pubkey_b64, node, ts, body_hash]
    ).encode("utf-8")


def body_hash_b64(body: bytes) -> str:
    """sha256(body) in base64url. Used in canonical signing payloads so
    tamper of the body invalidates the signature."""
    from hashlib import sha256

    return _b64url_encode(sha256(body).digest())
