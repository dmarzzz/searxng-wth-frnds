"""Producer-side age-v1 encryption (#93 phase 7, spec §3.6).

Pure-crypto helpers that wrap pyrage's `encrypt` / `Recipient.from_str`.
No I/O, no caching, no key material owned at module level — the
reservoir loader (`swf.bundles.reservoir`) is the only place keys live.

Recipient wire format (#108 ask 1, spec §3.6 amendment): every entry
in an envelope's `encryption.recipients[]` is an **age-v1 X25519
recipient string in bech32 form** — `age1...`, exactly the strings
`pyrage`'s `x25519.Recipient.from_str()` accepts. Other forms (raw
hex curve25519, ssh-ed25519 recipient lines, age plugin recipients
like `age1yubikey1...`) are explicitly out of scope: swf-node's
verifier checks the `age1` prefix at envelope shape time, and the
producer rejects anything else here. Locking this in one place
(producer + verifier + spec) keeps the alchemist app, voxterm sink,
and cohort viz from drifting.

The contract:

  - `encrypt_payload(plaintext, recipients)` returns the age-v1
    ciphertext as bytes. Callers base64-encode that into the
    envelope's `payload` field.

  - `build_encryption_block(recipients)` returns the dict that goes
    in the envelope's `encryption` field — `{"alg": "age-v1",
    "recipients": [...]}`. Convenience to keep the alg literal in one
    place.

  - We deliberately do NOT expose a decrypt path. Spec §3.6 is
    explicit: swf-node verifies envelope shape and stores opaque
    ciphertext; the consumer apps (cohort viz, alchemist Electron
    edition) decrypt with their reservoir keys. Adding a decrypt
    helper here would either need to load reservoir privkeys (which
    swf-node never holds) or accept identities from a caller, which
    is the consumer's job, not the producer's. Leaving it out keeps
    the encapsulation tight and the attack surface minimal.

  - On import error (no pyrage wheel for the target Python), this
    module surfaces a `RuntimeError` at *call* time, not import time.
    That keeps `from swf import bundles` working for ops that only
    need the verifier or the unencrypted hivemind path.
"""
from __future__ import annotations

#: Wire literal for the encryption algorithm. Spec §3.6: only one
#: value allowed today.
ENCRYPTION_ALG = "age-v1"


# Lazy import so that environments without pyrage (e.g. a stripped
# read-only deployment) can still `import swf.bundles` for verify-only
# uses. The error message is on the call path so operators see it
# when they actually try to encrypt.
try:
    import pyrage as _pyrage  # type: ignore[import-not-found]
    _PYRAGE_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # pragma: no cover — only hit on broken wheels
    _pyrage = None  # type: ignore[assignment]
    _PYRAGE_IMPORT_ERROR = _exc


def _require_pyrage() -> None:
    if _pyrage is None:
        raise RuntimeError(
            "pyrage is required for age-v1 encryption but failed to "
            f"import: {_PYRAGE_IMPORT_ERROR!r}. Reinstall the swf-node "
            "package or pin a pyrage wheel that matches your Python."
        )


def encrypt_payload(plaintext: bytes, recipients: list[str]) -> bytes:
    """age-v1 encrypt `plaintext` to all `recipients`.

    Returns the ciphertext bytes ready to be base64-encoded into an
    envelope's `payload` field. Each `recipients[i]` must be an age
    recipient string (bech32, starting `age1...`).

    Raises:
      ValueError on malformed recipients or empty list.
      RuntimeError if pyrage is not installed.

    Note: pyrage's `encrypt` returns an *armored* `age-encryption.org/v1`
    block when called with binary recipients. We pass through the raw
    bytes — base64 wrapping happens at the envelope layer.
    """
    _require_pyrage()
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError(
            f"plaintext must be bytes; got {type(plaintext).__name__}"
        )
    if not recipients:
        raise ValueError("recipients list must be non-empty")

    parsed: list = []
    for r in recipients:
        if not isinstance(r, str):
            raise ValueError(
                f"recipient must be str; got {type(r).__name__}"
            )
        if not r.startswith("age1"):
            raise ValueError(
                f"recipient {r!r} is not an age-v1 recipient "
                "(must start with 'age1')"
            )
        try:
            parsed.append(_pyrage.x25519.Recipient.from_str(r))  # type: ignore[union-attr]
        except _pyrage.RecipientError as exc:  # type: ignore[union-attr]
            raise ValueError(
                f"recipient {r!r} is not a well-formed age-v1 X25519 "
                f"recipient: {exc}"
            ) from exc

    return bytes(_pyrage.encrypt(bytes(plaintext), parsed))  # type: ignore[union-attr]


def build_encryption_block(recipients: list[str]) -> dict:
    """Return the envelope's `encryption` field.

    Centralizes the `alg` literal so tests + producers + verifier all
    agree on the single allowed string. We do NOT validate `recipients`
    here beyond non-emptiness — the verifier's shape check is the
    canonical gate, and we don't want to double-validate.
    """
    if not recipients:
        raise ValueError("recipients list must be non-empty")
    return {
        "alg": ENCRYPTION_ALG,
        "recipients": list(recipients),
    }
