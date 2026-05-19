"""Sync envelope: canonicalization, content_hash, signing, verification.

Spec §3. The wire format is:

    {
      "magic": "swf-sync-v1",
      "kind": "person",                         # one of SYNC_RECORD_KINDS
      "record_id": "<[a-z0-9._-]{1,128}>",
      "author_pubkey": "ed25519:<hex>",
      "wall_ts_ms": <int>,
      "prev_hash": "sha256:<hex>" | null,
      "content": { ... },                       # opaque JSON object
      "content_hash": "sha256:<hex>",           # sha256(canonical(content))
      "signature": "<128-char hex>"             # ed25519 over canonical-minus-signature
    }

Canonicalization rule (spec §3.3) reuses
`swf.bundles.envelope.canonicalize` verbatim — same JSON-canonical
form (`sort_keys=True`, no whitespace, UTF-8). The signing-payload
contract (spec §3.4) is byte-identical to the bundle substrate's
`sign_envelope` so we delegate there too.

Public surface mirrors the bundle envelope module so callers can read
the two side-by-side:
    - SYNC_MAGIC, SYNC_RECORD_KINDS, MAX_ENVELOPE_BYTES
    - canonicalize(envelope, *, drop_signature=True) -> bytes
    - content_hash(content) -> str          # sha256:<hex>
    - envelope_hash(envelope) -> str        # sha256 of canonical-minus-signature
    - sign_envelope(envelope, *, priv) -> str
    - verify_envelope_signature(envelope, *, expected_pubkey=None) -> bool

`verify_envelope_signature` accepts an optional `expected_pubkey` (the
cohort-keys pin) so the verifier can refuse mismatches without first
trusting the envelope's own claim of who signed it.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Reuse the bundle substrate's canonicalization byte-for-byte. The spec
# (§3.3) says "the rule already locked in swf.bundles.envelope.canonicalize"
# so this is the contract, not coincidence.
from swf.bundles.envelope import canonicalize as _bundle_canonicalize

# ── LOCKED CONTRACT constants ─────────────────────────────────────────────

#: Wire-format magic. Spec §3.1.
SYNC_MAGIC = "swf-sync-v1"

#: Allowed `kind` values. Phase 2 ships exactly one (spec §3.2);
#: future kinds (`place`, `event`) will extend this set without a
#: schema bump — receivers MUST drop unknown kinds with a warning
#: rather than failing the whole sync.
SYNC_RECORD_KINDS: frozenset[str] = frozenset({"person"})

#: 64 KiB hard cap on canonical envelope bytes (spec §3.5 / §9.3).
MAX_ENVELOPE_BYTES = 64 * 1024

#: `record_id` regex per spec §3.1.
_RECORD_ID_RE = re.compile(r"^[a-z0-9._-]{1,128}$")

#: `author_pubkey` and `prev_hash` / `content_hash` format strings.
_PUBKEY_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

#: `signature` is hex-encoded Ed25519 (64 raw bytes → 128 hex chars).
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")

#: Maximum content nesting depth (spec §3.5).
_MAX_CONTENT_DEPTH = 8

#: Required top-level keys.
_REQUIRED_TOP: tuple[str, ...] = (
    "magic",
    "kind",
    "record_id",
    "author_pubkey",
    "wall_ts_ms",
    "prev_hash",
    "content",
    "content_hash",
    "signature",
)


# ── Canonicalization ──────────────────────────────────────────────────────


def canonicalize(envelope: dict[str, Any], *, drop_signature: bool = True) -> bytes:
    """Return the canonical bytes for `envelope`.

    Wraps `swf.bundles.envelope.canonicalize` so the canonicalization
    rule lives in exactly one place. By default `signature` is dropped
    — that's the version both the signer and the content-id hasher
    consume.
    """
    return _bundle_canonicalize(envelope, drop_signature=drop_signature)


def content_hash(content: Any) -> str:
    """Return `sha256:<hex>` of the canonicalized content (spec §3.4).

    `content` is the envelope's `content` field — typically a dict but
    we don't restrict the JSON shape here (sync is opaque to the
    record payload). The canonicalization rule is the same as for the
    envelope; running it on a non-dict still produces a deterministic
    canonical form via `json.dumps`.
    """
    # `_bundle_canonicalize` calls `json.dumps` with `sort_keys=True`;
    # passing a top-level dict goes through the same path. For a
    # non-dict content (e.g. a list, even though §3.1 calls content an
    # "object"), `drop_signature` is harmless — there's no signature
    # field to drop. We keep the wrapping consistent for symmetry.
    if isinstance(content, dict):
        canon = _bundle_canonicalize(content, drop_signature=False)
    else:
        # Fall back to the same canonicalization rule for non-dict
        # content. We never strip `signature` here either.
        import json
        canon = json.dumps(
            content, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canon).hexdigest()


def envelope_hash(envelope: dict[str, Any]) -> str:
    """Return `sha256:<hex>` of the envelope's canonical-minus-signature
    bytes. Mirrors `swf.bundles.envelope.cid_for` but emits the
    `sha256:<hex>` prefix the spec uses on the wire for `prev_hash` /
    `content_hash`."""
    return "sha256:" + hashlib.sha256(
        canonicalize(envelope, drop_signature=True),
    ).hexdigest()


# ── Shape validation ──────────────────────────────────────────────────────


def _content_depth(node: Any, *, current: int = 0) -> int:
    """Return the maximum nesting depth of a JSON value.

    Used to defend against pathological `content` (spec §3.5) — a
    canonicalizer fed a 10k-deep nested dict could otherwise spend
    O(depth²) on `sort_keys` recursion.
    """
    if isinstance(node, dict):
        if not node:
            return current + 1
        return max(_content_depth(v, current=current + 1) for v in node.values())
    if isinstance(node, list):
        if not node:
            return current + 1
        return max(_content_depth(v, current=current + 1) for v in node)
    return current


def validate_shape(envelope: Any) -> tuple[bool, str]:
    """Walk the envelope and return `(ok, reason_tag)`.

    Mirrors `swf.bundles.envelope.validate_shape` — same shape, sync
    reasons.

    Reason tags (also surfaced by the HTTP layer in /sync error
    bodies):
        ""                       — ok
        "shape_invalid"          — wrong type / missing field / bad regex
        "kind_unknown"           — `kind` not in SYNC_RECORD_KINDS
        "envelope_too_large"     — canonical bytes > MAX_ENVELOPE_BYTES
        "content_too_deep"       — content nesting depth > 8
        "content_hash_mismatch"  — recomputed content_hash != envelope.content_hash
    """
    if not isinstance(envelope, dict):
        return False, "shape_invalid"

    for k in _REQUIRED_TOP:
        if k not in envelope:
            return False, "shape_invalid"

    if envelope["magic"] != SYNC_MAGIC:
        return False, "shape_invalid"

    kind = envelope["kind"]
    if not isinstance(kind, str):
        return False, "shape_invalid"
    if kind not in SYNC_RECORD_KINDS:
        return False, "kind_unknown"

    record_id = envelope["record_id"]
    if not isinstance(record_id, str) or not _RECORD_ID_RE.match(record_id):
        return False, "shape_invalid"

    pubkey = envelope["author_pubkey"]
    if not isinstance(pubkey, str) or not _PUBKEY_RE.match(pubkey):
        return False, "shape_invalid"

    wall_ts = envelope["wall_ts_ms"]
    if isinstance(wall_ts, bool) or not isinstance(wall_ts, int) or wall_ts < 0:
        return False, "shape_invalid"

    prev = envelope["prev_hash"]
    if prev is not None and (not isinstance(prev, str) or not _SHA256_RE.match(prev)):
        return False, "shape_invalid"

    content = envelope["content"]
    # `content` is required and MUST be a JSON object per §3.1. We
    # accept lists too (defensive — some serializers wrap), but the
    # depth check fires either way.
    if not isinstance(content, (dict, list)):
        return False, "shape_invalid"
    if _content_depth(content) > _MAX_CONTENT_DEPTH:
        return False, "content_too_deep"

    ch = envelope["content_hash"]
    if not isinstance(ch, str) or not _SHA256_RE.match(ch):
        return False, "shape_invalid"

    sig = envelope["signature"]
    if not isinstance(sig, str) or not _SIGNATURE_RE.match(sig):
        return False, "shape_invalid"

    # Envelope size cap (spec §3.5 / §9.3). Computed AFTER shape checks
    # so a malformed envelope doesn't get treated as a size error.
    try:
        canon = canonicalize(envelope, drop_signature=True)
    except (TypeError, ValueError):
        return False, "shape_invalid"
    if len(canon) > MAX_ENVELOPE_BYTES:
        return False, "envelope_too_large"

    # Content-hash sanity: recompute and compare. Spec §3.4 — the
    # receiver MUST reject on mismatch.
    if content_hash(content) != ch:
        return False, "content_hash_mismatch"

    return True, ""


# ── Signing / verification ────────────────────────────────────────────────


def sign_envelope(envelope: dict[str, Any], *, priv: Ed25519PrivateKey) -> str:
    """Compute the hex-encoded Ed25519 signature for `envelope`.

    Caller passes an envelope with every field EXCEPT `signature`
    populated. The canonical bytes consumed here are byte-identical
    to what `verify_envelope_signature` consumes on the other side.
    """
    msg = canonicalize(envelope, drop_signature=True)
    return priv.sign(msg).hex()


def verify_envelope_signature(
    envelope: dict[str, Any],
    *,
    expected_pubkey: str | None = None,
) -> bool:
    """Verify the envelope's signature.

    Returns True iff:
      - `signature` parses as 64-byte hex
      - `author_pubkey` parses as `ed25519:<64 hex>`
      - the canonical-minus-signature bytes verify under that pubkey
      - if `expected_pubkey` is given, it equals `author_pubkey`
        (the cohort-keys / record-author pin)

    Never raises — boolean predicate so callers can use it as a gate.
    """
    sig_hex = envelope.get("signature")
    pub_str = envelope.get("author_pubkey")
    if not isinstance(sig_hex, str) or not isinstance(pub_str, str):
        return False
    if not _SIGNATURE_RE.match(sig_hex) or not _PUBKEY_RE.match(pub_str):
        return False
    if expected_pubkey is not None and pub_str != expected_pubkey:
        return False

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
