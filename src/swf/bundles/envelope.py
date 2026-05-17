"""Bundle envelope: canonicalization, content-id, shape validation.

Phase 1 of #93. The envelope shape is a LOCKED CONTRACT in
`docs/SHAPE-ROTATOR-OS-SPEC.md` §3.1 (in shape-rotator-wrld-knwldge-viz).
Quoting the locked fields directly so the contract lives next to the
code that enforces it:

    {
      "magic": "swf-bundle-v1",
      "kind": "cohort.surface" | "cohort.depth"
            | "transcript.batch" | "search.result",
      "record_id": "<stable string, kind-specific>",
      "version": <monotonic int per record_id>,
      "author": {
        "pubkey": "ed25519:<hex>",
        "signed_at": "<ISO 8601>"
      },
      "prev_cid": "<optional, content hash of v-1 bundle>",
      "encryption": null | {
        "alg": "age-v1",
        "recipients": ["<pubkey>", ...]
      },
      "payload": "<base64 bytes>",
      "signature": "<hex; ed25519 over canonical(envelope minus signature)>"
    }

Canonicalization rule (§3.1): stringify with sorted keys, no extra
whitespace, every field EXCEPT `signature`. The same canonical bytes
are both the signing input and the CID input — verification and
content-addressing share the input.

Public surface:
    - BUNDLE_MAGIC, BUNDLE_KINDS
    - canonicalize(envelope, *, drop_signature=True) -> bytes
    - cid_for(envelope) -> str           # sha256 hex of canonical bytes
    - validate_shape(envelope) -> tuple[bool, str]
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from typing import Any

# ── LOCKED CONTRACT constants ─────────────────────────────────────────────

#: Wire-format magic. Spec §3.1.
BUNDLE_MAGIC = "swf-bundle-v1"

#: Allowed `kind` values. Spec §3.1.
BUNDLE_KINDS: frozenset[str] = frozenset({
    "cohort.surface",
    "cohort.depth",
    "transcript.batch",
    "search.result",
})

#: `author.pubkey` format per §3.7: `ed25519:<64 hex chars>`.
_PUBKEY_RE = re.compile(r"^ed25519:[0-9a-f]{64}$")

#: `signature` is hex-encoded Ed25519 (64 raw bytes -> 128 hex chars).
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")

#: `encryption.alg` enum (only one value today). Spec §3.6.
_ENCRYPTION_ALG_AGE_V1 = "age-v1"


# ── Canonicalization ──────────────────────────────────────────────────────

def canonicalize(envelope: dict[str, Any], *, drop_signature: bool = True) -> bytes:
    """Return the canonical bytes for `envelope`.

    Canonicalization rule (LOCKED, spec §3.1):
        json.dumps with sort_keys=True and no whitespace separators.

    By default `signature` is dropped — that's the version both the
    signer and the CID hasher consume. Pass `drop_signature=False` if
    you need the canonical form of the full envelope (uncommon).

    The output is `bytes` (UTF-8) so it can be fed straight to
    `Ed25519PublicKey.verify` / `hashlib.sha256` without re-encoding.
    """
    if drop_signature and "signature" in envelope:
        envelope = {k: v for k, v in envelope.items() if k != "signature"}
    # `separators=(",", ":")` strips whitespace; `sort_keys=True`
    # sorts at every nesting level via json's default object encoder.
    # `ensure_ascii=False` keeps unicode literals (§3.1 doesn't forbid
    # non-ASCII, and escaping would change the canonical bytes).
    return json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def cid_for(envelope: dict[str, Any]) -> str:
    """Content id of a bundle = sha256 hex of the canonical bytes
    (signature field stripped). Same input as the signature, so a
    bundle's CID is stable across signers and re-canonicalization.

    Spec note: CID is a swf-node-internal addressing primitive; the
    spec mentions `prev_cid` as "content hash of v-1 bundle" without
    specifying the algorithm. Sha256 is the obvious choice; documented
    here for forward compatibility.
    """
    return hashlib.sha256(canonicalize(envelope, drop_signature=True)).hexdigest()


# ── Shape validation ──────────────────────────────────────────────────────

# Top-level keys we know about. `prev_cid` is optional; everything else
# must be present at write time.
_REQUIRED_TOP = ("magic", "kind", "record_id", "version", "author",
                 "encryption", "payload", "signature")
_OPTIONAL_TOP = ("prev_cid",)


def validate_shape(envelope: Any) -> tuple[bool, str]:
    """Walk the envelope and return `(ok, reason_tag)`.

    Reason tags match `swf.bundles.verify.VerifyReason` so the verifier
    can pass them through unchanged. Specifically:
        ""                       — ok
        "shape_invalid"          — wrong type / missing field / bad encoding
        "kind_unknown"           — `kind` not in BUNDLE_KINDS
        "pubkey_malformed"       — `author.pubkey` doesn't match ed25519:<hex>
        "encryption_malformed"   — `encryption` block bad shape

    `signature` is checked for hex-shape only here; cryptographic
    verification is in `swf.bundles.signing.verify_envelope_signature`.
    """
    if not isinstance(envelope, dict):
        return False, "shape_invalid"

    for k in _REQUIRED_TOP:
        if k not in envelope:
            return False, "shape_invalid"

    # magic (LOCKED)
    if envelope["magic"] != BUNDLE_MAGIC:
        return False, "shape_invalid"

    # kind enum
    if not isinstance(envelope["kind"], str):
        return False, "shape_invalid"
    if envelope["kind"] not in BUNDLE_KINDS:
        return False, "kind_unknown"

    # record_id: non-empty string
    if not isinstance(envelope["record_id"], str) or not envelope["record_id"]:
        return False, "shape_invalid"

    # version: non-negative int (bool is a subclass of int — exclude)
    ver = envelope["version"]
    if isinstance(ver, bool) or not isinstance(ver, int) or ver < 0:
        return False, "shape_invalid"

    # author: { pubkey, signed_at }
    author = envelope["author"]
    if not isinstance(author, dict):
        return False, "shape_invalid"
    if "pubkey" not in author or "signed_at" not in author:
        return False, "shape_invalid"
    pubkey = author["pubkey"]
    if not isinstance(pubkey, str):
        return False, "shape_invalid"
    if not _PUBKEY_RE.match(pubkey):
        return False, "pubkey_malformed"
    if not isinstance(author["signed_at"], str) or not author["signed_at"]:
        return False, "shape_invalid"

    # prev_cid: optional string (None is also accepted; spec calls it optional)
    if "prev_cid" in envelope:
        prev = envelope["prev_cid"]
        if prev is not None and not isinstance(prev, str):
            return False, "shape_invalid"

    # encryption: null OR { alg, recipients[] }
    enc = envelope["encryption"]
    if enc is not None:
        if not isinstance(enc, dict):
            return False, "encryption_malformed"
        if enc.get("alg") != _ENCRYPTION_ALG_AGE_V1:
            return False, "encryption_malformed"
        recipients = enc.get("recipients")
        if not isinstance(recipients, list) or not recipients:
            return False, "encryption_malformed"
        for r in recipients:
            if not isinstance(r, str) or not r:
                return False, "encryption_malformed"

    # payload: base64 string. Decode to confirm well-formedness; we do
    # NOT keep the decoded bytes (spec §3.1: payload stays opaque to
    # swf-node, only the consumer decodes).
    payload = envelope["payload"]
    if not isinstance(payload, str):
        return False, "shape_invalid"
    try:
        # `validate=True` rejects non-base64 chars; empty payload is
        # technically legal (b64decode("") -> b"") and we allow it.
        base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return False, "shape_invalid"

    # signature: hex string of the right length
    sig = envelope["signature"]
    if not isinstance(sig, str):
        return False, "shape_invalid"
    if not _SIGNATURE_RE.match(sig):
        return False, "shape_invalid"

    return True, ""
