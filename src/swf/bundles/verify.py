"""Full bundle verification pipeline.

Phase 1 of #93. The verifier ties together envelope shape, alchemist
whitelist, signature, and version monotonicity into a single result.
The HTTP write path (phase 2) will call this exactly once per
incoming bundle; phase 1 just exposes the function so tests can
exercise it end-to-end.

Pipeline (in order; first failure wins):
  1. Shape — `validate_shape(envelope)` covers required fields,
     `kind` enum, `author.pubkey` regex, base64 payload, encryption
     block well-formedness, signature hex shape.
  2. Alchemist whitelist — `author.pubkey` is in `alchemists`. SKIPPED
     for `kind == "search.result"`: those bundles are signed by peer
     pubkeys, not alchemist keys (existing swf-node convention; spec
     §3.1 carves out `search.result` as the legacy domain).
  3. Signature — Ed25519 over the canonical bytes minus `signature`.
     Same canonical bytes the CID is computed from, so verify and
     content-address share an input.
  4. Monotonicity — `version > latest_version(conn, kind, record_id)`
     when a prior version exists. Strictly greater; equal-or-lower is
     a replay and is rejected.
  5. Reservoir recipients — when an explicit `reservoir` is passed
     and the bundle has an `encryption` block, every recipient must
     be in the reservoir's pubkey set. The kwarg is optional so phase-2
     callers stay back-compat; the hivemind sink and any future
     cohort.depth ingest pass the loaded reservoir.

About transcript.batch monotonicity:
    Spec §3.5 says "Batches MUST be append-only — `version` increments
    are NOT used; `batch_index` does." We interpret that at TWO
    levels:
      - Envelope level: every bundle (regardless of kind) carries an
        envelope `version` and the verifier enforces strict-greater
        monotonicity per `record_id`. This is the swf-node-internal
        anti-replay primitive and applies uniformly.
      - Payload level: `transcript.batch` payloads ALSO carry a
        `batch_index` integer that the cohort viewer / hivemind uses
        to reconstruct the full transcript. This is a payload-level
        application concern; phase 1 does NOT inspect payloads.
    A producer who follows the spec will just bump `version` in
    lockstep with `batch_index` (or use `version = batch_index`).
    Either way, envelope-level monotonicity is preserved.

Public surface:
    - VerifyReason   (string-tag namespace)
    - VerifyResult   (dataclass: ok, reason, cid)
    - verify_bundle(envelope, *, alchemists, conn) -> VerifyResult
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .alchemists import AlchemistList
from .envelope import cid_for, validate_shape
from .reservoir import Reservoir
from .signing import verify_envelope_signature
from .store import latest_version


class VerifyReason:
    """Short, machine-matchable rejection tags.

    These are deliberately *tags*, not sentences — operators and tests
    pattern-match on them. If you need a human-readable message, do
    the lookup at the call site.
    """

    SHAPE_INVALID = "shape_invalid"
    KIND_UNKNOWN = "kind_unknown"
    PUBKEY_MALFORMED = "pubkey_malformed"
    AUTHOR_NOT_ALCHEMIST = "author_not_alchemist"
    SIGNATURE_INVALID = "signature_invalid"
    VERSION_NOT_MONOTONIC = "version_not_monotonic"
    ENCRYPTION_MALFORMED = "encryption_malformed"
    ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR = "encryption_recipient_not_in_reservoir"


# Reasons emitted by `validate_shape`. We pass them through unchanged
# so callers can match on a single namespace.
_SHAPE_REASONS = {
    VerifyReason.SHAPE_INVALID,
    VerifyReason.KIND_UNKNOWN,
    VerifyReason.PUBKEY_MALFORMED,
    VerifyReason.ENCRYPTION_MALFORMED,
}


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of `verify_bundle`.

    `ok` is True iff every pipeline stage passed.
    `reason` is the empty string on success, otherwise one of the
    `VerifyReason` tags.
    `cid` is always populated — even on failure — so the caller can
    log "rejected <cid> reason=<r>" without recomputing. Computed
    from `cid_for(envelope)` if the envelope is at least a dict;
    otherwise empty string.
    """

    ok: bool
    reason: str
    cid: str


def _safe_cid(envelope: Any) -> str:
    """Best-effort CID. Returns "" if the envelope is so malformed
    that we can't even canonicalize it (e.g. not a dict)."""
    try:
        if not isinstance(envelope, dict):
            return ""
        return cid_for(envelope)
    except Exception:
        return ""


def verify_bundle(
    envelope: Any,
    *,
    alchemists: AlchemistList,
    conn: sqlite3.Connection,
    reservoir: Reservoir | None = None,
) -> VerifyResult:
    """Run the full 4-stage pipeline. See module docstring for stages.

    `alchemists` is loaded once at boot via
    `swf.bundles.alchemists.load_alchemists()`. `conn` is a connection
    to the indrex DB with `bundles` schema in place; phase 2's HTTP
    layer will hold a long-lived writer connection.

    `reservoir` is optional — when provided AND the bundle's
    `encryption` block is non-null, every recipient string in
    `encryption.recipients` is cross-checked against `reservoir.pubkeys()`.
    A recipient that's not in the reservoir produces
    `VerifyReason.ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR`. This is the
    phase-2-deferred check from #93; existing call sites that don't
    pass `reservoir` get the original 4-stage behavior unchanged
    (back-compat).
    """
    cid = _safe_cid(envelope)

    # 1. Shape (also covers encryption-block shape per
    #    `validate_shape`'s ENCRYPTION_MALFORMED branch).
    ok, reason = validate_shape(envelope)
    if not ok:
        # `reason` is one of _SHAPE_REASONS; pass it through.
        return VerifyResult(ok=False, reason=reason, cid=cid)

    # From here we know: envelope is a dict with all required fields,
    # kind is in the enum, pubkey is `ed25519:<hex>`, signature is hex
    # of the right length, encryption block (if present) is well-formed.
    kind = envelope["kind"]
    author = envelope["author"]
    pubkey = author["pubkey"]

    # 2. Alchemist whitelist. `search.result` bundles are signed by
    #    peer pubkeys, not alchemist keys, so they bypass this check
    #    by spec convention. Phase 1 doesn't accept search.result on
    #    this path anyway — it's the legacy peer-scraper domain — but
    #    we still implement the carve-out so the verifier is generic.
    if kind != "search.result" and not alchemists.is_alchemist_pubkey(pubkey):
        return VerifyResult(
            ok=False,
            reason=VerifyReason.AUTHOR_NOT_ALCHEMIST,
            cid=cid,
        )

    # 3. Signature.
    if not verify_envelope_signature(envelope):
        return VerifyResult(
            ok=False,
            reason=VerifyReason.SIGNATURE_INVALID,
            cid=cid,
        )

    # 4. Monotonicity. Strictly greater than the highest version we've
    #    already accepted for this (kind, record_id). If no prior
    #    version exists, anything `>= 0` is fine (shape stage already
    #    enforced version >= 0).
    record_id = envelope["record_id"]
    incoming_version = int(envelope["version"])
    prior = latest_version(conn, kind=kind, record_id=record_id)
    if prior is not None and incoming_version <= prior:
        return VerifyResult(
            ok=False,
            reason=VerifyReason.VERSION_NOT_MONOTONIC,
            cid=cid,
        )

    # 5. Reservoir-recipients cross-check (#93 phase 7, spec §3.6).
    #    Only fires when an explicit Reservoir is passed AND the bundle
    #    has an encryption block. The phase-2 call sites pass
    #    `reservoir=None` — they get unchanged behavior. The hivemind
    #    sink + future cohort.depth ingest path pass the loaded
    #    reservoir so a misconfigured producer can't sneak a recipient
    #    that no consumer can decrypt past us.
    enc = envelope.get("encryption")
    if reservoir is not None and isinstance(enc, dict):
        reservoir_pubkeys = set(reservoir.pubkeys())
        for r in enc.get("recipients", []):
            if r not in reservoir_pubkeys:
                return VerifyResult(
                    ok=False,
                    reason=VerifyReason.ENCRYPTION_RECIPIENT_NOT_IN_RESERVOIR,
                    cid=cid,
                )

    return VerifyResult(ok=True, reason="", cid=cid)
