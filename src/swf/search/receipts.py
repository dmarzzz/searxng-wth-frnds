"""SPEC v0.3 §27.16–§27.22 anonymous receipts — interface stub.

Phase 6D ships the **interface skeleton** for anonymous positive receipts
(§27.16 receipt eligibility, §27.17 receipt-ticket issuance, §27.19
redemption, §27.20 delivery modes, §27.21 privacy rules) without any
crypto. The data layer for `RECEIPT_TICKET_V1` already exists in
`tickets.py` — receipts share the spent-nullifier table, the issuer-key
registry, and the same envelope shape with a different family + scope.

Default off:
  * `SWF_ENABLE_RECEIPTS=1` opts the flow in. Without it, every public
    method here is a no-op — peers cannot issue, redeem, or accept
    receipts. This preserves the §27 default-deny posture identical to
    Phase 4 (DCNET) and Phase 6B/C (query tickets).
  * The default `_NullReceiptProvider` always refuses issuance and
    rejects every redemption attempt. It satisfies the `ReceiptProvider`
    Protocol so structure tests pass, but it never produces or accepts a
    valid receipt.
  * `tickets.verify_signature()` still raises NotImplementedError — the
    crypto seam is untouched. Receipt verification translates that into
    a structured `RECEIPT_SIGNATURE_NOT_VERIFIED` rejection instead of a
    stack trace.

To plug in a real Privacy Pass receipt issuer:
  1. Implement `ReceiptProvider` (Protocol).
  2. Replace the body of `tickets.verify_signature()` with the library's
     verify call (the same hook query tickets share).
  3. Call `receipts.set_provider(my_provider)` at swf-node boot.

The §29.2 invariants gate any privacy claim that depends on receipts —
this module emits clear `ReceiptRejection` reasons that callers (the
reputation system, the LAN receipt board, the wall UI) can surface
without having to mint a privacy claim themselves.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from . import tickets
from .tickets import (
    DEFAULT_NULLIFIER_RETENTION_MS,
    IssuerKey,
    TicketEnvelope,
    TicketFamily,
    TicketRejection,
)

# ── §27.18 receipt scope + classes ──────────────────────────────────

# §27.18 only one scope is defined for receipt tokens. Pinned in code
# (rather than as a free-string) so a misconfigured caller can't
# accidentally redeem a query ticket as a receipt or vice versa.
RECEIPT_SCOPE = "PROVIDER_POSITIVE_RECEIPT"


class ReceiptClass(str, Enum):
    """§27.18 receipt class enum. Spec is explicit: NO negative classes
    in v1 — anonymous negative feedback is too easy to weaponize. If
    someone tries to add NEGATIVE_RESULT here, that's a red flag."""
    USEFUL_RESULT = "useful_result"
    SAVED_RESULT = "saved_result"
    VERIFIED_SLICE = "verified_slice"
    HIGH_QUALITY_SNIPPET = "high_quality_snippet"


_ALLOWED_RECEIPT_CLASSES = frozenset(c.value for c in ReceiptClass)


# ── §27.19 redemption rejection reasons ─────────────────────────────

class ReceiptRejection(str, Enum):
    """Reasons §27.19 verification can fail. Distinct from
    `TicketRejection` so the audit trail can distinguish a query-ticket
    failure (auth) from a receipt failure (reputation signal)."""
    DISABLED = "anonymous_receipt_feature_disabled"
    MISSING = "anonymous_receipt_missing"
    INVALID = "anonymous_receipt_invalid"
    WRONG_FAMILY = "anonymous_receipt_wrong_family"
    WRONG_SCOPE = "anonymous_receipt_wrong_scope"
    UNKNOWN_CLASS = "anonymous_receipt_unknown_class"
    BAD_PROVIDER_KEY = "anonymous_receipt_bad_provider_key"
    MISSING_SERVICE_PROOF = "anonymous_receipt_missing_service_proof"
    DOUBLE_SPENT = "anonymous_receipt_double_spent"
    UNTRUSTED_ISSUER = "anonymous_receipt_issuer_untrusted"
    SIGNATURE_NOT_VERIFIED = "anonymous_receipt_signature_not_verified"
    WRONG_EPOCH = "anonymous_receipt_wrong_epoch"


# ── §27.16 service proof shape ──────────────────────────────────────

@dataclass(frozen=True)
class ServiceProof:
    """§27.16 swf.provider_service_proof.v1. The provider signs this
    over its response so a requester can later mint a receipt that
    references it. The receipt itself carries only the hash; the full
    proof stays local on the requester's machine.

    Crypto-opaque: `provider_signature` is just bytes here. A real
    provider Ed25519 implementation lives in a future PR — we don't
    verify the signature in this module either, but `redeem` requires
    the *hash* to be present on the redemption envelope so a future
    audit can cross-check."""
    schema: str
    circle_id: str
    epoch_id: str
    qid: str
    provider_pubkey: str
    response_digest: str       # H(canonical SearchResultBundle)
    served_at_ms: int
    receipt_challenge_nonce: str
    receipt_classes: tuple[str, ...]
    provider_signature: bytes


# ── §27.19 redemption envelope ──────────────────────────────────────

@dataclass(frozen=True)
class AnonymousReceipt:
    """§27.19 swf.anonymous_receipt.v1 over-the-wire shape. The
    `receipt_token` is a `TicketEnvelope` with family=RECEIPT_TICKET_V1
    and scope=PROVIDER_POSITIVE_RECEIPT.

    **service_proof_hash** is required (§27.19 step 8). Without it the
    receipt is rejected as MISSING_SERVICE_PROOF — that matters because
    a receipt without a service proof can't be cross-checked against a
    real provider response, which is the only thing keeping fake
    positive receipts from being unboundedly mintable (§27.22)."""
    schema: str
    circle_id: str
    epoch_id: str
    provider_pubkey: str
    receipt_class: str
    receipt_token: TicketEnvelope
    service_proof_hash: str
    result_digest: str
    created_ms: int


# ── §27.19 issuance / redemption verdicts ───────────────────────────

@dataclass(frozen=True)
class IssueReceiptResponse:
    """§27.17 issuer's response to a peer requesting receipt tokens.
    Empty `signed_blinds` ⇒ refused (e.g. quota exhausted)."""
    issuer_key_id: str
    signed_blinds: tuple[bytes, ...] = ()
    refused_reason: str = ""


@dataclass(frozen=True)
class RedemptionVerdict:
    """§27.19 redemption result. The reputation system consumes this
    and (on `accepted=True`) bumps the provider's local score subject
    to §27.23.3 caps. On rejection, the receipt is dropped silently —
    we do NOT propagate failure back to the requester (that would be a
    side-channel into anonymity)."""
    accepted: bool
    nullifier: str = ""
    rejection: ReceiptRejection | None = None
    detail: str = ""


# ── §27.20 delivery mode enum ───────────────────────────────────────

class DeliveryMode(str, Enum):
    """§27.20 receipt delivery modes. v1 default is LOCAL_ONLY — no
    network, no privacy risk, but no durable cross-peer reputation
    signal. Other modes are stubs until the DC-net round (§27.20.4)
    and direct-encrypted (§27.20.2) paths land."""
    LOCAL_ONLY = "local_only"
    DIRECT_ENCRYPTED_TO_PROVIDER = "direct_encrypted_to_provider"
    LAN_RECEIPT_BOARD = "lan_receipt_board"
    DC_NET_RECEIPT_ROUND = "dc_net_receipt_round"


# ── ReceiptProvider Protocol ────────────────────────────────────────

@runtime_checkable
class ReceiptProvider(Protocol):
    """Drop-in interface for a Privacy Pass receipt issuer.

    Same library hook as `Issuer` for query tickets; we keep them as
    separate Protocols so a deployment can plug different libraries (or
    different quota policies) for the two families."""
    name: str

    def issuer_key(self, *, circle_id: str, epoch_id: str) -> IssuerKey: ...
    def issue(
        self,
        *,
        peer_pubkey_b64: str,
        circle_id: str,
        epoch_id: str,
        blinded_tokens: tuple[bytes, ...],
    ) -> IssueReceiptResponse: ...


# ── default null provider ───────────────────────────────────────────

class _NullReceiptProvider:
    """Default no-op. `issue()` always refuses; `issuer_key()` returns
    a zero-byte key so trust_issuer_key() doesn't hit None.

    Under this provider, `mint_receipt_tickets` always returns
    `(0, "no_crypto")`, and any receipt that somehow reaches
    `redeem_receipt` is rejected as `SIGNATURE_NOT_VERIFIED` once the
    crypto stub fires. Safe by construction."""
    name = "null"

    def issuer_key(self, *, circle_id: str, epoch_id: str) -> IssuerKey:
        return IssuerKey(
            issuer_key_id="sha256:null_receipt",
            circle_id=circle_id, epoch_id=epoch_id,
            pubkey_bytes=b"",
            valid_from_ms=0,
            valid_until_ms=10**14,
        )

    def issue(
        self,
        *,
        peer_pubkey_b64: str,
        circle_id: str,
        epoch_id: str,
        blinded_tokens: tuple[bytes, ...],
    ) -> IssueReceiptResponse:
        return IssueReceiptResponse(
            issuer_key_id="sha256:null_receipt",
            signed_blinds=(),
            refused_reason="null_provider: receipts feature flag is off "
                           "or no real provider registered",
        )


_active_provider: ReceiptProvider = _NullReceiptProvider()
# Pass-5 #8: explicit boolean instead of `isinstance(_,
# _NullReceiptProvider)` so a future subclass for code reuse (or a
# `_StubNullReceiptProvider(_NullReceiptProvider)` in tests) can't
# accidentally bypass the no-crypto guard in either direction.
_real_provider_registered: bool = False


def set_provider(p: ReceiptProvider) -> None:
    """Register a real Privacy Pass receipt provider. Idempotent."""
    global _active_provider, _real_provider_registered
    _active_provider = p
    _real_provider_registered = not isinstance(p, _NullReceiptProvider)


def get_provider() -> ReceiptProvider:
    return _active_provider


def reset_provider() -> None:
    """Restore the null provider. For tests."""
    global _active_provider, _real_provider_registered
    _active_provider = _NullReceiptProvider()
    _real_provider_registered = False


# ── feature flag ────────────────────────────────────────────────────

def _flag_enabled() -> bool:
    """`SWF_ENABLE_RECEIPTS=1` opts the flow in. Default off — every
    public method here is a no-op until set."""
    return (os.environ.get("SWF_ENABLE_RECEIPTS") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# ── §27.16 service-proof helpers ────────────────────────────────────

def service_proof_hash(proof: ServiceProof) -> str:
    """§27.16 service_proof_hash =
    H("swf.service_proof.v1" || canonical_service_proof). The
    canonical encoding pins all fields except `provider_signature` so
    the hash is stable independent of the signature scheme."""
    h = hashlib.sha256()
    h.update(b"swf.service_proof.v1")
    h.update(proof.schema.encode("utf-8"))
    h.update(proof.circle_id.encode("utf-8"))
    h.update(proof.epoch_id.encode("utf-8"))
    h.update(proof.qid.encode("utf-8"))
    h.update(proof.provider_pubkey.encode("utf-8"))
    h.update(proof.response_digest.encode("utf-8"))
    h.update(str(proof.served_at_ms).encode("ascii"))
    h.update(proof.receipt_challenge_nonce.encode("utf-8"))
    for c in proof.receipt_classes:
        h.update(b"|")
        h.update(c.encode("utf-8"))
    return f"sha256:{h.hexdigest()}"


def _is_valid_provider_pubkey(pk: str) -> bool:
    """§27.19 step 6: provider key must be syntactically valid. We
    accept the spec's canonical `ed25519:<base64>` format and refuse
    everything else. Real signature verification is downstream."""
    if not pk or len(pk) > 256:
        return False
    if not pk.startswith("ed25519:"):
        return False
    body = pk[len("ed25519:"):]
    if not body or len(body) > 200:
        return False
    # base64url alphabet (we don't decode here — that's library-level)
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    return all(ch in allowed for ch in body)


# ── §27.19 receipt nullifier ────────────────────────────────────────

def receipt_nullifier_for(envelope: TicketEnvelope) -> str:
    """§27.19 receipt nullifier =
    H("swf.receipt_ticket.nullifier.v1" || canonical_token_encoding).
    Distinct domain separation from query-ticket nullifiers so the two
    families share the same SQLite table without collision."""
    h = hashlib.sha256()
    h.update(b"swf.receipt_ticket.nullifier.v1")
    h.update(envelope.issuer_signature)
    h.update(envelope.token_body.nonce.encode("utf-8"))
    h.update(envelope.token_body.scope.encode("utf-8"))
    return f"sha256:{h.hexdigest()}"


# ── §27.17 issuance flow ────────────────────────────────────────────

def mint_receipt_tickets(
    *,
    peer_pubkey_b64: str,
    circle_id: str,
    epoch_id: str,
    count: int,
) -> tuple[int, str]:
    """Client-side: ask the active receipt provider for `count` blinded
    receipt tokens, unblind, store. Returns `(stored_count, status)`:
      "ok"          — tokens stored
      "disabled"    — flag off
      "no_crypto"   — null provider (real one not registered)
      "refused:<r>" — provider refused
    """
    if not _flag_enabled():
        return (0, "disabled")
    if count <= 0:
        return (0, "ok")

    provider = get_provider()
    if not _real_provider_registered:
        return (0, "no_crypto")

    pre_blinds = tuple(secrets.token_bytes(32) for _ in range(count))
    try:
        resp = provider.issue(
            peer_pubkey_b64=peer_pubkey_b64,
            circle_id=circle_id, epoch_id=epoch_id,
            blinded_tokens=pre_blinds,
        )
    except Exception as e:  # noqa: BLE001
        return (0, f"refused:provider_error:{type(e).__name__}")

    if not resp.signed_blinds:
        return (0, f"refused:{resp.refused_reason or 'unknown'}")

    tickets.trust_issuer_key(
        provider.issuer_key(circle_id=circle_id, epoch_id=epoch_id)
    )

    stored = 0
    now_ms = int(time.time() * 1000)
    for token_bytes in resp.signed_blinds:
        try:
            tickets.store_ticket(
                family=TicketFamily.RECEIPT_TICKET_V1,
                circle_id=circle_id,
                epoch_id=epoch_id,
                issuer_key_id=resp.issuer_key_id,
                token_bytes=token_bytes,
                issued_at_ms=now_ms,
            )
            stored += 1
        except RuntimeError:
            continue
    return (stored, "ok")


# ── §27.19 redemption flow ──────────────────────────────────────────

def redeem_receipt(
    receipt: AnonymousReceipt,
    *,
    expected_circle_id: str,
    current_epoch_id: str,
    previous_epoch_id: str | None = None,
    now_ms: int | None = None,
) -> RedemptionVerdict:
    """§27.19 verifier-side flow. Walks every check in spec order:

      1. flag enabled (else DISABLED — receipts never accepted when
         the feature is off; default-deny posture matches §27.29)
      2. envelope shape: family == RECEIPT_TICKET_V1
      3. scope == PROVIDER_POSITIVE_RECEIPT
      4. receipt_class is in the allowed enum
      5. provider_pubkey syntactically valid
      6. service_proof_hash present (§27.19 step 8)
      7. issuer key trusted for circle + epoch
      8. signature verifies (currently NotImplementedError → translated
         to SIGNATURE_NOT_VERIFIED)
      9. nullifier not already spent (atomic INSERT OR IGNORE)

    Receipt rejections are silently dropped by the caller — propagating
    failure back to the requester would be a side-channel into the
    anonymity set (§27.21)."""
    if not _flag_enabled():
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.DISABLED,
            detail="receipt feature flag disabled",
        )
    if receipt is None:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.MISSING,
            detail="no receipt provided",
        )

    env = receipt.receipt_token
    # Step 2: family.
    if env.family != TicketFamily.RECEIPT_TICKET_V1:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.WRONG_FAMILY,
            detail=f"expected RECEIPT_TICKET_V1, got {env.family.value}",
        )
    # Step 3: scope.
    if env.token_body.scope != RECEIPT_SCOPE:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.WRONG_SCOPE,
            detail=f"expected {RECEIPT_SCOPE}, got {env.token_body.scope!r}",
        )
    # Step 4: receipt class.
    if receipt.receipt_class not in _ALLOWED_RECEIPT_CLASSES:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.UNKNOWN_CLASS,
            detail=f"receipt_class {receipt.receipt_class!r} not in allowed set",
        )
    # Step 5: provider key syntactic validity.
    if not _is_valid_provider_pubkey(receipt.provider_pubkey):
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.BAD_PROVIDER_KEY,
            detail="provider_pubkey not in expected ed25519:<base64> form",
        )
    # Step 6: service_proof_hash present.
    if not receipt.service_proof_hash or \
            not receipt.service_proof_hash.startswith("sha256:"):
        return RedemptionVerdict(
            accepted=False,
            rejection=ReceiptRejection.MISSING_SERVICE_PROOF,
            detail="service_proof_hash missing or malformed",
        )
    # Step 7: also runs envelope validation, which checks
    # circle/scope/nonce/sig-presence/epoch/issuer-pin.
    rej = tickets.validate_envelope(
        env,
        expected_circle_id=expected_circle_id,
        current_epoch_id=current_epoch_id,
        previous_epoch_id=previous_epoch_id,
        expected_scope=RECEIPT_SCOPE,
        now_ms=now_ms,
    )
    if rej is not None:
        # Translate ticket rejections into receipt rejections so the
        # caller's audit log shows the receipt-side reason.
        mapped = {
            TicketRejection.WRONG_EPOCH: ReceiptRejection.WRONG_EPOCH,
            TicketRejection.UNTRUSTED_ISSUER: ReceiptRejection.UNTRUSTED_ISSUER,
            TicketRejection.INVALID: ReceiptRejection.INVALID,
        }.get(rej, ReceiptRejection.INVALID)
        return RedemptionVerdict(
            accepted=False, rejection=mapped,
            detail=f"envelope rejected: {rej.value}",
        )

    # Step 8: crypto verification. Until a Privacy Pass library is
    # plugged in, `verify_signature()` raises NotImplementedError; we
    # translate to a structured rejection so the caller never sees a
    # stack trace from a default-off path.
    issuer = tickets.get_issuer_key(
        env.issuer_key_id,
        circle_id=expected_circle_id, epoch_id=env.epoch_id,
    )
    if issuer is None:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.UNTRUSTED_ISSUER,
            detail="issuer key not in registry",
        )
    try:
        ok = tickets.verify_signature(env, issuer)
    except NotImplementedError:
        return RedemptionVerdict(
            accepted=False,
            rejection=ReceiptRejection.SIGNATURE_NOT_VERIFIED,
            detail="verify_signature stub: Privacy Pass library not "
                   "yet plugged in (see SPEC §27.10)",
        )
    except Exception as e:  # noqa: BLE001
        return RedemptionVerdict(
            accepted=False,
            rejection=ReceiptRejection.SIGNATURE_NOT_VERIFIED,
            detail=f"crypto error: {type(e).__name__}",
        )
    if not ok:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.INVALID,
            detail="signature failed verification",
        )

    # Step 9: nullifier double-spend (cross-peer registry).
    nullifier = receipt_nullifier_for(env)
    spent_at = now_ms or int(time.time() * 1000)
    fresh = tickets.try_spend_nullifier(
        nullifier,
        family=TicketFamily.RECEIPT_TICKET_V1,
        circle_id=env.circle_id,
        epoch_id=env.epoch_id,
        spent_at_ms=spent_at,
        retention_ms=DEFAULT_NULLIFIER_RETENTION_MS,
    )
    if not fresh:
        return RedemptionVerdict(
            accepted=False, rejection=ReceiptRejection.DOUBLE_SPENT,
            nullifier=nullifier,
            detail="nullifier already in spent registry",
        )
    return RedemptionVerdict(accepted=True, nullifier=nullifier)


# ── §27.21 public-board record (privacy-stripped) ──────────────────

@dataclass(frozen=True)
class PublicBoardRecord:
    """§27.21 swf.receipt_board_record.v1. ZERO requester-identifying
    fields; coarse timestamp bucket only. This is what a LAN receipt
    board (§27.20.3) is permitted to publish."""
    schema: str
    circle_id: str
    epoch_id: str
    provider_pubkey: str
    receipt_class: str
    receipt_nullifier_hash: str
    service_proof_hash: str
    accepted_at_ms_bucket: int


_DEFAULT_BUCKET_MS = 60 * 60 * 1000  # one-hour buckets


def to_public_board_record(
    receipt: AnonymousReceipt,
    *,
    nullifier: str,
    accepted_at_ms: int | None = None,
    bucket_ms: int = _DEFAULT_BUCKET_MS,
) -> PublicBoardRecord:
    """Build the §27.21 public record from an accepted receipt. Only
    fields enumerated in §27.21 are copied over; the §27.21 forbid-list
    (requester identity, raw query, qid, raw URL, full service proof,
    exact click ts, IP, device name) is enforced by construction —
    those fields literally don't exist in `PublicBoardRecord`.

    Tests pin this contract: any future field added to
    `AnonymousReceipt` must NOT silently leak into the board record."""
    accepted_at_ms = accepted_at_ms or int(time.time() * 1000)
    bucket = (accepted_at_ms // bucket_ms) * bucket_ms
    # Hash the nullifier for the public board (§27.21: not the raw
    # nullifier — the *hash* of the nullifier — so the board can detect
    # double-acceptance without exposing the nullifier itself for
    # offline correlation against a peer's spent-tickets sqlite).
    h = hashlib.sha256()
    h.update(b"swf.receipt_nullifier_hash.v1")
    h.update(nullifier.encode("utf-8"))
    nullifier_hash = f"sha256:{h.hexdigest()}"
    return PublicBoardRecord(
        schema="swf.receipt_board_record.v1",
        circle_id=receipt.circle_id,
        epoch_id=receipt.epoch_id,
        provider_pubkey=receipt.provider_pubkey,
        receipt_class=receipt.receipt_class,
        receipt_nullifier_hash=nullifier_hash,
        service_proof_hash=receipt.service_proof_hash,
        accepted_at_ms_bucket=bucket,
    )


__all__ = [
    "RECEIPT_SCOPE",
    "ReceiptClass", "ReceiptRejection", "DeliveryMode",
    "ServiceProof", "AnonymousReceipt",
    "IssueReceiptResponse", "RedemptionVerdict",
    "PublicBoardRecord",
    "ReceiptProvider",
    "set_provider", "get_provider", "reset_provider",
    "service_proof_hash", "receipt_nullifier_for",
    "mint_receipt_tickets", "redeem_receipt",
    "to_public_board_record",
]
