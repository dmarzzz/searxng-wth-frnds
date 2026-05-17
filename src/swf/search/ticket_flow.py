"""SPEC v0.3 §27.9 + §27.11 issuance + redemption flow — interface stub.

Phase 6A shipped the **data layer** (envelope dataclasses, sqlite store,
nullifier registry) in `swf.search.tickets`. This module ships the
**flow** — the orchestrator code that walks the §27.9 issuance protocol
and the §27.11 redemption protocol — without the crypto.

  * Default `_NullIssuer` mints 0 tokens and `verify_query_ticket()`
    refuses everything. With `SWF_ENABLE_TICKETS` UNSET, the flow is
    inert: callers can't issue, can't redeem, can't accidentally
    accept anything.
  * With `SWF_ENABLE_TICKETS=1` AND a real issuer registered via
    `set_issuer(...)`, the flow runs end-to-end. The crypto seam
    points at `tickets.verify_signature()` which still raises
    `NotImplementedError` — no caller can silently no-op.
  * The §27.29 invariant ("query ticket missing/invalid must NOT
    trigger public egress fallback") lives in the router; this
    module returns clear `TicketRejection` reasons that the router
    surfaces without escalating.

To plug in a real Privacy Pass library (RFC 9474 publicly-verifiable
blind RSA, or RFC 9578 VOPRF):
  1. Implement `Issuer` (Protocol).
  2. Replace the body of `tickets.verify_signature()` with the
     library's verify call (signature stays the same).
  3. Call `ticket_flow.set_issuer(my_issuer)` at swf-node boot.

Nothing else in the search router needs to change — the §29.2
invariants gate any privacy claim that depends on tickets.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from . import tickets
from .tickets import (
    DEFAULT_NULLIFIER_RETENTION_MS,
    IssuerKey,
    TicketEnvelope,
    TicketFamily,
    TicketRejection,
)

# ── §27.9 Issuance request shape ────────────────────────────────────

@dataclass(frozen=True)
class IssueRequest:
    """Client-side request to the issuer. The peer's durable identity
    authenticates this — see §27.9 step 1. The blinded tokens are
    crypto-library-dependent; we treat them as opaque bytes so the
    real-issuer plug-in can use any encoding (RSA / VOPRF / …)."""
    peer_pubkey_b64: str
    circle_id: str
    epoch_id: str
    family: TicketFamily
    blinded_tokens: tuple[bytes, ...]   # client's pre-blinded inputs
    cost_class: str = "standard_query"


@dataclass(frozen=True)
class IssueResponse:
    """Issuer's response. `signed_blinds` are 1:1 with the request's
    `blinded_tokens`. Empty list = issuance refused (e.g. quota hit,
    not a circle member)."""
    issuer_key_id: str
    signed_blinds: tuple[bytes, ...] = ()
    refused_reason: str = ""


# ── §27.11 Redemption verdict ───────────────────────────────────────

@dataclass(frozen=True)
class RedemptionVerdict:
    """Result of `verify_query_ticket()`. The router uses this to
    decide whether to admit a SEARCH_V1 onto the LAN_FRIEND_DCNET
    path. §27.29 invariant: a missing/invalid ticket must NOT trigger
    public egress fallback — the router surfaces this rejection to
    the caller without escalating."""
    accepted: bool
    nullifier: str = ""
    rejection: TicketRejection | None = None
    detail: str = ""


# ── Issuer Protocol ────────────────────────────────────────────────

@runtime_checkable
class Issuer(Protocol):
    """Drop-in interface for any real Privacy Pass implementation.

    Two halves:
      - issue(req): runs the §27.9 blind-signature protocol; returns
        signed blinds the peer unblinds locally
      - issuer_key(): returns the IssuerKey the peer should pin so
        verify_query_ticket() can later check signatures
    """
    name: str

    def issuer_key(self, *, circle_id: str, epoch_id: str) -> IssuerKey: ...
    def issue(self, req: IssueRequest) -> IssueResponse: ...


# ── default null issuer ────────────────────────────────────────────

class _NullIssuer:
    """Default no-op. `issue()` always refuses; `issuer_key()` returns
    a zero-byte key so trust_issuer_key() doesn't hit None.

    This module's `issue_query_tickets()` returns 0 tickets under the
    null issuer, so a peer's local store stays empty and any
    redemption attempt fails as `MISSING`. Safe by construction.
    """
    name = "null"

    def issuer_key(self, *, circle_id: str, epoch_id: str) -> IssuerKey:
        # Long valid_until so the row sticks around for tests; real
        # issuers SHOULD scope to the epoch boundary plus grace.
        return IssuerKey(
            issuer_key_id="sha256:null",
            circle_id=circle_id, epoch_id=epoch_id,
            pubkey_bytes=b"",
            valid_from_ms=0,
            valid_until_ms=10**14,
        )

    def issue(self, req: IssueRequest) -> IssueResponse:
        return IssueResponse(
            issuer_key_id="sha256:null",
            signed_blinds=(),
            refused_reason="null_issuer: tickets feature flag is off "
                           "or no real issuer registered",
        )


_active_issuer: Issuer = _NullIssuer()
# Pass-5 #8: explicit boolean instead of `isinstance(_, _NullIssuer)`
# so a future PR that subclasses _NullIssuer for code reuse (or a
# test-only `_StubNullIssuer(_NullIssuer)`) can't accidentally trip
# the no-crypto guard in either direction. Flipped only by set_issuer
# when the caller passes a non-Null instance.
_real_issuer_registered: bool = False


def set_issuer(i: Issuer) -> None:
    """Register a real Privacy Pass issuer. Idempotent. Calling with
    a `_NullIssuer` instance flips the registered flag back off — so
    tests can `set_issuer(_NullIssuer())` to simulate teardown."""
    global _active_issuer, _real_issuer_registered
    _active_issuer = i
    _real_issuer_registered = not isinstance(i, _NullIssuer)


def get_issuer() -> Issuer:
    return _active_issuer


def reset_issuer() -> None:
    """Restore the null issuer. For tests."""
    global _active_issuer, _real_issuer_registered
    _active_issuer = _NullIssuer()
    _real_issuer_registered = False


# ── feature flag ───────────────────────────────────────────────────

def _flag_enabled() -> bool:
    """`SWF_ENABLE_TICKETS=1` opts the flow in. Default off — every
    public method is a no-op until set."""
    return (os.environ.get("SWF_ENABLE_TICKETS") or "").strip().lower() in (
        "1", "true", "yes", "on",
    )


# ── §27.9 client-side issuance flow ───────────────────────────────

def issue_query_tickets(
    *,
    peer_pubkey_b64: str,
    circle_id: str,
    epoch_id: str,
    count: int,
    cost_class: str = "standard_query",
) -> tuple[int, str]:
    """Client-side request: produce N blinded tokens, ask the active
    issuer to sign them, unblind, store. Returns
    `(stored_count, status)` where status is one of:
      "ok"          — tokens stored locally
      "disabled"    — feature flag off
      "refused:<r>" — issuer refused (quota / not-a-member / etc.)
      "no_crypto"   — real issuer not yet registered (null issuer
                      always refuses, but we report the cause clearly)

    **Does not return the token bytes** — they live exclusively in
    the local sqlite store keyed by `peer_pubkey_b64`.
    """
    if not _flag_enabled():
        return (0, "disabled")
    if count <= 0:
        return (0, "ok")

    issuer = get_issuer()
    if not _real_issuer_registered:
        return (0, "no_crypto")

    # Generate N random pre-blind values. The real implementation
    # blinds these via the library's API; we're library-agnostic at
    # this layer.
    pre_blinds = tuple(secrets.token_bytes(32) for _ in range(count))
    req = IssueRequest(
        peer_pubkey_b64=peer_pubkey_b64,
        circle_id=circle_id,
        epoch_id=epoch_id,
        family=TicketFamily.QUERY_TICKET_V1,
        blinded_tokens=pre_blinds,
        cost_class=cost_class,
    )

    try:
        resp = issuer.issue(req)
    except Exception as e:  # noqa: BLE001
        # Issuer failure should never crash the caller; surface
        # cleanly so a wall can prompt the user to retry later.
        return (0, f"refused:issuer_error:{type(e).__name__}")

    if not resp.signed_blinds:
        return (0, f"refused:{resp.refused_reason or 'unknown'}")

    # Pin the issuer's pubkey so verify_query_ticket can look it up.
    tickets.trust_issuer_key(
        issuer.issuer_key(circle_id=circle_id, epoch_id=epoch_id)
    )

    # Persist each unblinded token. The real flow unblinds via the
    # crypto library; we just store the signed blob the issuer
    # returned. The receiver's `verify_signature()` is what gives
    # this meaning — and it's still NotImplementedError until the
    # library lands.
    stored = 0
    now_ms = int(time.time() * 1000)
    for token_bytes in resp.signed_blinds:
        try:
            tickets.store_ticket(
                family=TicketFamily.QUERY_TICKET_V1,
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


# ── §27.11 server-side redemption flow ────────────────────────────

def verify_query_ticket(
    envelope: TicketEnvelope,
    *,
    expected_circle_id: str,
    current_epoch_id: str,
    expected_scope: str,
    previous_epoch_id: str | None = None,
    spend_context: str = "",
    now_ms: int | None = None,
) -> RedemptionVerdict:
    """§27.11 verifier-side flow. Walks every check in order:

      1. flag enabled (else MISSING — we never accept tickets when
         the feature is off; that's the §27.29 default-deny posture)
      2. envelope shape valid (delegates to tickets.validate_envelope
         — circle / scope / nonce / signature / epoch / issuer-pin)
      3. signature verifies (tickets.verify_signature — currently
         raises NotImplementedError, so the verifier safely refuses
         until a real Privacy Pass library lands)
      4. nullifier not already spent (atomic INSERT OR IGNORE)

    Returns a `RedemptionVerdict`. The router consumes this and, on
    rejection, refuses the SEARCH_V1 path WITHOUT falling back to
    public egress (§27.29 — ticket failure is an authorization
    failure, not a search-insufficiency signal).
    """
    if not _flag_enabled():
        return RedemptionVerdict(
            accepted=False, rejection=TicketRejection.MISSING,
            detail="ticket feature flag disabled",
        )
    if envelope is None:
        return RedemptionVerdict(
            accepted=False, rejection=TicketRejection.MISSING,
            detail="no envelope provided",
        )

    # Step 2: non-crypto checks.
    rej = tickets.validate_envelope(
        envelope,
        expected_circle_id=expected_circle_id,
        current_epoch_id=current_epoch_id,
        previous_epoch_id=previous_epoch_id,
        expected_scope=expected_scope,
        now_ms=now_ms,
    )
    if rej is not None:
        return RedemptionVerdict(accepted=False, rejection=rej,
                                 detail=f"envelope rejected: {rej.value}")

    # Step 3: crypto verification. Currently NotImplementedError until
    # a Privacy Pass library is plugged in. Catch and translate so
    # the caller gets a structured rejection instead of a stack trace.
    issuer = tickets.get_issuer_key(
        envelope.issuer_key_id,
        circle_id=expected_circle_id, epoch_id=envelope.epoch_id,
    )
    if issuer is None:
        return RedemptionVerdict(
            accepted=False, rejection=TicketRejection.UNTRUSTED_ISSUER,
            detail="issuer key not in registry",
        )
    try:
        ok = tickets.verify_signature(envelope, issuer)
    except NotImplementedError:
        return RedemptionVerdict(
            accepted=False,
            rejection=TicketRejection.SIGNATURE_NOT_VERIFIED,
            detail="verify_signature stub: Privacy Pass library not "
                   "yet plugged in (see SPEC §27.10)",
        )
    except Exception as e:  # noqa: BLE001
        return RedemptionVerdict(
            accepted=False,
            rejection=TicketRejection.SIGNATURE_NOT_VERIFIED,
            detail=f"crypto error: {type(e).__name__}",
        )
    if not ok:
        return RedemptionVerdict(
            accepted=False, rejection=TicketRejection.INVALID,
            detail="signature failed verification",
        )

    # Step 4: nullifier double-spend check.
    nullifier = tickets.nullifier_for(envelope)
    spent_at = now_ms or int(time.time() * 1000)
    fresh = tickets.try_spend_nullifier(
        nullifier,
        family=envelope.family,
        circle_id=envelope.circle_id,
        epoch_id=envelope.epoch_id,
        spent_at_ms=spent_at,
        retention_ms=DEFAULT_NULLIFIER_RETENTION_MS,
    )
    if not fresh:
        return RedemptionVerdict(
            accepted=False, rejection=TicketRejection.DOUBLE_SPENT,
            nullifier=nullifier,
            detail="nullifier already in spent registry",
        )
    return RedemptionVerdict(accepted=True, nullifier=nullifier)


__all__ = [
    "IssueRequest", "IssueResponse", "RedemptionVerdict",
    "Issuer", "set_issuer", "get_issuer", "reset_issuer",
    "issue_query_tickets", "verify_query_ticket",
]
