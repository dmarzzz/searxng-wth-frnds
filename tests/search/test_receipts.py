"""Phase 6D — anonymous receipts interface stub.

Pins the contract:
  - default-off via SWF_ENABLE_RECEIPTS — every public method is a
    no-op until the operator opts in
  - the null provider mints 0 tokens, even with the flag set
  - `redeem_receipt()` always returns a structured `RedemptionVerdict`,
    NEVER raises (the §27.10 stub is translated into a clean rejection)
  - the §27.21 forbid-list is enforced by construction:
    `to_public_board_record()` cannot leak requester identity, raw
    query, qid, or full service proof — those fields aren't in the
    record dataclass
  - cross-family domain separation: receipt and query nullifiers share
    a sqlite table but cannot collide
"""
from __future__ import annotations

import pytest

from swf.search import receipts, tickets
from swf.search.receipts import (
    RECEIPT_SCOPE,
    AnonymousReceipt,
    DeliveryMode,
    IssueReceiptResponse,
    PublicBoardRecord,
    ReceiptClass,
    ReceiptProvider,
    ReceiptRejection,
    RedemptionVerdict,
    ServiceProof,
    _NullReceiptProvider,
    get_provider,
    mint_receipt_tickets,
    receipt_nullifier_for,
    redeem_receipt,
    reset_provider,
    service_proof_hash,
    set_provider,
    to_public_board_record,
)
from swf.search.tickets import (
    IssuerKey,
    TicketEnvelope,
    TicketFamily,
    TicketRejection,
    TokenBody,
)


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "tickets.sqlite"))
    monkeypatch.delenv("SWF_ENABLE_RECEIPTS", raising=False)
    monkeypatch.delenv("SWF_ENABLE_TICKETS", raising=False)
    reset_provider()
    yield
    reset_provider()


# ── helpers ─────────────────────────────────────────────────────────

def _receipt_envelope(
    *,
    circle_id: str = "circle_a",
    epoch_id: str = "epoch_x",
    issuer_key_id: str = "sha256:issuer-A",
    family: TicketFamily = TicketFamily.RECEIPT_TICKET_V1,
    scope: str = RECEIPT_SCOPE,
    nonce: str = "R" * 32,
    sig: bytes = b"signed-receipt-bytes",
) -> TicketEnvelope:
    return TicketEnvelope(
        family=family,
        circle_id=circle_id,
        epoch_id=epoch_id,
        issuer_key_id=issuer_key_id,
        token_body=TokenBody(nonce=nonce, scope=scope,
                             cost_class="standard_query"),
        issuer_signature=sig,
    )


def _receipt(
    *,
    circle_id: str = "circle_a",
    epoch_id: str = "epoch_x",
    provider_pubkey: str = "ed25519:AAAA-real-looking-base64-blob_",
    receipt_class: str = "useful_result",
    service_proof_hash: str = "sha256:" + "0" * 64,
    envelope: TicketEnvelope | None = None,
) -> AnonymousReceipt:
    return AnonymousReceipt(
        schema="swf.anonymous_receipt.v1",
        circle_id=circle_id,
        epoch_id=epoch_id,
        provider_pubkey=provider_pubkey,
        receipt_class=receipt_class,
        receipt_token=envelope or _receipt_envelope(
            circle_id=circle_id, epoch_id=epoch_id,
        ),
        service_proof_hash=service_proof_hash,
        result_digest="sha256:" + "f" * 64,
        created_ms=1_700_000_000_000,
    )


# ── feature flag default-off ────────────────────────────────────────

def test_mint_disabled_without_flag():
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status == "disabled"


def test_redeem_disabled_without_flag_returns_disabled():
    """§27.29-equivalent default-deny: with the feature flag off, NO
    receipt is accepted — even a perfectly-shaped one."""
    v = redeem_receipt(
        _receipt(),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
    )
    assert v.accepted is False
    assert v.rejection == ReceiptRejection.DISABLED


# ── null provider (default with flag set) ──────────────────────────

def test_null_provider_refuses_with_no_crypto_status(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status == "no_crypto"


def test_get_provider_default_is_null():
    assert isinstance(get_provider(), _NullReceiptProvider)


def test_null_provider_issue_returns_empty_blinds():
    p = _NullReceiptProvider()
    resp = p.issue(peer_pubkey_b64="pk", circle_id="c", epoch_id="e",
                   blinded_tokens=(b"x", b"y"))
    assert resp.signed_blinds == ()
    assert "null_provider" in resp.refused_reason


def test_count_zero_returns_ok_immediately(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=0,
    )
    assert (n, status) == (0, "ok")


# ── real provider happy path ───────────────────────────────────────

class _FakeRealReceiptProvider:
    """Simulates a real Privacy Pass receipt issuer. Crypto is fake;
    only the FLOW is exercised."""
    name = "fake_real_receipt"

    def __init__(self, *, key_id: str = "sha256:fake-receipt",
                 quota_per_request: int | None = None):
        self.key_id = key_id
        self.quota = quota_per_request

    def issuer_key(self, *, circle_id, epoch_id):
        return IssuerKey(
            issuer_key_id=self.key_id,
            circle_id=circle_id, epoch_id=epoch_id,
            pubkey_bytes=b"FAKE-RECEIPT-PUBKEY-32-BYTES_OK!",
            valid_from_ms=0, valid_until_ms=10**14,
        )

    def issue(self, *, peer_pubkey_b64, circle_id, epoch_id, blinded_tokens):
        if self.quota is not None and len(blinded_tokens) > self.quota:
            return IssueReceiptResponse(
                issuer_key_id=self.key_id, signed_blinds=(),
                refused_reason="quota_exhausted",
            )
        signed = tuple(b + b"<receipt-sig>" for b in blinded_tokens)
        return IssueReceiptResponse(
            issuer_key_id=self.key_id, signed_blinds=signed,
        )


def test_real_provider_stores_n_tokens(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    set_provider(_FakeRealReceiptProvider())
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=5,
    )
    assert n == 5
    assert status == "ok"


def test_real_provider_quota_refusal(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    set_provider(_FakeRealReceiptProvider(quota_per_request=2))
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status.startswith("refused:")
    assert "quota" in status


def test_real_provider_pins_issuer_key_after_issuance(monkeypatch):
    """First successful issuance pins the issuer's pubkey via
    `tickets.trust_issuer_key()`."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    set_provider(_FakeRealReceiptProvider())
    mint_receipt_tickets(peer_pubkey_b64="pk",
                         circle_id="c", epoch_id="e", count=1)
    pinned = tickets.get_issuer_key("sha256:fake-receipt",
                                    circle_id="c", epoch_id="e")
    assert pinned is not None
    assert pinned.pubkey_bytes == b"FAKE-RECEIPT-PUBKEY-32-BYTES_OK!"


def test_provider_exception_returns_clean_status(monkeypatch):
    class _Boom:
        name = "boom"
        def issuer_key(self, **kw): raise RuntimeError("boom")
        def issue(self, **kw): raise RuntimeError("boom")
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    set_provider(_Boom())
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=3,
    )
    assert n == 0
    assert status.startswith("refused:provider_error:")


# ── redemption: per-spec §27.19 step ordering ───────────────────────

def test_redeem_no_envelope_returns_missing(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        None,  # type: ignore[arg-type]
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.MISSING


def test_redeem_wrong_family_rejected(monkeypatch):
    """Step 2: a query ticket envelope handed to receipt redemption
    must be rejected as WRONG_FAMILY — receipts and queries are
    different scarcity pools."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    bad_env = _receipt_envelope(family=TicketFamily.QUERY_TICKET_V1)
    v = redeem_receipt(
        _receipt(envelope=bad_env),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.WRONG_FAMILY


def test_redeem_wrong_scope_rejected(monkeypatch):
    """Step 3: scope must be PROVIDER_POSITIVE_RECEIPT."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(envelope=_receipt_envelope(scope="LAN_FRIEND_DCNET")),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.WRONG_SCOPE


def test_redeem_unknown_class_rejected(monkeypatch):
    """Step 4: receipt_class must be in the §27.18 enum. Crucially,
    NO negative class should ever be accepted in v1."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(receipt_class="negative_garbage"),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.UNKNOWN_CLASS


@pytest.mark.parametrize("bad_pk", [
    "",
    "ed25519:",            # empty body
    "ssh-rsa:abc",         # wrong scheme
    "ed25519:abc!@#",      # disallowed chars
    "ed25519:" + "A" * 300,  # too long
])
def test_redeem_bad_provider_pubkey_rejected(monkeypatch, bad_pk):
    """Step 5: provider key must look like ed25519:<base64>."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(provider_pubkey=bad_pk),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.BAD_PROVIDER_KEY


def test_redeem_missing_service_proof_rejected(monkeypatch):
    """Step 6: service_proof_hash is required (§27.19 step 8). Without
    it, fake positive receipts could be minted unboundedly (§27.22)."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(service_proof_hash=""),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.MISSING_SERVICE_PROOF


def test_redeem_wrong_circle_rejected(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(circle_id="circle_a",
                 envelope=_receipt_envelope(circle_id="circle_a")),
        expected_circle_id="circle_b", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.INVALID


def test_redeem_wrong_epoch_rejected(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(envelope=_receipt_envelope(epoch_id="ancient")),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.WRONG_EPOCH


def test_redeem_unknown_issuer_rejected(monkeypatch):
    """Step 7: issuer key must be pinned for (circle, epoch)."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    v = redeem_receipt(
        _receipt(),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.rejection == ReceiptRejection.UNTRUSTED_ISSUER


def test_redeem_pinned_issuer_hits_signature_stub(monkeypatch):
    """Step 8: with everything else valid, redemption reaches the
    `tickets.verify_signature()` stub which raises NotImplementedError.
    The flow must translate that into a structured rejection rather
    than letting it propagate."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    tickets.trust_issuer_key(IssuerKey(
        issuer_key_id="sha256:issuer-A",
        circle_id="circle_a", epoch_id="epoch_x",
        pubkey_bytes=b"P" * 32,
        valid_from_ms=0, valid_until_ms=10**14,
    ))
    v = redeem_receipt(
        _receipt(),
        expected_circle_id="circle_a", current_epoch_id="epoch_x",
    )
    assert v.accepted is False
    assert v.rejection == ReceiptRejection.SIGNATURE_NOT_VERIFIED
    assert "Privacy Pass library" in v.detail


# ── nullifier domain separation ─────────────────────────────────────

def test_receipt_and_query_nullifiers_differ_for_same_envelope():
    """The two nullifier constructions use distinct domain-separation
    prefixes. Even with an identical envelope (different family), the
    nullifiers MUST NOT collide — otherwise a receipt and a query
    ticket could clash in the shared spent-nullifier table."""
    env = _receipt_envelope()
    n_receipt = receipt_nullifier_for(env)
    n_query = tickets.nullifier_for(env)
    assert n_receipt != n_query
    assert n_receipt.startswith("sha256:")
    assert n_query.startswith("sha256:")


def test_receipt_nullifier_is_deterministic():
    env = _receipt_envelope()
    assert receipt_nullifier_for(env) == receipt_nullifier_for(env)


# ── §27.21 public-board record: privacy by construction ────────────

def test_public_board_record_has_no_requester_fields():
    """§27.21: the board record MUST NOT carry requester identity,
    raw query, qid, raw URL, full service proof, exact timestamp.
    `PublicBoardRecord` is a frozen dataclass — those fields literally
    don't exist on it. This test pins the dataclass shape so a future
    change can't sneak a leak in."""
    field_names = set(PublicBoardRecord.__dataclass_fields__.keys())
    forbidden = {
        "requester_id", "requester_pubkey", "peer_pubkey",
        "raw_query", "query", "qid",
        "result_url", "raw_url",
        "full_service_proof", "service_proof",
        "click_ts_ms", "exact_accepted_at_ms",
        "ip_address", "ip", "device_name",
    }
    leaked = forbidden & field_names
    assert leaked == set(), f"PublicBoardRecord leaks: {leaked}"


def test_public_board_record_buckets_timestamp():
    """§27.21: coarse timestamp buckets only. With 1-hour buckets, two
    receipts within the same hour must produce the same bucket value."""
    r = _receipt()
    rec_a = to_public_board_record(r, nullifier="sha256:n1",
                                    accepted_at_ms=1_700_000_000_000)
    rec_b = to_public_board_record(r, nullifier="sha256:n2",
                                    accepted_at_ms=1_700_000_000_000 + 60_000)
    # Same hour bucket.
    assert rec_a.accepted_at_ms_bucket == rec_b.accepted_at_ms_bucket
    # And the bucket must be aligned.
    assert rec_a.accepted_at_ms_bucket % (60 * 60 * 1000) == 0


def test_public_board_record_hashes_nullifier():
    """§27.21 stores the *hash* of the nullifier on public boards, not
    the raw nullifier — that prevents offline correlation against a
    peer's local spent-tickets sqlite."""
    r = _receipt()
    rec = to_public_board_record(r, nullifier="sha256:n1",
                                 accepted_at_ms=1_700_000_000_000)
    assert rec.receipt_nullifier_hash != "sha256:n1"
    assert rec.receipt_nullifier_hash.startswith("sha256:")


# ── service-proof hash determinism ──────────────────────────────────

def test_service_proof_hash_independent_of_signature():
    """§27.16: the service_proof_hash covers a canonical encoding that
    excludes `provider_signature`. Two proofs with different signatures
    but identical body must hash the same."""
    base = ServiceProof(
        schema="swf.provider_service_proof.v1",
        circle_id="c", epoch_id="e", qid="q",
        provider_pubkey="ed25519:abc",
        response_digest="sha256:abc",
        served_at_ms=1,
        receipt_challenge_nonce="n",
        receipt_classes=("useful_result",),
        provider_signature=b"sig-v1",
    )
    other = ServiceProof(**{**base.__dict__, "provider_signature": b"sig-v2"})
    assert service_proof_hash(base) == service_proof_hash(other)


def test_service_proof_hash_changes_with_body_field():
    base = ServiceProof(
        schema="swf.provider_service_proof.v1",
        circle_id="c", epoch_id="e", qid="q",
        provider_pubkey="ed25519:abc",
        response_digest="sha256:abc",
        served_at_ms=1,
        receipt_challenge_nonce="n",
        receipt_classes=("useful_result",),
        provider_signature=b"sig-v1",
    )
    other = ServiceProof(**{**base.__dict__, "qid": "different-qid"})
    assert service_proof_hash(base) != service_proof_hash(other)


# ── never-raise contract ───────────────────────────────────────────

def test_redeem_never_raises_under_pathological_inputs(monkeypatch):
    """Every public method here returns a structured verdict, never
    propagates an exception. The reputation system relies on this so a
    misbehaving peer can't poison the receipt-acceptance loop."""
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    cases = [
        # missing envelope
        (None, "circle_a", "epoch_x"),
        # wrong family
        (_receipt(envelope=_receipt_envelope(family=TicketFamily.QUERY_TICKET_V1)),
         "circle_a", "epoch_x"),
        # wrong scope
        (_receipt(envelope=_receipt_envelope(scope="other")),
         "circle_a", "epoch_x"),
        # short nonce
        (_receipt(envelope=_receipt_envelope(nonce="x")),
         "circle_a", "epoch_x"),
        # bad provider key
        (_receipt(provider_pubkey="garbage"), "circle_a", "epoch_x"),
        # missing service-proof hash
        (_receipt(service_proof_hash=""), "circle_a", "epoch_x"),
        # bad receipt class
        (_receipt(receipt_class="not-an-enum"), "circle_a", "epoch_x"),
    ]
    for r, cid, eid in cases:
        v = redeem_receipt(r, expected_circle_id=cid, current_epoch_id=eid)
        assert v.accepted is False
        assert v.rejection is not None
        assert isinstance(v.detail, str)


# ── Protocol conformance ───────────────────────────────────────────

def test_null_provider_satisfies_protocol():
    assert isinstance(_NullReceiptProvider(), ReceiptProvider)
    assert isinstance(_FakeRealReceiptProvider(), ReceiptProvider)


# ── enum closure: no negative classes in v1 ────────────────────────

def test_no_negative_receipt_classes_in_enum():
    """§27.18 explicitly says no negative receipt classes in v1.
    A future PR adding NEGATIVE_* needs to fail this test on purpose
    and force a conscious review."""
    for c in ReceiptClass:
        assert "negative" not in c.value
        assert "spam" not in c.value
        assert "bad" not in c.value


def test_delivery_mode_default_is_local_only():
    """§27.20.1: the safest mode is local-only. We don't pin a default
    in the redeem flow (the redeemer is the receipt-acceptor, not the
    sender), but the LOCAL_ONLY enum value MUST exist as the safe
    fallback."""
    assert DeliveryMode.LOCAL_ONLY.value == "local_only"
