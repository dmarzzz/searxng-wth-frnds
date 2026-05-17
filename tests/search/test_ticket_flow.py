"""Phase 6B/C — issuance + redemption flow.

Pins the contract:
  - default-off via SWF_ENABLE_TICKETS — every public method is a
    no-op until the operator opts in
  - null issuer mints 0 tokens, even with the flag set
  - redemption refuses with structured `TicketRejection` reasons,
    NEVER raising and NEVER falling through to public egress
  - the §27.29 default-deny posture: a missing/invalid ticket is
    NOT a search-insufficiency signal
"""
from __future__ import annotations

from pathlib import Path

import pytest

from swf.search import ticket_flow, tickets
from swf.search.ticket_flow import (
    IssueRequest,
    IssueResponse,
    RedemptionVerdict,
    _NullIssuer,
    get_issuer,
    issue_query_tickets,
    reset_issuer,
    set_issuer,
    verify_query_ticket,
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
    monkeypatch.delenv("SWF_ENABLE_TICKETS", raising=False)
    reset_issuer()
    yield
    reset_issuer()


def _envelope(*, circle_id="circle_a", epoch_id="epoch_x",
              issuer_key_id="sha256:issuer-A",
              scope="LAN_FRIEND_DCNET",
              nonce="A" * 32, sig=b"signed-bytes") -> TicketEnvelope:
    return TicketEnvelope(
        family=TicketFamily.QUERY_TICKET_V1,
        circle_id=circle_id,
        epoch_id=epoch_id,
        issuer_key_id=issuer_key_id,
        token_body=TokenBody(nonce=nonce, scope=scope,
                             cost_class="standard_query"),
        issuer_signature=sig,
    )


# ─── feature flag default-off ──────────────────────────────────────

def test_issue_disabled_without_flag():
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status == "disabled"


def test_verify_disabled_without_flag_returns_missing():
    """§27.29 default-deny: with the feature flag off, NO envelope is
    accepted. Even a perfectly-shaped one must come back as MISSING."""
    v = verify_query_ticket(
        _envelope(),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.accepted is False
    assert v.rejection == TicketRejection.MISSING
    assert "disabled" in v.detail


# ─── null issuer (default with flag set) ───────────────────────────

def test_null_issuer_refuses_with_no_crypto_status(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    # No real issuer registered → default _NullIssuer.
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status == "no_crypto"


def test_get_issuer_default_is_null():
    assert isinstance(get_issuer(), _NullIssuer)


def test_null_issuer_issue_returns_empty_blinds():
    issuer = _NullIssuer()
    resp = issuer.issue(IssueRequest(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e",
        family=TicketFamily.QUERY_TICKET_V1,
        blinded_tokens=(b"x", b"y"),
    ))
    assert resp.signed_blinds == ()
    assert "null_issuer" in resp.refused_reason


# ─── real issuer happy path ────────────────────────────────────────

class _FakeRealIssuer:
    """Simulates a real Privacy Pass issuer that signs blinds. The
    crypto is fake (concat(blind, b'<sig>')) — the test only covers
    the FLOW, not signature verification (which still raises
    NotImplementedError per §27.10)."""
    name = "fake_real"

    def __init__(self, *, key_id: str = "sha256:fake-real",
                 quota_per_request: int | None = None):
        self.key_id = key_id
        self.quota = quota_per_request

    def issuer_key(self, *, circle_id, epoch_id):
        return IssuerKey(
            issuer_key_id=self.key_id,
            circle_id=circle_id, epoch_id=epoch_id,
            pubkey_bytes=b"FAKE-PUBKEY-32-BYTES-PLACEHOLDER!",
            valid_from_ms=0, valid_until_ms=10**14,
        )

    def issue(self, req):
        if self.quota is not None and len(req.blinded_tokens) > self.quota:
            return IssueResponse(issuer_key_id=self.key_id,
                                 signed_blinds=(),
                                 refused_reason="quota_exhausted")
        # "Sign" by concatenating; real impl uses RSA / VOPRF.
        signed = tuple(b + b"<sig>" for b in req.blinded_tokens)
        return IssueResponse(issuer_key_id=self.key_id,
                             signed_blinds=signed)


def test_real_issuer_stores_n_tokens(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    set_issuer(_FakeRealIssuer())
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=5,
    )
    assert n == 5
    assert status == "ok"


def test_real_issuer_quota_refusal(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    set_issuer(_FakeRealIssuer(quota_per_request=2))
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=10,
    )
    assert n == 0
    assert status.startswith("refused:")
    assert "quota" in status


def test_real_issuer_pins_issuer_key_after_issuance(monkeypatch):
    """First successful issuance pins the issuer's pubkey via
    `tickets.trust_issuer_key()` so verify_query_ticket() can later
    look it up."""
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    set_issuer(_FakeRealIssuer())
    issue_query_tickets(peer_pubkey_b64="pk",
                        circle_id="c", epoch_id="e", count=1)
    pinned = tickets.get_issuer_key("sha256:fake-real",
                                     circle_id="c", epoch_id="e")
    assert pinned is not None
    assert pinned.pubkey_bytes == b"FAKE-PUBKEY-32-BYTES-PLACEHOLDER!"


def test_issuer_exception_returns_clean_status(monkeypatch):
    """Any uncaught issuer exception must NOT crash the caller — we
    return a structured `refused:issuer_error:...` status."""
    class _Boom:
        name = "boom"
        def issuer_key(self, **kw): raise RuntimeError("boom")
        def issue(self, req): raise RuntimeError("boom")
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    set_issuer(_Boom())
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=3,
    )
    assert n == 0
    assert status.startswith("refused:issuer_error:")


def test_count_zero_returns_ok_immediately(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=0,
    )
    assert (n, status) == (0, "ok")


# ─── redemption flow ───────────────────────────────────────────────

def test_verify_with_unknown_issuer_returns_untrusted(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    v = verify_query_ticket(
        _envelope(),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.accepted is False
    assert v.rejection == TicketRejection.UNTRUSTED_ISSUER


def test_verify_pinned_issuer_hits_signature_stub(monkeypatch):
    """With the feature flag on AND the issuer pinned, verification
    reaches `tickets.verify_signature()` which still raises
    `NotImplementedError`. The flow translates that into a clean
    `SIGNATURE_NOT_VERIFIED` rejection rather than letting the
    exception propagate."""
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    tickets.trust_issuer_key(IssuerKey(
        issuer_key_id="sha256:issuer-A",
        circle_id="circle_a", epoch_id="epoch_x",
        pubkey_bytes=b"P" * 32,
        valid_from_ms=0, valid_until_ms=10**14,
    ))
    v = verify_query_ticket(
        _envelope(),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.accepted is False
    assert v.rejection == TicketRejection.SIGNATURE_NOT_VERIFIED
    assert "Privacy Pass library" in v.detail


def test_verify_wrong_circle_short_circuits_before_crypto(monkeypatch):
    """Envelope checks run before signature verification. A wrong
    `circle_id` fails as INVALID — the crypto stub is not reached."""
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    v = verify_query_ticket(
        _envelope(circle_id="circle_a"),
        expected_circle_id="circle_b",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.rejection == TicketRejection.INVALID


def test_verify_wrong_scope_short_circuits(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    v = verify_query_ticket(
        _envelope(scope="UNRELATED"),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.rejection == TicketRejection.INVALID


def test_verify_wrong_epoch_short_circuits(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    v = verify_query_ticket(
        _envelope(epoch_id="ancient"),
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.rejection == TicketRejection.WRONG_EPOCH


def test_verify_no_envelope_returns_missing(monkeypatch):
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    v = verify_query_ticket(
        None,  # type: ignore[arg-type]
        expected_circle_id="circle_a",
        current_epoch_id="epoch_x",
        expected_scope="LAN_FRIEND_DCNET",
    )
    assert v.rejection == TicketRejection.MISSING


# ─── §27.29 default-deny: ticket failure does NOT trigger fallback ─

def test_ticket_failure_returns_clean_rejection_no_exception(monkeypatch):
    """The single most important post-condition: every ticket failure
    returns a `RedemptionVerdict` with `accepted=False` and a
    structured rejection. Never raises. The router relies on this
    contract to enforce §27.29 (ticket failure ≠ public-egress
    fallback signal)."""
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    # Try every constructor path that could go wrong.
    cases = [
        # missing envelope
        (None, "circle_a", "epoch_x", "LAN_FRIEND_DCNET"),
        # wrong circle
        (_envelope(circle_id="other"), "circle_a", "epoch_x", "LAN_FRIEND_DCNET"),
        # wrong scope
        (_envelope(scope="other"), "circle_a", "epoch_x", "LAN_FRIEND_DCNET"),
        # short nonce
        (_envelope(nonce="x"), "circle_a", "epoch_x", "LAN_FRIEND_DCNET"),
    ]
    for env, cid, eid, scope in cases:
        v = verify_query_ticket(
            env, expected_circle_id=cid,
            current_epoch_id=eid, expected_scope=scope,
        )
        assert v.accepted is False
        assert v.rejection is not None
        assert isinstance(v.detail, str)


# ─── Protocol conformance ─────────────────────────────────────────

def test_null_issuer_satisfies_protocol():
    from swf.search.ticket_flow import Issuer
    assert isinstance(_NullIssuer(), Issuer)
    assert isinstance(_FakeRealIssuer(), Issuer)
