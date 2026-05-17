"""Phase 6A ticket data layer tests.

The crypto IS NOT implemented (per spec §27.10); we test only the
storage, atomic spend, issuer-key registry, and non-crypto envelope
validation. `verify_signature()` is asserted to raise.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from swf.search import tickets
from swf.search.tickets import (
    IssuerKey,
    TicketEnvelope,
    TicketFamily,
    TicketRejection,
    TokenBody,
    epoch_acceptable,
    get_issuer_key,
    is_spent,
    list_available,
    mark_spent,
    nullifier_for,
    store_ticket,
    trust_issuer_key,
    try_spend_nullifier,
    vacuum_expired_nullifiers,
    validate_envelope,
    verify_signature,
)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "tickets.sqlite"))
    yield


def _envelope(*, circle_id="circle_a", epoch_id="epoch_2026-04-29",
              issuer_key_id="sha256:abc", scope="LAN_FRIEND_DCNET",
              nonce="A" * 32, sig=b"signed-bytes") -> TicketEnvelope:
    return TicketEnvelope(
        family=TicketFamily.QUERY_TICKET_V1,
        circle_id=circle_id,
        epoch_id=epoch_id,
        issuer_key_id=issuer_key_id,
        token_body=TokenBody(nonce=nonce, scope=scope, cost_class="standard_query"),
        issuer_signature=sig,
    )


def _issuer(*, issuer_key_id="sha256:abc",
            circle_id="circle_a",
            epoch_id="epoch_2026-04-29") -> IssuerKey:
    return IssuerKey(
        issuer_key_id=issuer_key_id, circle_id=circle_id, epoch_id=epoch_id,
        pubkey_bytes=b"pubkey-bytes-32-mock-aaaaaaaaaaaa",
        valid_from_ms=0, valid_until_ms=10**14,
    )


# ─── ticket store ─────────────────────────────────────────────────────

def test_store_and_list_round_trip():
    tid = store_ticket(
        family=TicketFamily.QUERY_TICKET_V1,
        circle_id="circle_a", epoch_id="epoch_x",
        issuer_key_id="sha256:abc",
        token_bytes=b"token-bytes-1",
    )
    assert tid > 0
    rows = list_available(family=TicketFamily.QUERY_TICKET_V1,
                          circle_id="circle_a", epoch_id="epoch_x")
    assert len(rows) == 1
    assert rows[0]["id"] == tid


def test_store_dedupes_by_token_hash():
    a = store_ticket(family=TicketFamily.QUERY_TICKET_V1,
                     circle_id="c", epoch_id="e",
                     issuer_key_id="i", token_bytes=b"same-bytes")
    b = store_ticket(family=TicketFamily.QUERY_TICKET_V1,
                     circle_id="c", epoch_id="e",
                     issuer_key_id="i", token_bytes=b"same-bytes")
    assert a == b   # same row returned, not a duplicate


def test_mark_spent_only_succeeds_once():
    tid = store_ticket(family=TicketFamily.QUERY_TICKET_V1,
                       circle_id="c", epoch_id="e",
                       issuer_key_id="i", token_bytes=b"bytes")
    assert mark_spent(tid, spend_context="ctx-1") is True
    # Second attempt fails because the WHERE clause requires available status
    assert mark_spent(tid, spend_context="ctx-2") is False


# ─── nullifier registry: atomic double-spend prevention ──────────────

def test_try_spend_nullifier_first_call_succeeds():
    ok = try_spend_nullifier("sha256:nullifier-1",
                              family=TicketFamily.QUERY_TICKET_V1,
                              circle_id="c", epoch_id="e")
    assert ok is True


def test_try_spend_nullifier_double_spend_blocked():
    n = "sha256:nullifier-double"
    assert try_spend_nullifier(n, family=TicketFamily.QUERY_TICKET_V1,
                               circle_id="c", epoch_id="e") is True
    assert try_spend_nullifier(n, family=TicketFamily.QUERY_TICKET_V1,
                               circle_id="c", epoch_id="e") is False
    assert is_spent(n) is True


def test_empty_nullifier_rejected():
    assert try_spend_nullifier("", family=TicketFamily.QUERY_TICKET_V1,
                               circle_id="c", epoch_id="e") is False


def test_vacuum_expired_drops_old_entries():
    assert try_spend_nullifier("n1", family=TicketFamily.QUERY_TICKET_V1,
                                circle_id="c", epoch_id="e",
                                retention_ms=0)
    n_dropped = vacuum_expired_nullifiers()
    assert n_dropped >= 1
    assert is_spent("n1") is False  # vacuumed


# ─── issuer key registry ────────────────────────────────────────────

def test_trust_and_get_issuer_round_trip():
    k = _issuer()
    trust_issuer_key(k)
    fetched = get_issuer_key(k.issuer_key_id,
                             circle_id=k.circle_id, epoch_id=k.epoch_id)
    assert fetched is not None
    assert fetched.pubkey_bytes == k.pubkey_bytes


def test_unknown_issuer_returns_none():
    assert get_issuer_key("sha256:never", circle_id="c", epoch_id="e") is None


# ─── envelope validation (no crypto) ────────────────────────────────

def test_validate_envelope_happy_path():
    trust_issuer_key(_issuer())
    env = _envelope()
    assert validate_envelope(
        env,
        expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
        expected_scope="LAN_FRIEND_DCNET",
    ) is None


def test_validate_envelope_wrong_circle_rejected():
    trust_issuer_key(_issuer())
    env = _envelope(circle_id="circle_b")
    assert validate_envelope(
        env, expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
    ) == TicketRejection.INVALID


def test_validate_envelope_wrong_scope_rejected():
    trust_issuer_key(_issuer())
    env = _envelope(scope="UNRELATED_SCOPE")
    assert validate_envelope(
        env, expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
        expected_scope="LAN_FRIEND_DCNET",
    ) == TicketRejection.INVALID


def test_validate_envelope_wrong_epoch_rejected():
    trust_issuer_key(_issuer(epoch_id="epoch_2026-04-29"))
    env = _envelope(epoch_id="epoch_2026-04-29")
    res = validate_envelope(
        env,
        expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-30",  # current is different
        previous_epoch_id="epoch_2026-04-28",  # but ticket is from a yet-earlier
    )
    assert res == TicketRejection.WRONG_EPOCH


def test_validate_envelope_previous_epoch_within_grace_ok():
    trust_issuer_key(_issuer(epoch_id="epoch_old"))
    env = _envelope(epoch_id="epoch_old")
    res = validate_envelope(
        env,
        expected_circle_id="circle_a",
        current_epoch_id="epoch_new",
        previous_epoch_id="epoch_old",
        grace_ms=60_000,
        epoch_started_ms=1000, now_ms=1500,  # 500ms into new epoch — within grace
    )
    assert res is None


def test_validate_envelope_previous_epoch_past_grace_rejected():
    trust_issuer_key(_issuer(epoch_id="epoch_old"))
    env = _envelope(epoch_id="epoch_old")
    res = validate_envelope(
        env,
        expected_circle_id="circle_a",
        current_epoch_id="epoch_new",
        previous_epoch_id="epoch_old",
        grace_ms=60_000,
        epoch_started_ms=1000, now_ms=200_000,  # 199s into new epoch — past grace
    )
    assert res == TicketRejection.WRONG_EPOCH


def test_validate_envelope_unknown_issuer_rejected():
    """Don't trust the issuer key — registry has no row for it."""
    env = _envelope()
    res = validate_envelope(
        env, expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
    )
    assert res == TicketRejection.UNTRUSTED_ISSUER


def test_validate_envelope_short_nonce_rejected():
    trust_issuer_key(_issuer())
    env = _envelope(nonce="too-short")
    res = validate_envelope(
        env, expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
    )
    assert res == TicketRejection.INVALID


def test_validate_envelope_empty_signature_rejected():
    trust_issuer_key(_issuer())
    env = _envelope(sig=b"")
    res = validate_envelope(
        env, expected_circle_id="circle_a",
        current_epoch_id="epoch_2026-04-29",
    )
    assert res == TicketRejection.INVALID


# ─── nullifier construction ─────────────────────────────────────────

def test_nullifier_is_deterministic_per_envelope():
    a = _envelope()
    b = _envelope()
    assert nullifier_for(a) == nullifier_for(b)


def test_nullifier_changes_with_signature():
    a = _envelope(sig=b"sig-1")
    b = _envelope(sig=b"sig-2")
    assert nullifier_for(a) != nullifier_for(b)


def test_nullifier_format_is_sha256():
    n = nullifier_for(_envelope())
    assert n.startswith("sha256:")
    assert len(n) == len("sha256:") + 64


# ─── crypto stub raises ─────────────────────────────────────────────

def test_verify_signature_raises_not_implemented():
    """Spec §27.10: the actual blind-signature verification needs a
    vetted Privacy Pass library. We MUST NOT silently accept tickets;
    this stub raises so any caller that forgets is caught loudly."""
    with pytest.raises(NotImplementedError, match="Privacy Pass"):
        verify_signature(_envelope(), _issuer())


# ─── envelope round-trip ────────────────────────────────────────────

def test_envelope_to_dict_shape_matches_spec():
    env = _envelope()
    d = env.to_dict()
    assert d["family"] == "QUERY_TICKET_V1"
    assert d["circle_id"] == "circle_a"
    assert d["token_body"]["scope"] == "LAN_FRIEND_DCNET"
    assert "issuer_signature_b64" in d
    assert "issuer_signature" not in d  # bytes never escape directly


# ─── epoch helper ───────────────────────────────────────────────────

def test_epoch_acceptable_current_always():
    assert epoch_acceptable("e1", current_epoch_id="e1") is True


def test_epoch_acceptable_unrelated_rejected():
    assert epoch_acceptable("e0", current_epoch_id="e1") is False
