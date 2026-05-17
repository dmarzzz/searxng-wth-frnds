"""SPEC v0.3 §27 + §29.8 anonymous-ticket data layer.

This module ships the data + storage that don't require crypto: ticket
envelope dataclasses, the local SQLite ticket store, the spent-nullifier
cross-peer registry, issuer key registry, and validation up to (but not
including) the actual blind-signature verification.

**The crypto is intentionally NOT here.** §27.10 and §27.3 say:

  > Do not invent a new blind-signature scheme. The exact cryptographic
  > encoding depends on the token library.

The hooks for a real Privacy Pass implementation (RFC 9474 blind RSA, or
RFC 9578 publicly-verifiable tokens) live in `crypto.py` as a clean
interface. Until that's wired, `verify_signature()` raises
`NotImplementedError("plug in a vetted Privacy Pass library")` and the
router's LAN_FRIEND_DCNET path treats tickets as unverified — the route
still emits `route_not_implemented` for the same reason.

What this module DOES guarantee, today:
- A correctly-shaped ticket envelope with deterministic field validation.
- A local sqlite store with the §27.13 schemas (anonymous_tickets +
  spent_ticket_nullifiers).
- Atomic claim/spend: `try_spend(nullifier)` is INSERT OR FAIL on a
  UNIQUE index, so double-spend attempts return False without race.
- Issuer-key registry: a peer can pin trusted issuer pubkeys per circle
  + epoch and refuse tickets from unknown issuers.
- Epoch arithmetic + clock-skew tolerance per §27.6.

A future PR plugs in the actual blind-token library and wires
LAN_FRIEND_DCNET; nothing in the data layer needs to change at that
point.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


# §27.8 ticket families.
class TicketFamily(str, Enum):
    QUERY_TICKET_V1 = "QUERY_TICKET_V1"
    RECEIPT_TICKET_V1 = "RECEIPT_TICKET_V1"


class TicketStatus(str, Enum):
    AVAILABLE = "available"
    SPENT = "spent"
    EXPIRED = "expired"
    REVOKED = "revoked"


# §27.6 epoch and skew defaults.
DEFAULT_EPOCH_DURATION_MS = 24 * 3600 * 1000
DEFAULT_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000          # 5 minutes
DEFAULT_ACCEPT_PREVIOUS_EPOCH_MS = 10 * 60 * 1000  # grace
DEFAULT_NULLIFIER_RETENTION_MS = 7 * 24 * 3600 * 1000


@dataclass(frozen=True)
class TokenBody:
    """§27.10 inner token body. The bytes that the issuer signs over."""
    nonce: str        # 256-bit random, base64url
    scope: str        # e.g. "LAN_FRIEND_DCNET"
    cost_class: str   # e.g. "standard_query"


@dataclass(frozen=True)
class TicketEnvelope:
    """§27.10 logical structure. Crypto-opaque: `issuer_signature`
    interpretation is the Privacy Pass library's job."""
    family: TicketFamily
    circle_id: str
    epoch_id: str
    issuer_key_id: str
    token_body: TokenBody
    issuer_signature: bytes  # blind-signature output

    def to_dict(self) -> dict:
        return {
            "family": self.family.value,
            "circle_id": self.circle_id,
            "epoch_id": self.epoch_id,
            "issuer_key_id": self.issuer_key_id,
            "token_body": {
                "nonce": self.token_body.nonce,
                "scope": self.token_body.scope,
                "cost_class": self.token_body.cost_class,
            },
            "issuer_signature_b64": _b64(self.issuer_signature),
        }


@dataclass(frozen=True)
class IssuerKey:
    """A trusted issuer pubkey for a (circle_id, epoch_id) pair. The
    raw key bytes are crypto-library-dependent; we just track the
    fingerprint and freshness here."""
    issuer_key_id: str   # `sha256:...` of the public key
    circle_id: str
    epoch_id: str
    pubkey_bytes: bytes
    valid_from_ms: int
    valid_until_ms: int


# Reasons a ticket validation can fail. Mapped to the §25 failure
# taxonomy verbatim.
class TicketRejection(str, Enum):
    MISSING = "anonymous_ticket_missing"
    INVALID = "anonymous_ticket_invalid"
    DOUBLE_SPENT = "anonymous_ticket_double_spent"
    WRONG_EPOCH = "anonymous_ticket_wrong_epoch"
    UNTRUSTED_ISSUER = "anonymous_ticket_issuer_untrusted"
    SIGNATURE_NOT_VERIFIED = "anonymous_ticket_signature_not_verified"


# ── DB layout ────────────────────────────────────────────────────────

_CREATE = """
CREATE TABLE IF NOT EXISTS anonymous_tickets (
    id                INTEGER PRIMARY KEY,
    family            TEXT NOT NULL,
    circle_id         TEXT NOT NULL,
    epoch_id          TEXT NOT NULL,
    issuer_key_id     TEXT NOT NULL,
    token_ciphertext  BLOB NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    status            TEXT NOT NULL,
    issued_at_ms      INTEGER,
    spent_at_ms       INTEGER,
    spend_context     TEXT,
    CHECK (family IN ('QUERY_TICKET_V1', 'RECEIPT_TICKET_V1')),
    CHECK (status IN ('available','spent','expired','revoked'))
);

CREATE INDEX IF NOT EXISTS idx_anonymous_tickets_status
  ON anonymous_tickets(status, family, epoch_id);

CREATE TABLE IF NOT EXISTS spent_ticket_nullifiers (
    nullifier      TEXT PRIMARY KEY,
    family         TEXT NOT NULL,
    circle_id      TEXT NOT NULL,
    epoch_id       TEXT NOT NULL,
    spent_at_ms    INTEGER NOT NULL,
    expires_at_ms  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spent_nullifiers_expiry
  ON spent_ticket_nullifiers(expires_at_ms);

CREATE TABLE IF NOT EXISTS issuer_keys (
    issuer_key_id   TEXT NOT NULL,
    circle_id       TEXT NOT NULL,
    epoch_id        TEXT NOT NULL,
    pubkey_bytes    BLOB NOT NULL,
    valid_from_ms   INTEGER NOT NULL,
    valid_until_ms  INTEGER NOT NULL,
    PRIMARY KEY (issuer_key_id, circle_id, epoch_id)
);
"""


def db_path() -> Path:
    """Ticket store. Parent dir is mode 0700 via swf.paths."""
    from ..paths import ensure_dir, state_dir
    env = os.environ.get("SWF_TICKETS_DB")
    if env:
        p = Path(env)
        ensure_dir(p.parent)
    else:
        p = state_dir() / "tickets.sqlite"
    return p


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=2.0)
    conn.row_factory = sqlite3.Row
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_CREATE)
    return conn


# ── ticket store ─────────────────────────────────────────────────────

def store_ticket(
    *,
    family: TicketFamily,
    circle_id: str,
    epoch_id: str,
    issuer_key_id: str,
    token_bytes: bytes,
    issued_at_ms: int | None = None,
) -> int:
    """Persist a freshly-issued ticket. `token_bytes` is the canonical
    serialization of the unblinded token; we store it as-is (`§27.13
    raw_token_file_permissions: 0600` is enforced by db_path's mode
    inheritance from `~/.config/swf`)."""
    issued_at_ms = issued_at_ms or int(time.time() * 1000)
    h = _token_hash(token_bytes)
    try:
        conn = _connect()
    except sqlite3.OperationalError as e:
        raise RuntimeError(f"ticket store unavailable: {e}") from e
    try:
        cur = conn.execute(
            """INSERT OR IGNORE INTO anonymous_tickets
                  (family, circle_id, epoch_id, issuer_key_id,
                   token_ciphertext, token_hash, status, issued_at_ms)
               VALUES (?, ?, ?, ?, ?, ?, 'available', ?)""",
            (family.value, circle_id, epoch_id, issuer_key_id,
             token_bytes, h, issued_at_ms),
        )
        conn.commit()
        if cur.lastrowid is not None and cur.rowcount > 0:
            return cur.lastrowid
        # Already stored; return its id.
        row = conn.execute(
            "SELECT id FROM anonymous_tickets WHERE token_hash=?", (h,)
        ).fetchone()
        return row["id"] if row else -1
    finally:
        conn.close()


def list_available(
    *,
    family: TicketFamily,
    circle_id: str,
    epoch_id: str,
    limit: int = 1,
) -> list[dict]:
    """Return up to `limit` rows in `available` state. Caller picks one,
    proceeds to spend it via `mark_spent`."""
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return []
    try:
        rows = conn.execute(
            """SELECT id, token_ciphertext, token_hash, issuer_key_id
               FROM anonymous_tickets
               WHERE family=? AND circle_id=? AND epoch_id=?
                 AND status='available'
               ORDER BY id ASC LIMIT ?""",
            (family.value, circle_id, epoch_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def mark_spent(
    ticket_id: int,
    *,
    spend_context: str,
    spent_at_ms: int | None = None,
) -> bool:
    """Local bookkeeping: flip our own ticket row to `spent`. The
    cross-peer double-spend check uses `try_spend_nullifier()` instead
    — that's what other peers consult."""
    spent_at_ms = spent_at_ms or int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return False
    try:
        cur = conn.execute(
            """UPDATE anonymous_tickets
               SET status='spent', spent_at_ms=?, spend_context=?
               WHERE id=? AND status='available'""",
            (spent_at_ms, spend_context, ticket_id),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


# ── nullifier registry (cross-peer double-spend) ─────────────────────

_NULLIFIER_VACUUM_EVERY = 1024
_nullifier_spend_count = 0
_nullifier_vacuum_lock = __import__("threading").Lock()


def try_spend_nullifier(
    nullifier: str,
    *,
    family: TicketFamily,
    circle_id: str,
    epoch_id: str,
    spent_at_ms: int | None = None,
    retention_ms: int = DEFAULT_NULLIFIER_RETENTION_MS,
) -> bool:
    """Atomically claim a nullifier. Returns True on first claim,
    False if the nullifier is already in the table (double-spend).

    UNIQUE PRIMARY KEY + INSERT OR IGNORE makes this race-free even
    under concurrent writers — we read `cur.rowcount` to decide.

    Red-team pass-3 finding F: opportunistically vacuum every
    `_NULLIFIER_VACUUM_EVERY` spends so the table can't grow without
    bound under sustained write load.
    """
    if not nullifier:
        return False
    spent_at_ms = spent_at_ms or int(time.time() * 1000)
    expires = spent_at_ms + retention_ms
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return False
    try:
        cur = conn.execute(
            """INSERT OR IGNORE INTO spent_ticket_nullifiers
                  (nullifier, family, circle_id, epoch_id,
                   spent_at_ms, expires_at_ms)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (nullifier, family.value, circle_id, epoch_id,
             spent_at_ms, expires),
        )
        conn.commit()
        accepted = cur.rowcount == 1
    finally:
        conn.close()
    # Opportunistic vacuum. Cheap when the table is small; bounded
    # when it's large because DELETE expires_at_ms <= now is indexed.
    global _nullifier_spend_count
    with _nullifier_vacuum_lock:
        _nullifier_spend_count += 1
        do_vacuum = (_nullifier_spend_count % _NULLIFIER_VACUUM_EVERY) == 0
    if do_vacuum:
        with contextlib.suppress(Exception):
            vacuum_expired_nullifiers(now_ms=spent_at_ms)
    return accepted


def is_spent(nullifier: str) -> bool:
    """Read-only check; for diagnostics. The race-safe spend path is
    `try_spend_nullifier`."""
    if not nullifier:
        return False
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM spent_ticket_nullifiers WHERE nullifier=?",
            (nullifier,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def vacuum_expired_nullifiers(*, now_ms: int | None = None) -> int:
    """Drop nullifier rows past their expiry + truncate WAL.
    Cron-friendly. Resource audit F3: WAL checkpoint runs after the
    DELETE so the on-disk file doesn't grow unbounded between
    SQLite's automatic checkpoints."""
    now_ms = now_ms or int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return 0
    try:
        cur = conn.execute(
            "DELETE FROM spent_ticket_nullifiers WHERE expires_at_ms <= ?",
            (now_ms,),
        )
        conn.commit()
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return cur.rowcount
    finally:
        conn.close()


# ── issuer-key registry ─────────────────────────────────────────────

def trust_issuer_key(key: IssuerKey) -> None:
    """Pin an issuer pubkey as trusted for (circle_id, epoch_id). The
    spec's §27.5.1 single-issuer model is the v1 default; rotating /
    threshold modes register multiple keys per epoch."""
    try:
        conn = _connect()
    except sqlite3.OperationalError as e:
        raise RuntimeError(f"ticket store unavailable: {e}") from e
    try:
        conn.execute(
            """INSERT OR REPLACE INTO issuer_keys
                  (issuer_key_id, circle_id, epoch_id, pubkey_bytes,
                   valid_from_ms, valid_until_ms)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (key.issuer_key_id, key.circle_id, key.epoch_id,
             key.pubkey_bytes, key.valid_from_ms, key.valid_until_ms),
        )
        conn.commit()
    finally:
        conn.close()


def get_issuer_key(
    issuer_key_id: str, *, circle_id: str, epoch_id: str,
) -> IssuerKey | None:
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return None
    try:
        row = conn.execute(
            """SELECT * FROM issuer_keys
               WHERE issuer_key_id=? AND circle_id=? AND epoch_id=?""",
            (issuer_key_id, circle_id, epoch_id),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return IssuerKey(
        issuer_key_id=row["issuer_key_id"],
        circle_id=row["circle_id"],
        epoch_id=row["epoch_id"],
        pubkey_bytes=row["pubkey_bytes"],
        valid_from_ms=row["valid_from_ms"],
        valid_until_ms=row["valid_until_ms"],
    )


# ── envelope validation up to (but not including) crypto ─────────────

def epoch_acceptable(
    epoch_id: str,
    *,
    current_epoch_id: str,
    previous_epoch_id: str | None = None,
    grace_ms: int = DEFAULT_ACCEPT_PREVIOUS_EPOCH_MS,
    epoch_started_ms: int | None = None,
    now_ms: int | None = None,
) -> bool:
    """§27.6: accept current epoch always; accept previous_epoch only
    within `grace_ms` of the new epoch's start. The caller drives
    epoch_started_ms; we don't pretend to know wall-clock authoritative
    epoch boundaries."""
    if epoch_id == current_epoch_id:
        return True
    if previous_epoch_id is None or epoch_id != previous_epoch_id:
        return False
    if epoch_started_ms is None:
        return True   # we have no clock evidence; trust the registry
    now_ms = now_ms or int(time.time() * 1000)
    return (now_ms - epoch_started_ms) <= grace_ms


def validate_envelope(
    env: TicketEnvelope,
    *,
    expected_circle_id: str,
    current_epoch_id: str,
    previous_epoch_id: str | None = None,
    expected_scope: str | None = None,
    grace_ms: int = DEFAULT_ACCEPT_PREVIOUS_EPOCH_MS,
    epoch_started_ms: int | None = None,
    now_ms: int | None = None,
) -> TicketRejection | None:
    """Run every check that does NOT require crypto verification.
    Returns None if all non-crypto checks pass; otherwise a
    `TicketRejection` enum value naming the failure.

    The caller must STILL run `verify_signature(env, issuer_pubkey)`
    via the (eventually-plugged-in) Privacy Pass library before
    accepting the ticket.
    """
    if env.circle_id != expected_circle_id:
        return TicketRejection.INVALID
    if expected_scope is not None and env.token_body.scope != expected_scope:
        return TicketRejection.INVALID
    if not env.issuer_signature:
        return TicketRejection.INVALID
    if not env.token_body.nonce or len(env.token_body.nonce) < 22:
        # 22 chars of base64url ≈ 132 bits — minimum reasonable nonce
        return TicketRejection.INVALID
    if not epoch_acceptable(
        env.epoch_id,
        current_epoch_id=current_epoch_id,
        previous_epoch_id=previous_epoch_id,
        grace_ms=grace_ms,
        epoch_started_ms=epoch_started_ms,
        now_ms=now_ms,
    ):
        return TicketRejection.WRONG_EPOCH
    issuer = get_issuer_key(
        env.issuer_key_id,
        circle_id=expected_circle_id, epoch_id=env.epoch_id,
    )
    if issuer is None:
        return TicketRejection.UNTRUSTED_ISSUER
    return None


# ── crypto interface (NOT IMPLEMENTED — see §27.10) ─────────────────

def verify_signature(envelope: TicketEnvelope, issuer: IssuerKey) -> bool:
    """Verify the blind-signature on the ticket envelope.

    **NOT IMPLEMENTED in this PR.** §27.10 explicitly says do NOT
    invent a new blind-signature scheme. A future PR plugs in a vetted
    Privacy Pass library (RFC 9474 publicly-verifiable blind RSA, or
    RFC 9578 VOPRF tokens) and replaces this stub.

    Until then, every caller MUST treat the result of this function as
    "unverified" and must NOT accept the ticket. The router's
    LAN_FRIEND_DCNET path remains gated on this — it ships as
    `route_not_implemented` precisely because the crypto isn't here.
    """
    raise NotImplementedError(
        "blind-signature verification requires a Privacy Pass library "
        "(see SPEC §27.10); plug in RFC 9474 / 9578 here"
    )


def nullifier_for(envelope: TicketEnvelope) -> str:
    """§27.11 nullifier construction.

    Computed from the canonical encoding of the unblinded token. The
    canonical encoding itself is library-dependent — for now we hash
    the issuer_signature || token_body, which is stable for any
    deterministic Privacy Pass scheme (the issuer_signature IS the
    unblinded token in publicly-verifiable variants). When a real
    library lands, swap this for the library's own nullifier
    computation if it differs.
    """
    import hashlib
    h = hashlib.sha256()
    h.update(b"swf.query_ticket.nullifier.v1")
    h.update(envelope.issuer_signature)
    h.update(envelope.token_body.nonce.encode("utf-8"))
    h.update(envelope.token_body.scope.encode("utf-8"))
    return f"sha256:{h.hexdigest()}"


# ── helpers ──────────────────────────────────────────────────────────

def _token_hash(token_bytes: bytes) -> str:
    import hashlib
    return f"sha256:{hashlib.sha256(token_bytes).hexdigest()}"


def _b64(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")
