"""SPEC v0.3 §29.10 local reputation.

Scores are LOCAL — they stay on this device, never leave. They drive
two things in v0:

1. **Display:** `result.provider.provider_score_local` is set for every
   peer-attributable hit so a wall renderer can show provider quality.
2. **Re-rank:** `enrich_results()` boosts results from high-score
   providers within the same delivery_path (the §15 router doesn't
   touch ordering across routes — that stays sufficiency-driven).

Phase 6 layers anonymous receipts on top: a peer can prove "X said I
served them well" without identifying the user. For now we have only
direct, local feedback.

Storage: SQLite at `~/.local/share/swf/reputation.db`. Single
provider_scores table, simple and easy to inspect.
"""
from __future__ import annotations

import contextlib
import math
import os
import sqlite3
import time
from collections.abc import Iterable
from pathlib import Path

from .response import SearchResult

# ── score model ──────────────────────────────────────────────────────
#
# Scores live in [0, 1] with a neutral default of 0.5. Each event
# nudges the score up or down by a small delta; magnitudes pulled from
# the spec's "feedback signals are bounded and modest" rule.
#
# The half-life is 30 days: a score drifts back to 0.5 over time so
# that reputation is recent-weighted. `apply_decay` is called from
# both `score_for` (lazy) and a one-shot `decay_all()` for batch jobs.

DEFAULT_SCORE = 0.5
NEUTRAL_PULL = 0.5
HALF_LIFE_DAYS = 30.0
HALF_LIFE_MS = HALF_LIFE_DAYS * 24 * 3600 * 1000

# Event type → score delta. Positive = up-weight; negative = down-weight.
EVENT_DELTA: dict[str, float] = {
    # Direct user signals
    "open": +0.020,
    "save": +0.060,
    "click_through": +0.010,
    "user_marked_useful": +0.080,
    "user_marked_useless": -0.080,
    # Verification signals
    "signature_verified": +0.030,
    "verification_failed": -0.040,
    # Provenance violations: peer said share_scope=public but the row
    # was actually private when re-fetched, etc. (§29.10 "malformed-
    # response penalties").
    "malformed_response": -0.060,
    "claim_violated": -0.120,
    # Receipt validation (Phase 6+ wires this to anonymous receipts).
    "receipt_validated": +0.040,
}

# Hard caps so a single provider can never spike to 1.0 or floor at 0.
# §29.10 explicitly mentions "caps".
MIN_SCORE = 0.05
MAX_SCORE = 0.95


_CREATE = """
CREATE TABLE IF NOT EXISTS provider_scores (
    provider_pubkey   TEXT PRIMARY KEY,
    score             REAL NOT NULL,
    last_updated_ms   INTEGER NOT NULL,
    notes             TEXT
)
"""


def db_path() -> Path:
    """Reputation DB; sibling of community.db / search_cache.db.
    Parent dir is mode 0700 via swf.paths."""
    from ..paths import ensure_dir, state_dir
    env = os.environ.get("SWF_REPUTATION_DB")
    if env:
        p = Path(env)
        ensure_dir(p.parent)
    else:
        p = state_dir() / "reputation.db"
    return p


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path()), timeout=2.0)
    conn.row_factory = sqlite3.Row
    with contextlib.suppress(sqlite3.DatabaseError):
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_CREATE)
    return conn


def _decayed(score: float, last_updated_ms: int, now_ms: int) -> float:
    """Pull `score` toward NEUTRAL_PULL with half-life HALF_LIFE_DAYS."""
    if last_updated_ms <= 0 or now_ms <= last_updated_ms:
        return score
    elapsed_ms = now_ms - last_updated_ms
    weight = math.pow(0.5, elapsed_ms / HALF_LIFE_MS)
    return NEUTRAL_PULL + (score - NEUTRAL_PULL) * weight


# ── reads ────────────────────────────────────────────────────────────

def score_for(provider_pubkey: str, *, now_ms: int | None = None) -> float:
    """Return a provider's current decay-adjusted score in [0, 1]."""
    if not provider_pubkey:
        return DEFAULT_SCORE
    now_ms = now_ms or int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return DEFAULT_SCORE
    try:
        row = conn.execute(
            "SELECT score, last_updated_ms FROM provider_scores "
            "WHERE provider_pubkey=?",
            (provider_pubkey,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return DEFAULT_SCORE
    return _clamp(_decayed(row["score"], row["last_updated_ms"], now_ms))


def scores_for_many(pubkeys: Iterable[str]) -> dict[str, float]:
    """Bulk read; cheaper than N round-trips."""
    keys = [k for k in set(pubkeys) if k]
    if not keys:
        return {}
    now_ms = int(time.time() * 1000)
    placeholders = ",".join("?" * len(keys))
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return {k: DEFAULT_SCORE for k in keys}
    try:
        rows = conn.execute(
            f"SELECT provider_pubkey, score, last_updated_ms "
            f"FROM provider_scores WHERE provider_pubkey IN ({placeholders})",
            keys,
        ).fetchall()
    finally:
        conn.close()
    out = {k: DEFAULT_SCORE for k in keys}
    for r in rows:
        out[r["provider_pubkey"]] = _clamp(
            _decayed(r["score"], r["last_updated_ms"], now_ms)
        )
    return out


# ── writes ───────────────────────────────────────────────────────────

def bump(
    provider_pubkey: str,
    event: str,
    *,
    now_ms: int | None = None,
    notes: str | None = None,
) -> float:
    """Apply an event's delta to a provider's score. Caps at
    [MIN_SCORE, MAX_SCORE]. Returns the new score for convenience.
    Unknown event names are no-ops (log + return current)."""
    if not provider_pubkey:
        return DEFAULT_SCORE
    delta = EVENT_DELTA.get(event)
    if delta is None:
        return score_for(provider_pubkey, now_ms=now_ms)
    now_ms = now_ms or int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return DEFAULT_SCORE
    # Red-team pass-2 finding #3 + pass-3 finding D: read-modify-write
    # must be serialized. `BEGIN IMMEDIATE` on a fresh `_connect()`
    # always succeeds (we're in autocommit mode); a failure here
    # IS a real error, NOT a "fall through and race anyway" signal.
    # Explicit ROLLBACK on any inner exception so the writer lock is
    # released promptly.
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT score, last_updated_ms FROM provider_scores "
                "WHERE provider_pubkey=?",
                (provider_pubkey,),
            ).fetchone()
            if row is None:
                current = DEFAULT_SCORE
            else:
                current = _decayed(row["score"], row["last_updated_ms"], now_ms)
            new_score = _clamp(current + delta)
            conn.execute(
                """INSERT INTO provider_scores(provider_pubkey, score,
                                                last_updated_ms, notes)
                   VALUES(?, ?, ?, ?)
                   ON CONFLICT(provider_pubkey) DO UPDATE SET
                     score = excluded.score,
                     last_updated_ms = excluded.last_updated_ms,
                     notes = COALESCE(excluded.notes, provider_scores.notes)""",
                (provider_pubkey, new_score, now_ms, notes),
            )
            conn.commit()
        except Exception:
            with contextlib.suppress(sqlite3.Error):
                conn.rollback()
            raise
    finally:
        conn.close()
    return new_score


def decay_all(*, now_ms: int | None = None) -> int:
    """One-shot pass that materializes the decay-adjusted score back into
    the table + truncates the WAL file. Idempotent. Useful for cron-
    style hygiene; lazy decay in `score_for` already handles read-time
    correctness. Resource audit F3: WAL checkpoint runs after writes."""
    now_ms = now_ms or int(time.time() * 1000)
    try:
        conn = _connect()
    except sqlite3.OperationalError:
        return 0
    try:
        rows = conn.execute(
            "SELECT provider_pubkey, score, last_updated_ms "
            "FROM provider_scores"
        ).fetchall()
        n = 0
        for r in rows:
            new_score = _clamp(
                _decayed(r["score"], r["last_updated_ms"], now_ms)
            )
            if abs(new_score - r["score"]) < 1e-9:
                continue
            conn.execute(
                "UPDATE provider_scores SET score=?, last_updated_ms=? "
                "WHERE provider_pubkey=?",
                (new_score, now_ms, r["provider_pubkey"]),
            )
            n += 1
        conn.commit()
        with contextlib.suppress(sqlite3.OperationalError):
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return n
    finally:
        conn.close()


# ── result enrichment ────────────────────────────────────────────────

def enrich_results(results: list[SearchResult]) -> list[SearchResult]:
    """Populate `result.provider.provider_score_local` in place. Does
    not re-rank — the router decides whether to call `rerank()`. Safe
    on results without a provider_pubkey (no-op for those rows)."""
    keys = []
    for r in results:
        pk = r.provider.provider_pubkey if r.provider else None
        if pk:
            keys.append(pk)
    scores = scores_for_many(keys)
    for r in results:
        if r.provider and r.provider.provider_pubkey:
            r.provider.provider_score_local = round(
                scores.get(r.provider.provider_pubkey, DEFAULT_SCORE), 4
            )
    return results


def rerank(results: list[SearchResult],
           *, weight: float = 0.30) -> list[SearchResult]:
    """Re-rank results by `combined = result.score + weight * (provider_score - 0.5)`.

    The weight is conservative: a very high-rep provider only gets
    ~+0.15 boost, and a very low-rep one ~-0.15. Sufficiency thresholds
    in §14 are unaffected — they ran before this on the un-reranked
    list, by design (route quality is about the route, not the
    contributor).

    Returns a NEW list with new `SearchResult` instances (rank
    rewritten on the copies); the input list and items are left
    untouched.
    """
    import copy
    cloned = [copy.deepcopy(r) for r in results]
    enrich_results(cloned)
    def key(r: SearchResult) -> float:
        ps = (r.provider.provider_score_local
              if r.provider and r.provider.provider_score_local is not None
              else DEFAULT_SCORE)
        return r.score + weight * (ps - NEUTRAL_PULL)
    out = sorted(cloned, key=key, reverse=True)
    for i, r in enumerate(out):
        r.rank = i + 1
    return out


# ── helpers ──────────────────────────────────────────────────────────

def _clamp(s: float) -> float:
    return max(MIN_SCORE, min(MAX_SCORE, s))
