"""Unit tests for `swf.sync.store.apply_envelope` (spec §5 + §9.9 + §9.10)."""
from __future__ import annotations

import time

import pytest

from swf.sync import (
    apply_envelope,
    build_manifest,
    is_record_forked,
    latest_envelope,
    pinned_author,
)


def test_first_envelope_is_applied(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    env = make_envelope(record_id="amiller", wall_ts_ms=1000)
    result = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert result.ok
    assert result.was_new
    assert result.became_latest
    assert pinned_author(sync_conn, "amiller") == sync_keypair.pubkey_str


def test_replay_dedup_is_idempotent(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    """Spec §5.3 / §9.10: a second envelope with the same content_hash
    is dropped at the INSERT OR IGNORE level."""
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    env = make_envelope(record_id="amiller", wall_ts_ms=1000)
    first = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert first.ok and first.was_new
    second = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert second.ok
    assert not second.was_new
    # Only one row in the table.
    count = sync_conn.execute(
        "SELECT COUNT(*) FROM sync_records WHERE record_id=?", ("amiller",),
    ).fetchone()[0]
    assert count == 1


def test_lww_wins_higher_wall_ts(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    older = make_envelope(record_id="amiller", wall_ts_ms=1000,
                          content={"v": 1})
    newer = make_envelope(record_id="amiller", wall_ts_ms=2000,
                          content={"v": 2},
                          prev_hash=older["content_hash"])
    apply_envelope(sync_conn, older, cohort_keys=cohort)
    r = apply_envelope(sync_conn, newer, cohort_keys=cohort)
    assert r.ok and r.became_latest
    latest = latest_envelope(sync_conn, "amiller")
    assert latest["wall_ts_ms"] == 2000
    assert latest["content"] == {"v": 2}


def test_lww_tiebreaker_on_equal_ts(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    """Spec §5.1: on equal wall_ts_ms, lexicographically larger
    content_hash wins."""
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    a = make_envelope(record_id="amiller", wall_ts_ms=1000, content={"a": 1})
    b = make_envelope(record_id="amiller", wall_ts_ms=1000, content={"b": 2})
    # NOTE: both have prev_hash=None, same author — that creates a fork!
    # To test tiebreaker without fork, give them different prev_hashes.
    # We'll create a v0 first then two siblings with different prev:
    apply_envelope(sync_conn, a, cohort_keys=cohort)
    # B is a fork sibling of A — same prev_hash (None), same record_id,
    # same author. apply_envelope handles fork; latest should NOT update.
    # For pure tiebreaker test, use different prev_hashes:
    v0 = a
    v1a = make_envelope(record_id="amiller", wall_ts_ms=2000,
                        content={"x": 1}, prev_hash=v0["content_hash"])
    v1b = make_envelope(record_id="amiller", wall_ts_ms=2000,
                        content={"y": 1}, prev_hash=v1a["content_hash"])
    # v1a and v1b have different prev_hashes (sequential), so no fork.
    apply_envelope(sync_conn, v1a, cohort_keys=cohort)
    apply_envelope(sync_conn, v1b, cohort_keys=cohort)
    # The newer chain entry wins regardless of ms collision; tiebreaker
    # only matters when prev_hash is equal. Verify the most-recently-
    # applied envelope is the LWW winner.
    latest = latest_envelope(sync_conn, "amiller")
    # Pick whichever of v1a, v1b has the larger content_hash —
    # that's the deterministic winner per (wall_ts DESC, content_hash DESC).
    winning_ch = max(v1a["content_hash"], v1b["content_hash"])
    assert latest["content_hash"] == winning_ch


def test_fork_detection_two_siblings(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    """Spec §9.9: two envelopes with same (record_id, author, prev_hash)
    but different content_hash → fork; both stored, record flagged
    forked, manifest omits the record."""
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    e1 = make_envelope(record_id="amiller", wall_ts_ms=1000,
                       content={"v": 1}, prev_hash=None)
    e2 = make_envelope(record_id="amiller", wall_ts_ms=2000,
                       content={"v": 2}, prev_hash=None)  # sibling of e1!
    r1 = apply_envelope(sync_conn, e1, cohort_keys=cohort)
    r2 = apply_envelope(sync_conn, e2, cohort_keys=cohort)
    assert r1.ok and not r1.fork_detected
    assert r2.ok
    assert r2.fork_detected
    # Both envelopes persist.
    rows = sync_conn.execute(
        "SELECT COUNT(*) FROM sync_records WHERE record_id=?", ("amiller",),
    ).fetchone()[0]
    assert rows == 2
    # Author row is flagged.
    assert is_record_forked(sync_conn, "amiller")
    # Manifest omits the forked record (spec §9.9 step 3).
    manifest = build_manifest(sync_conn)
    assert "amiller" not in manifest["records"]


def test_fork_resolution_clears_flag(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    """Spec §9.9 step 5: a fresh envelope from the author clears the
    fork flag."""
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    e1 = make_envelope(record_id="amiller", wall_ts_ms=1000,
                       content={"v": 1}, prev_hash=None)
    e2 = make_envelope(record_id="amiller", wall_ts_ms=2000,
                       content={"v": 2}, prev_hash=None)
    apply_envelope(sync_conn, e1, cohort_keys=cohort)
    apply_envelope(sync_conn, e2, cohort_keys=cohort)
    assert is_record_forked(sync_conn, "amiller")

    # Author writes a new envelope with a fresh prev_hash pointing at
    # one of the siblings.
    resolution = make_envelope(record_id="amiller", wall_ts_ms=3000,
                               content={"v": 3},
                               prev_hash=e2["content_hash"])
    r = apply_envelope(sync_conn, resolution, cohort_keys=cohort)
    assert r.ok and r.was_new
    assert not is_record_forked(sync_conn, "amiller")
    # Manifest now includes the resolved record.
    manifest = build_manifest(sync_conn)
    assert "amiller" in manifest["records"]


def test_clock_skew_rejection(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    """Spec §9.4: envelopes more than 5 min in the future are dropped."""
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    now = int(time.time() * 1000)
    far_future = now + 10 * 60 * 1000  # 10 min ahead
    env = make_envelope(record_id="amiller", wall_ts_ms=far_future)
    r = apply_envelope(sync_conn, env, cohort_keys=cohort, now_ms=now)
    assert not r.ok
    assert r.reason == "clock_too_far_ahead"


def test_unknown_author_rejected(sync_conn, make_envelope, cohort_keys_with, sync_keypair):
    """Spec §4.4 step 3: author not in cohort → drop."""
    # Cohort doesn't include our keypair.
    cohort = cohort_keys_with(other="ed25519:" + "00" * 32)
    env = make_envelope(record_id="amiller")
    r = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r.ok
    assert r.reason == "author_not_in_cohort"


def test_record_author_pin_collision(sync_conn, make_envelope, make_keypair, cohort_keys_with):
    """Spec §9.6: a second author claiming an existing record_id is
    rejected with `record_id_owned_by_other_author`."""
    k1 = make_keypair()
    k2 = make_keypair()
    cohort = cohort_keys_with(amiller=k1.pubkey_str, halcyon=k2.pubkey_str)

    # First envelope from k1 pins the author.
    e1 = make_envelope(
        record_id="amiller", wall_ts_ms=1000,
        priv=k1.priv, pubkey_str=k1.pubkey_str,
    )
    r1 = apply_envelope(sync_conn, e1, cohort_keys=cohort)
    assert r1.ok

    # Second envelope from k2 for the same record_id → collision.
    e2 = make_envelope(
        record_id="amiller", wall_ts_ms=2000,
        priv=k2.priv, pubkey_str=k2.pubkey_str,
    )
    r2 = apply_envelope(sync_conn, e2, cohort_keys=cohort)
    assert not r2.ok
    assert r2.reason == "record_id_owned_by_other_author"


def test_signature_invalid_after_tamper(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    env = make_envelope(record_id="amiller")
    # Tamper content WITHOUT recomputing content_hash to dodge the
    # shape stage check — keep content_hash stale so we go further.
    # Easier: keep content_hash consistent but flip a wall_ts byte and
    # leave the signature intact.
    env["wall_ts_ms"] = env["wall_ts_ms"] + 1
    r = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r.ok
    assert r.reason == "signature_invalid"


def test_manifest_hash_stable_across_runs(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    env = make_envelope(record_id="amiller", wall_ts_ms=1000)
    apply_envelope(sync_conn, env, cohort_keys=cohort)
    m1 = build_manifest(sync_conn)
    m2 = build_manifest(sync_conn)
    assert m1["manifest_hash"] == m2["manifest_hash"]
    assert m1["manifest_hash"].startswith("sha256:")


def test_manifest_empty_when_no_records(sync_conn):
    manifest = build_manifest(sync_conn)
    assert manifest["records"] == {}
    # Even for empty records, hash is deterministic.
    assert manifest["manifest_hash"].startswith("sha256:")


def test_oversized_envelope_rejected_at_apply(sync_conn, sync_keypair, make_envelope, cohort_keys_with):
    cohort = cohort_keys_with(amiller=sync_keypair.pubkey_str)
    huge = {"blob": "x" * (70 * 1024)}
    env = make_envelope(record_id="amiller", content=huge)
    r = apply_envelope(sync_conn, env, cohort_keys=cohort)
    assert not r.ok
    assert r.reason == "envelope_too_large"
