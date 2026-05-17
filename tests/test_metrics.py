"""Tests for swf.community_full.metrics — bucketed time-series + push counters.

Covers the unit-level surface (percentile math, bucket grouping) plus an
end-to-end smoke test that inserts samples into a temp community.db and
queries them back through the public series() / snapshot() helpers.

Both /metrics/snapshot and /metrics/series are read-only and live under
--full, so this is the trust line we test from."""
from __future__ import annotations

import importlib
import sys
import time

import pytest


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Point the community_full DB at a fresh temp file and re-init schema.

    The metrics module imports `db` at module-import time, so we must
    patch SWF_COMMUNITY_DB BEFORE the metrics module is loaded. Reload
    is required because some tests share the module across runs and the
    DEFAULT_DB constant is captured at import."""
    db_path = tmp_path / "community.db"
    monkeypatch.setenv("SWF_COMMUNITY_DB", str(db_path))
    # Force fresh import so DEFAULT_DB picks up the env var.
    for mod in list(sys.modules):
        if mod.startswith("swf.community_full"):
            del sys.modules[mod]
    from swf.community_full import db as cdb  # noqa: WPS433
    cdb.init()
    return cdb


def _import_metrics():
    from swf.community_full import metrics as cmetrics  # noqa: WPS433
    return cmetrics


# ─── percentile helper ────────────────────────────────────────────────────


def test_percentile_empty_returns_zero(tmp_db):
    cmetrics = _import_metrics()
    assert cmetrics._percentile([], 0.5) == 0.0
    assert cmetrics._percentile([], 0.95) == 0.0


def test_percentile_single_value(tmp_db):
    cmetrics = _import_metrics()
    assert cmetrics._percentile([42.0], 0.5) == 42.0
    assert cmetrics._percentile([42.0], 0.95) == 42.0


def test_percentile_p50_p95_basic(tmp_db):
    cmetrics = _import_metrics()
    vals = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
    assert cmetrics._percentile(vals, 0.50) == pytest.approx(5.5)
    # p95 over 10 values: linear-interp gives index 9*0.95 = 8.55
    assert cmetrics._percentile(vals, 0.95) == pytest.approx(9.55)


# ─── push-style counters ──────────────────────────────────────────────────


def test_record_search_drains_into_tick_snapshot(tmp_db):
    cmetrics = _import_metrics()
    # Reset push state so prior tests don't leak in
    cmetrics._search_durations_ms.clear()
    cmetrics._scrape_durations_ms.clear()
    cmetrics._search_total = 0
    cmetrics._search_errors = 0
    cmetrics._scrape_total = 0
    cmetrics._scrape_errors = 0

    cmetrics.record_search(120.0, ok=True)
    cmetrics.record_search(80.0, ok=True)
    cmetrics.record_search(2000.0, ok=False)
    cmetrics.record_scrape(50.0, ok=True)

    drained = cmetrics._drain_push_metrics()
    assert drained["web_search.total"] == 3.0
    assert drained["web_search.errors"] == 1.0
    assert drained["web_search.duration_ms_p50"] == pytest.approx(120.0)
    # p95 of 3 samples with linear interpolation lands between p50 and the
    # max — we just need it to be safely above the median.
    assert drained["web_search.duration_ms_p95"] > 1500.0
    assert drained["slice_scrape.total"] == 1.0

    # Drain again — the buffers MUST be empty now (otherwise a slow tick
    # would double-count entries).
    drained2 = cmetrics._drain_push_metrics()
    assert drained2["web_search.total"] == 0.0
    assert "web_search.duration_ms_p50" not in drained2


# ─── bucketing in series() ────────────────────────────────────────────────


def test_series_buckets_samples_by_step(tmp_db):
    cmetrics = _import_metrics()
    base = 1_000_000_000_000  # arbitrary epoch ms
    rows = [
        # name=A, four samples in two 60s buckets
        (base + 0,     "A", 10.0, ""),
        (base + 30_000,  "A", 20.0, ""),  # same bucket as 0
        (base + 60_000,  "A", 30.0, ""),  # next bucket
        (base + 90_000,  "A", 40.0, ""),  # same as 60_000
        # name=B once
        (base + 30_000,  "B", 5.0, ""),
    ]
    with tmp_db.writer() as conn:
        conn.executemany(
            "INSERT INTO metrics_samples(ts_ms, name, value, labels_json) VALUES (?,?,?,?)",
            rows,
        )

    out = cmetrics.series(
        ["A", "B"],
        from_ms=base,
        until_ms=base + 120_000,
        step_ms=60_000,
    )
    a_rows = [r for r in out["series"] if r["name"] == "A"]
    b_rows = [r for r in out["series"] if r["name"] == "B"]
    # A has two buckets; AVG([10,20])=15, AVG([30,40])=35
    a_vals = sorted(r["value"] for r in a_rows)
    assert a_vals == pytest.approx([15.0, 35.0])
    # B has one bucket, value 5
    assert len(b_rows) == 1
    assert b_rows[0]["value"] == pytest.approx(5.0)
    assert out["truncated"] is False


def test_series_caps_max_rows_with_truncated_flag(tmp_db):
    cmetrics = _import_metrics()
    base = 2_000_000_000_000
    # Insert 25 distinct buckets at step=1000 ms
    rows = [
        (base + i * 1_000, "M", float(i), "") for i in range(25)
    ]
    with tmp_db.writer() as conn:
        conn.executemany(
            "INSERT INTO metrics_samples(ts_ms, name, value, labels_json) VALUES (?,?,?,?)",
            rows,
        )
    out = cmetrics.series(
        ["M"],
        from_ms=base,
        until_ms=base + 30_000,
        step_ms=1_000,
        max_rows=10,
    )
    assert len(out["series"]) == 10
    assert out["truncated"] is True


def test_series_rejects_empty_names(tmp_db):
    cmetrics = _import_metrics()
    out = cmetrics.series(
        [],
        from_ms=0,
        until_ms=1_000,
        step_ms=1_000,
    )
    assert out["series"] == []
    assert out["truncated"] is False


# ─── snapshot ─────────────────────────────────────────────────────────────


def test_snapshot_falls_back_to_community_counts(tmp_db):
    """Cold-start: no tick has run yet, but snapshot() must still return
    something useful so the wall has data on first paint. Post-#43 PR C
    `contributions.count_total` is gone (the contributions table was
    removed); peers/pages keys remain from indrex.db."""
    cmetrics = _import_metrics()
    cmetrics._latest_snapshot = {}
    cmetrics._latest_snapshot_ts = 0
    snap = cmetrics.snapshot()
    vals = snap["values"]
    assert "peers.count_known" in vals
    assert "pages.count_total" in vals
    # contributions.count_total was removed in #43 PR C — assert
    # it's NOT silently re-emitted (a regression here would mean a
    # forgotten reference to the deleted table).
    assert "contributions.count_total" not in vals


def test_do_tick_inserts_samples(tmp_db):
    """End-to-end: run a single tick and verify rows landed in
    metrics_samples and series() can pull them back."""
    cmetrics = _import_metrics()
    cmetrics._do_tick()
    with tmp_db.reader() as conn:
        n = conn.execute(
            "SELECT COUNT(*) AS n FROM metrics_samples"
        ).fetchone()["n"]
    assert n > 0
    # Pull back via series() — pick a name that's always emitted.
    now_ms = int(time.time() * 1000)
    out = cmetrics.series(
        ["pages.count_total"],
        from_ms=now_ms - 60_000,
        until_ms=now_ms + 60_000,
        step_ms=10_000,
    )
    assert len(out["series"]) >= 1
    assert out["series"][0]["name"] == "pages.count_total"


# ── #82: FD high-water log fires once per rising threshold ────────


def test_fd_high_water_logs_once_per_threshold(tmp_db, monkeypatch, capsys):
    """Crossing 500 logs once. Subsequent ticks at the same level stay
    silent. Crossing 1000 logs again."""
    cmetrics = _import_metrics()
    # Reset the seen-set so this test is order-independent.
    cmetrics._fd_high_water_seen.clear()
    monkeypatch.setattr(cmetrics, "_fd_thresholds", (500, 1000))

    # First tick: pretend num_fds=600. Crosses 500 only.
    monkeypatch.setattr(cmetrics, "_process_sample",
                        lambda: {"process.num_fds": 600.0})
    monkeypatch.setattr(cmetrics, "_community_sample", lambda: {})
    monkeypatch.setattr(cmetrics, "_drain_push_metrics", lambda: {})
    cmetrics._do_tick()
    err1 = capsys.readouterr().err
    assert "FD high-water crossed 500" in err1
    assert "crossed 1000" not in err1

    # Second tick at the same level: silent.
    cmetrics._do_tick()
    err2 = capsys.readouterr().err
    assert "FD high-water" not in err2

    # Third tick crosses 1000.
    monkeypatch.setattr(cmetrics, "_process_sample",
                        lambda: {"process.num_fds": 1100.0})
    cmetrics._do_tick()
    err3 = capsys.readouterr().err
    assert "FD high-water crossed 1000" in err3


def test_fd_high_water_silent_below_threshold(tmp_db, monkeypatch, capsys):
    """Sane FD counts (single-digit / double-digit) never log."""
    cmetrics = _import_metrics()
    cmetrics._fd_high_water_seen.clear()
    monkeypatch.setattr(cmetrics, "_fd_thresholds", (500, 1000))
    monkeypatch.setattr(cmetrics, "_process_sample",
                        lambda: {"process.num_fds": 12.0})
    monkeypatch.setattr(cmetrics, "_community_sample", lambda: {})
    monkeypatch.setattr(cmetrics, "_drain_push_metrics", lambda: {})
    cmetrics._do_tick()
    assert "FD high-water" not in capsys.readouterr().err


# ─── #93 phase 8: bundle-subsystem health gauges ──────────────────────────


def _make_bundle_envelope(*, kind: str, record_id: str, version: int = 0,
                          encrypted: bool = False, priv=None,
                          pubkey_str: str | None = None) -> dict:
    """Build a fully-signed envelope for the given kind. Mirrors the
    `make_envelope` factory in `tests/bundles/conftest.py` but lives
    here so tests in this file don't have to reach into the bundles
    test package's conftest."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from swf.bundles import sign_envelope

    if priv is None:
        priv = Ed25519PrivateKey.generate()
        raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pubkey_str = f"ed25519:{raw.hex()}"
    elif pubkey_str is None:
        raw = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pubkey_str = f"ed25519:{raw.hex()}"

    encryption: dict | None = None
    if encrypted:
        encryption = {
            "alg": "age-v1",
            "recipients": ["age1exampleexampleexampleexampleexample0000000000000"],
        }

    env: dict = {
        "magic": "swf-bundle-v1",
        "kind": kind,
        "record_id": record_id,
        "version": int(version),
        "author": {
            "pubkey": pubkey_str,
            "signed_at": "2026-05-04T12:00:00Z",
        },
        "encryption": encryption,
        "payload": base64.b64encode(b'{"hello":"world"}').decode("ascii"),
    }
    env["signature"] = sign_envelope(env, priv=priv)
    return env


@pytest.fixture
def bundles_indrex(tmp_path, monkeypatch):
    """Point `swf.indrex.db_path()` at a fresh tmp dir for tests that
    drive `_bundles_sample` directly. The bundles substrate uses the
    indrex DB (NOT community.db), so we override `SWF_KNOWLEDGE_DIR`
    on top of `SWF_COMMUNITY_DB` from `tmp_db`. Also reset the
    once-per-process missing-table-warning flag so each fresh DB
    test sees the warning fire if applicable."""
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    cmetrics = _import_metrics()
    cmetrics._reset_bundles_table_missing_logged_for_tests()
    return tmp_path / "index.db"


def test_bundles_sample_empty_db(tmp_db, bundles_indrex):
    """Fresh indrex.db with the bundles table created but empty: every
    count gauge is 0 and the alchemists/reservoir gauges reflect the
    test fixtures (no `.alchemists.yml` or `.reservoir.yml` staged ->
    both at 0)."""
    import sqlite3

    from swf.bundles import ensure_schema
    from swf.bundles.alchemists import reset_alchemists_cache_for_tests
    from swf.bundles.reservoir import reset_reservoir_cache_for_tests

    # Materialize the bundles table on a fresh indrex.db without
    # inserting any rows.
    conn = sqlite3.connect(str(bundles_indrex))
    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    reset_alchemists_cache_for_tests()
    reset_reservoir_cache_for_tests()

    cmetrics = _import_metrics()
    out = cmetrics._bundles_sample()

    assert out["bundles.count_total"] == 0.0
    assert out["bundles.count_by_kind.cohort_surface"] == 0.0
    assert out["bundles.count_by_kind.cohort_depth"] == 0.0
    assert out["bundles.count_by_kind.transcript_batch"] == 0.0
    assert out["bundles.count_by_kind.search_result"] == 0.0
    assert out["bundles.encrypted_count"] == 0.0
    # No file fixtures staged in this test — both file-backed gauges
    # land at 0 (the loaders log a stderr warning and return empty
    # rosters).
    assert out["bundles.alchemists_loaded"] == 0.0
    assert out["bundles.reservoir_keys_loaded"] == 0.0
    # No convent signing key cached, no puller thread alive.
    assert out["bundles.signing_key_loaded"] == 0.0
    assert out["bundles.puller_thread_alive"] == 0.0


def test_bundles_sample_counts_by_kind(tmp_db, bundles_indrex):
    """Insert one bundle of each kind via `bundles.insert` and verify
    each per-kind gauge matches."""
    from swf.bundles import insert

    for kind in ("cohort.surface", "cohort.depth",
                 "transcript.batch", "search.result"):
        env = _make_bundle_envelope(kind=kind, record_id=f"rec-{kind}")
        insert(env)

    cmetrics = _import_metrics()
    out = cmetrics._bundles_sample()

    assert out["bundles.count_total"] == 4.0
    assert out["bundles.count_by_kind.cohort_surface"] == 1.0
    assert out["bundles.count_by_kind.cohort_depth"] == 1.0
    assert out["bundles.count_by_kind.transcript_batch"] == 1.0
    assert out["bundles.count_by_kind.search_result"] == 1.0
    assert out["bundles.encrypted_count"] == 0.0


def test_bundles_sample_encrypted_count(tmp_db, bundles_indrex):
    """One encrypted + one plaintext: encrypted_count == 1."""
    from swf.bundles import insert

    insert(_make_bundle_envelope(
        kind="cohort.depth", record_id="enc", encrypted=True,
    ))
    insert(_make_bundle_envelope(
        kind="cohort.surface", record_id="plain", encrypted=False,
    ))

    cmetrics = _import_metrics()
    out = cmetrics._bundles_sample()

    assert out["bundles.count_total"] == 2.0
    assert out["bundles.encrypted_count"] == 1.0


def test_bundles_sample_signing_key_gauge(tmp_db, bundles_indrex, tmp_path):
    """Without convent key set the gauge is 0.0; after
    `sink.load_signing_key` is called the gauge flips to 1.0."""
    import secrets

    from swf.hivemind import sink

    sink.reset_signing_key_cache_for_tests()

    cmetrics = _import_metrics()
    out = cmetrics._bundles_sample()
    assert out["bundles.signing_key_loaded"] == 0.0

    seed_path = tmp_path / "convent-signing.key"
    seed_path.write_bytes(secrets.token_bytes(32))
    sink.load_signing_key(seed_path)

    out2 = cmetrics._bundles_sample()
    assert out2["bundles.signing_key_loaded"] == 1.0

    sink.reset_signing_key_cache_for_tests()


def test_bundles_sample_handles_missing_table(tmp_db, bundles_indrex, capsys):
    """A fresh indrex.db where `bundles.ensure_schema` has not been
    called (so the `bundles` table does not exist) MUST NOT crash
    `_bundles_sample`: it returns zeros and emits a one-line stderr
    warning."""
    # Materialize the indrex.db file without the bundles table — just
    # touch it via sqlite3 so the file exists with no schema.
    import sqlite3

    conn = sqlite3.connect(str(bundles_indrex))
    try:
        conn.execute("CREATE TABLE _placeholder(x INTEGER)")
        conn.commit()
    finally:
        conn.close()
    assert bundles_indrex.exists()

    cmetrics = _import_metrics()
    cmetrics._reset_bundles_table_missing_logged_for_tests()

    out = cmetrics._bundles_sample()

    # Counts all zero — table was missing.
    assert out["bundles.count_total"] == 0.0
    assert out["bundles.count_by_kind.cohort_surface"] == 0.0
    assert out["bundles.encrypted_count"] == 0.0

    err = capsys.readouterr().err
    assert "bundles table missing" in err

    # Second call: the once-per-process flag suppresses the repeat
    # warning so a chronically-missing table doesn't spam every tick.
    out2 = cmetrics._bundles_sample()
    err2 = capsys.readouterr().err
    assert out2["bundles.count_total"] == 0.0
    assert "bundles table missing" not in err2


def test_bundles_sample_wired_into_do_tick(tmp_db, bundles_indrex):
    """End-to-end: `_do_tick` includes the bundle gauges in its
    sample, so `/metrics/snapshot` and `/metrics/series` can both
    surface them."""
    import sqlite3

    from swf.bundles import ensure_schema, insert

    conn = sqlite3.connect(str(bundles_indrex))
    try:
        ensure_schema(conn)
        conn.commit()
    finally:
        conn.close()

    insert(_make_bundle_envelope(
        kind="cohort.surface", record_id="rec-1",
    ))

    cmetrics = _import_metrics()
    cmetrics._do_tick()

    snap = cmetrics.snapshot()
    vals = snap["values"]
    assert "bundles.count_total" in vals
    assert vals["bundles.count_total"] == 1.0
    assert "bundles.count_by_kind.cohort_surface" in vals
    assert vals["bundles.count_by_kind.cohort_surface"] == 1.0
    assert "bundles.puller_thread_alive" in vals
    assert "bundles.signing_key_loaded" in vals
