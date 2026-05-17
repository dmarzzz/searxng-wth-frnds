"""Self-contained metrics collector + query layer for the wall.

Design:
- A single background thread ticks every SWF_METRICS_INTERVAL_SECS (default
  10s) and inserts samples into the `metrics_samples` table.
- Push-style metrics (search durations, scrape durations) are recorded into
  ring buffers via `record_search` / `record_scrape`; each tick flushes
  count + p50 + p95 + error counts and resets the buffers.
- Maintenance pass every hour deletes rows older than 7 days.
- Two query helpers — `snapshot()` and `series()` — are used by the
  /metrics/snapshot and /metrics/series HTTP endpoints respectively.

Self-contained: only depends on `psutil` (added to project deps) plus the
stdlib + the existing community.db. No Prometheus, no daemons.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import threading
import time
from collections import deque
from collections.abc import Iterable

try:  # psutil is now a hard dep but keep the failure ergonomic
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore

from . import db

logger = logging.getLogger(__name__)

# ─── config ───────────────────────────────────────────────────────────────
INTERVAL_SECS = max(2, int(os.environ.get("SWF_METRICS_INTERVAL_SECS", "10")))
RETENTION_DAYS = max(1, int(os.environ.get("SWF_METRICS_RETENTION_DAYS", "7")))
MAINTENANCE_INTERVAL_SECS = 3600  # 1 hour

# #82: FD-leak guard. The peer-server's ThreadingHTTPServer keeps an
# FD per in-flight connection; a local prober that RSTs mid-handshake
# at high rate has been observed pushing num_fds into the thousands
# before the OS reaps. The exact reset path is now quiet (see
# `_QuietThreadingHTTPServer.handle_error`), but the FD high-water
# is the load-bearing signal for "something is still off." We log
# once per rising threshold crossing — never spam, never silent.
# Override via SWF_FD_HIGH_WATER (single int) or accept the defaults.
_FD_DEFAULT_THRESHOLDS = (500, 1000, 2000, 4000, 8000)
_fd_thresholds: tuple[int, ...] = (
    tuple(sorted({int(x) for x in os.environ["SWF_FD_HIGH_WATER"].split(",")
                  if x.strip().isdigit()}))
    if os.environ.get("SWF_FD_HIGH_WATER")
    else _FD_DEFAULT_THRESHOLDS
)
_fd_high_water_seen: set[int] = set()

# Ring sizes — bounded. Heavy traffic between ticks doesn't grow unbounded
# memory; we keep the most recent N observations per kind, since the goal
# is "what does the latest 10s window look like" not full audit history.
_RING_MAX = 5_000


# ─── push-style buffers ───────────────────────────────────────────────────
# Locked because /web_search and the scraper run on different threads from
# the metrics ticker.
_lock = threading.Lock()
_search_durations_ms: deque[float] = deque(maxlen=_RING_MAX)
_search_total = 0
_search_errors = 0
_scrape_durations_ms: deque[float] = deque(maxlen=_RING_MAX)
_scrape_total = 0
_scrape_errors = 0


def record_search(duration_ms: float, *, ok: bool = True) -> None:
    """Called by the /web_search handler. Cheap; never throws."""
    global _search_total, _search_errors
    try:
        with _lock:
            _search_durations_ms.append(float(duration_ms))
            _search_total += 1
            if not ok:
                _search_errors += 1
    except Exception:
        pass


def record_scrape(duration_ms: float, *, ok: bool = True) -> None:
    """Called by the slice-scraper for every _pull_slice attempt."""
    global _scrape_total, _scrape_errors
    try:
        with _lock:
            _scrape_durations_ms.append(float(duration_ms))
            _scrape_total += 1
            if not ok:
                _scrape_errors += 1
    except Exception:
        pass


# ─── sampling ─────────────────────────────────────────────────────────────


def _percentile(values: list[float], pct: float) -> float:
    """Naive linear-interpolation percentile. Works on tiny lists; we never
    hand it more than a few thousand entries per tick."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _process_sample() -> dict[str, float]:
    """RSS / CPU% / fd-count for THIS process. psutil.Process(None) is the
    current process. cpu_percent(interval=None) returns the percentage
    since the previous call, so we keep a singleton to make the cadence
    consistent with INTERVAL_SECS."""
    if psutil is None:
        return {}
    try:
        proc = _process_singleton()
        out: dict[str, float] = {}
        # cpu_percent returns 0.0 on the very first call; that's fine — the
        # tick after that has a meaningful number.
        out["process.cpu_percent"] = float(proc.cpu_percent(interval=None))
        out["process.rss_bytes"] = float(proc.memory_info().rss)
        # num_fds is unix-only. macOS supports it; Windows does not. Skip on
        # any failure rather than killing the metrics thread.
        with contextlib.suppress(AttributeError, OSError):
            out["process.num_fds"] = float(proc.num_fds())
        return out
    except Exception:
        return {}


_proc_singleton: psutil.Process | None = None


def _process_singleton():  # type: ignore[no-untyped-def]
    global _proc_singleton
    if _proc_singleton is None and psutil is not None:
        _proc_singleton = psutil.Process()
    return _proc_singleton


def _community_sample() -> dict[str, float]:
    """Snapshot peer + page counts from indrex.db (the single-graph
    store post-#43). The legacy community.db `contributions` table no
    longer exists; we drop that gauge.

    Always returns the three baseline keys (`peers.count_known`,
    `peers.count_active`, `pages.count_total`) at 0.0 so a fresh
    deploy without indrex.db yet still gives the wall something to
    render on first paint."""
    out: dict[str, float] = {
        "peers.count_known": 0.0,
        "peers.count_active": 0.0,
        "pages.count_total": 0.0,
    }
    try:
        import sqlite3

        from swf import indrex
        p = indrex.db_path()
        if not p.exists():
            return out
        try:
            uri = f"file:{p}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=0.5)
        except sqlite3.OperationalError:
            return out
        conn.row_factory = sqlite3.Row
        try:
            try:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM peers"
                ).fetchone()
                if row is not None:
                    out["peers.count_known"] = float(row["n"])
                from datetime import datetime, timedelta, timezone
                cutoff = (
                    datetime.now(timezone.utc) - timedelta(minutes=5)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM peers "
                    "WHERE last_seen_at IS NOT NULL AND last_seen_at > ?",
                    (cutoff,),
                ).fetchone()
                if row is not None:
                    out["peers.count_active"] = float(row["n"])
            except sqlite3.OperationalError:
                pass
            try:
                row = conn.execute("SELECT COUNT(*) AS n FROM pages").fetchone()
                if row is not None:
                    out["pages.count_total"] = float(row["n"])
            except sqlite3.OperationalError:
                pass
            # events.lag_secs from the indrex events table (#43 PR B).
            try:
                row = conn.execute(
                    "SELECT MAX(ts) AS last_ts FROM events"
                ).fetchone()
                last_ts = row["last_ts"] if row is not None else None
                if last_ts:
                    from datetime import datetime, timezone
                    try:
                        if last_ts.endswith("Z"):
                            last_ts_clean = last_ts[:-1]
                        else:
                            last_ts_clean = last_ts
                        if "." in last_ts_clean:
                            last_ts_clean = last_ts_clean.split(".", 1)[0]
                        last_dt = datetime.strptime(
                            last_ts_clean, "%Y-%m-%dT%H:%M:%S"
                        ).replace(tzinfo=timezone.utc)
                        lag = (datetime.now(timezone.utc) - last_dt).total_seconds()
                        out["events.lag_secs"] = max(0.0, float(lag))
                    except Exception:
                        pass
            except sqlite3.OperationalError:
                pass
        finally:
            conn.close()
    except Exception:
        pass
    return out


def _bundles_sample() -> dict[str, float]:
    """Bundle-subsystem health gauges. Best-effort; never raises.

    Reads from indrex.db's `bundles` table (counts by kind, encrypted
    count) and from in-memory caches (alchemists, reservoir, sink
    signing key, puller daemon). Operators see at-a-glance whether the
    bundle substrate is wired up: alchemists.yml loaded? reservoir
    staged? convent signing key cached? puller thread alive?

    Always emits the count gauges at 0.0 even when the `bundles` table
    is missing entirely (fresh DB before `ensure_schema` fired) so a
    cold-start `/metrics/snapshot` still has the keys present —
    matches `_community_sample`'s baseline-keys convention.
    """
    out: dict[str, float] = {
        "bundles.count_total": 0.0,
        "bundles.count_by_kind.cohort_surface": 0.0,
        "bundles.count_by_kind.cohort_depth": 0.0,
        "bundles.count_by_kind.transcript_batch": 0.0,
        "bundles.count_by_kind.search_result": 0.0,
        "bundles.encrypted_count": 0.0,
        "bundles.alchemists_loaded": 0.0,
        "bundles.reservoir_keys_loaded": 0.0,
        "bundles.signing_key_loaded": 0.0,
        "bundles.puller_thread_alive": 0.0,
        "bundles.puller_last_visited": 0.0,
        "bundles.puller_last_pulled": 0.0,
        "bundles.puller_last_failed": 0.0,
    }

    # Counts from the bundles table. A fresh indrex.db without the
    # bundles table (substrate not yet wired up) is NOT a crash — we
    # warn once, stay silent thereafter, and serve zeros.
    try:
        import sqlite3

        from swf import indrex
        p = indrex.db_path()
        if p.exists():
            try:
                uri = f"file:{p}?mode=ro"
                conn = sqlite3.connect(uri, uri=True, timeout=0.5)
            except sqlite3.OperationalError:
                conn = None
            if conn is not None:
                conn.row_factory = sqlite3.Row
                try:
                    try:
                        row = conn.execute(
                            "SELECT COUNT(*) AS n FROM bundles"
                        ).fetchone()
                        if row is not None:
                            out["bundles.count_total"] = float(row["n"])
                    except sqlite3.OperationalError:
                        # No `bundles` table — fresh DB before
                        # `bundles.ensure_schema` fired. Emit zeros and
                        # log once so the operator sees the gap without
                        # a per-tick spam.
                        global _bundles_table_missing_logged
                        if not _bundles_table_missing_logged:
                            _bundles_table_missing_logged = True
                            logger.warning(
                                "bundles table missing; "
                                "emitting zeros until bundles.ensure_schema runs",
                            )
                        return out

                    # Per-kind counts. The keyspace uses underscores
                    # because the metric-name convention treats `.` as
                    # a hierarchy separator (e.g. `pages.count_total`)
                    # — so the `cohort.surface` kind becomes
                    # `bundles.count_by_kind.cohort_surface`.
                    try:
                        rows = conn.execute(
                            "SELECT kind, COUNT(*) AS n FROM bundles "
                            "GROUP BY kind"
                        ).fetchall()
                        for r in rows or []:
                            kind = r["kind"] or ""
                            sub = kind.replace(".", "_")
                            out[f"bundles.count_by_kind.{sub}"] = float(r["n"])
                    except sqlite3.OperationalError:
                        pass
                    try:
                        row = conn.execute(
                            "SELECT COUNT(*) AS n FROM bundles "
                            "WHERE encryption_alg IS NOT NULL"
                        ).fetchone()
                        if row is not None:
                            out["bundles.encrypted_count"] = float(row["n"])
                    except sqlite3.OperationalError:
                        pass
                finally:
                    conn.close()
    except Exception:
        pass

    # Alchemist roster + reservoir size. Both helpers are
    # mtime-guarded caches — calling them on every tick is cheap (one
    # stat() per file) and gives operators a live view of whether
    # `.alchemists.yml` / `.reservoir.yml` got picked up after an edit.
    try:
        from swf.bundles.alchemists import load_alchemists_cached
        out["bundles.alchemists_loaded"] = float(
            len(load_alchemists_cached().members)
        )
    except Exception:
        pass
    try:
        from swf.bundles.reservoir import load_reservoir_cached
        out["bundles.reservoir_keys_loaded"] = float(
            len(load_reservoir_cached().pubkeys())
        )
    except Exception:
        pass

    # Sink signing key. We DO NOT trigger a load here — that would
    # pay the file-IO and crash on a missing seed (which is the normal
    # state on a non-convent peer). Use the read-only introspection
    # helper instead, so the gauge is 0.0 until something else in the
    # process loads the key.
    try:
        from swf.hivemind.sink import signing_key_cached
        out["bundles.signing_key_loaded"] = 1.0 if signing_key_cached() else 0.0
    except Exception:
        pass

    # Puller daemon liveness + last-tick stats. The puller is started
    # by `peer_server._start_full_subsystems` under --full; the gauges
    # are 0.0 on a peer that hasn't been started in --full mode (or on
    # a node where the operator disabled the puller via
    # SWF_BUNDLE_PULL_INTERVAL_SECS=0). The (visited, pulled, failed)
    # tuple captures the most recent tick's pass over the LAN — a
    # stuck puller surfaces as `visited=0` even when peers exist.
    try:
        from swf.bundles.puller import is_thread_alive, puller_stats
        out["bundles.puller_thread_alive"] = 1.0 if is_thread_alive() else 0.0
        visited, pulled, failed = puller_stats()
        out["bundles.puller_last_visited"] = float(visited)
        out["bundles.puller_last_pulled"] = float(pulled)
        out["bundles.puller_last_failed"] = float(failed)
    except Exception:
        pass

    return out


# Once-per-process flag for the missing-bundles-table warning. Module
# scope so the warning fires the first time `_bundles_sample` notices
# the gap and stays silent on subsequent ticks. Reset by tests via
# `_reset_bundles_table_missing_logged_for_tests`.
_bundles_table_missing_logged: bool = False


def _reset_bundles_table_missing_logged_for_tests() -> None:
    """Clear the once-per-process bundles-table-missing-logged flag.
    Tests that drive `_bundles_sample` against multiple tmp DBs call
    this between cases so each fresh DB gets a fresh warning."""
    global _bundles_table_missing_logged
    _bundles_table_missing_logged = False


def _drain_push_metrics() -> dict[str, float]:
    """Atomically drain the push-style ring buffers into a tick snapshot."""
    global _search_total, _search_errors, _scrape_total, _scrape_errors
    with _lock:
        s_durs = list(_search_durations_ms)
        sc_durs = list(_scrape_durations_ms)
        s_tot = _search_total
        s_err = _search_errors
        sc_tot = _scrape_total
        sc_err = _scrape_errors
        _search_durations_ms.clear()
        _scrape_durations_ms.clear()
        _search_total = 0
        _search_errors = 0
        _scrape_total = 0
        _scrape_errors = 0
    out: dict[str, float] = {}
    if s_durs:
        out["web_search.duration_ms_p50"] = _percentile(s_durs, 0.50)
        out["web_search.duration_ms_p95"] = _percentile(s_durs, 0.95)
    out["web_search.total"] = float(s_tot)
    out["web_search.errors"] = float(s_err)
    if sc_durs:
        out["slice_scrape.duration_ms_p50"] = _percentile(sc_durs, 0.50)
        out["slice_scrape.duration_ms_p95"] = _percentile(sc_durs, 0.95)
    out["slice_scrape.total"] = float(sc_tot)
    out["slice_scrape.errors"] = float(sc_err)
    return out


def _insert_samples(values: dict[str, float], *, ts_ms: int | None = None) -> None:
    if not values:
        return
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    rows = [(ts_ms, k, float(v), "") for k, v in values.items()]
    try:
        with db.writer() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO metrics_samples(ts_ms, name, value, labels_json) "
                "VALUES (?, ?, ?, ?)",
                rows,
            )
    except Exception as exc:
        logger.error("insert failed: %s", exc)


# Latest snapshot is cached so /metrics/snapshot can return without a
# round-trip to the DB on the hot path.
_latest_snapshot: dict[str, float] = {}
_latest_snapshot_ts: int = 0
_latest_lock = threading.Lock()


def _do_tick() -> None:
    """One sampling tick. Composes process + community + push samples and
    persists them to metrics_samples."""
    global _latest_snapshot, _latest_snapshot_ts
    ts_ms = int(time.time() * 1000)
    sample: dict[str, float] = {}
    sample.update(_process_sample())
    sample.update(_community_sample())
    sample.update(_bundles_sample())
    sample.update(_drain_push_metrics())
    # #82: surface the swallowed-loopback-reset count. Tells an operator
    # whether a probe is still hammering loopback even though the log
    # has gone quiet.
    try:
        from swf import peer_server as _ps
        sample["peer_server.loopback_resets"] = float(_ps.loopback_reset_count())
    except Exception:
        pass
    _insert_samples(sample, ts_ms=ts_ms)
    # #82: FD high-water log. Fires once per rising threshold crossing so
    # repeat ticks at the same level stay silent.
    fds = sample.get("process.num_fds")
    if fds is not None:
        fd_int = int(fds)
        for t in _fd_thresholds:
            if fd_int >= t and t not in _fd_high_water_seen:
                _fd_high_water_seen.add(t)
                resets = int(sample.get("peer_server.loopback_resets", 0))
                logger.warning(
                    "FD high-water crossed %s "
                    "(num_fds=%s loopback_resets=%s). "
                    "If this keeps climbing, run "
                    "`lsof -nP -iTCP:7777 -sTCP:ESTABLISHED` to find "
                    "the local culprit.",
                    t, fd_int, resets,
                )
    with _latest_lock:
        _latest_snapshot = dict(sample)
        _latest_snapshot_ts = ts_ms


def _do_maintenance() -> None:
    cutoff_ms = int((time.time() - RETENTION_DAYS * 24 * 3600) * 1000)
    try:
        with db.writer() as conn:
            conn.execute(
                "DELETE FROM metrics_samples WHERE ts_ms < ?", (cutoff_ms,)
            )
    except Exception as exc:
        logger.error("retention sweep failed: %s", exc)


# ─── ticker thread ────────────────────────────────────────────────────────
_started = False
_stop = threading.Event()


def start() -> None:
    """Idempotent. Called from peer_server's _start_full_subsystems."""
    global _started
    if _started:
        return
    _started = True
    if psutil is None:
        logger.warning(
            "psutil not installed — process samples will be skipped",
        )

    def loop() -> None:
        last_maint = time.monotonic()
        # Prime cpu_percent so the first real tick has a delta.
        try:
            if psutil is not None:
                _process_singleton().cpu_percent(interval=None)
        except Exception:
            pass
        while not _stop.is_set():
            try:
                _do_tick()
            except Exception as exc:
                logger.error("tick error: %s", exc)
            now = time.monotonic()
            if now - last_maint >= MAINTENANCE_INTERVAL_SECS:
                last_maint = now
                try:
                    _do_maintenance()
                except Exception as exc:
                    logger.error("maintenance error: %s", exc)
            # Sleep with early-exit on stop event so tests can shut us down.
            _stop.wait(INTERVAL_SECS)

    t = threading.Thread(target=loop, name="swf-metrics", daemon=True)
    t.start()


def stop() -> None:
    """Mostly for tests."""
    _stop.set()


# ─── HTTP query helpers ───────────────────────────────────────────────────


def snapshot() -> dict:
    """Live values for the dashboard top stat row.

    Reads the cached values from the most recent tick. If the ticker has
    not run yet we fall back to a one-shot sample so the wall has something
    to show on a cold start, plus a fresh community-count query."""
    with _latest_lock:
        cached = dict(_latest_snapshot)
        ts_ms = _latest_snapshot_ts
    if not cached:
        cached = {}
        cached.update(_community_sample())
        cached.update(_bundles_sample())
        ts_ms = int(time.time() * 1000)
    else:
        # Always overlay fresh community + bundle counts — they're cheap
        # and the user expects /metrics/snapshot to feel live, not
        # 10s-stale.
        cached.update(_community_sample())
        cached.update(_bundles_sample())
    return {"ts_ms": ts_ms, "values": cached}


def series(
    names: Iterable[str],
    *,
    from_ms: int,
    until_ms: int,
    step_ms: int = 60_000,
    max_rows: int = 5_000,
) -> dict:
    """Query bucketed time-series for the given metric names.

    Server-side bucketing collapses all samples falling inside a given
    `step_ms` window into one row per (name, bucket). Buckets are aligned
    to from_ms so consecutive `/metrics/series` calls with the same step
    produce consistent grids.

    Returns:
      {
        "names": [...],
        "step_ms": int,
        "from_ms": int,
        "until_ms": int,
        "series": [{ts_ms: int, name: str, value: float}, ...],
        "truncated": bool,
      }
    """
    names = list(dict.fromkeys(n for n in names if n))[:64]  # de-dup, cap
    if not names or step_ms <= 0 or until_ms <= from_ms:
        return {"names": names, "step_ms": step_ms, "from_ms": from_ms,
                "until_ms": until_ms, "series": [], "truncated": False}
    placeholders = ",".join("?" * len(names))
    bucket_expr = (
        "((ts_ms - ?) / ?) * ? + ?"
    )  # floor((ts - from) / step) * step + from
    sql = (
        f"SELECT name, {bucket_expr} AS bucket_ts, AVG(value) AS value "
        f"FROM metrics_samples "
        f"WHERE name IN ({placeholders}) AND ts_ms >= ? AND ts_ms < ? "
        f"GROUP BY name, bucket_ts "
        f"ORDER BY bucket_ts ASC, name ASC "
        f"LIMIT ?"
    )
    params: list = [from_ms, step_ms, step_ms, from_ms, *names, from_ms,
                    until_ms, max_rows + 1]
    try:
        with db.reader() as conn:
            rows = conn.execute(sql, params).fetchall()
    except Exception as exc:
        logger.error("series query failed: %s", exc)
        rows = []
    truncated = len(rows) > max_rows
    rows = rows[:max_rows]
    return {
        "names": names,
        "step_ms": step_ms,
        "from_ms": from_ms,
        "until_ms": until_ms,
        "series": [
            {"ts_ms": int(r["bucket_ts"]), "name": r["name"],
             "value": float(r["value"])}
            for r in rows
        ],
        "truncated": truncated,
    }


# ─── small JSON helper used by peer_server ────────────────────────────────


def snapshot_json() -> str:
    return json.dumps(snapshot())


def series_json(names: Iterable[str], *, from_ms: int, until_ms: int,
                step_ms: int = 60_000) -> str:
    return json.dumps(series(names, from_ms=from_ms, until_ms=until_ms,
                              step_ms=step_ms))
