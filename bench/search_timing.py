"""TODO-11 / SPEC §27.30 timing-distinguishability microbenchmark.

Boots an in-process router via ``swf.search.web_search`` (no HTTP, no
socket — we measure the router itself, not the network), runs N calls
per scenario, records per-call wall-clock latency in microseconds, and
reports a p50/p95/p99/mean/stddev table plus a JSON dump.

This is an opt-in measurement tool, NOT a unit test. Living under
``bench/`` keeps it out of ``pytest`` collection (the smoke test in
``tests/search/test_timing_smoke.py`` invokes this file as a subprocess).

The §27.30 invariant we're checking: per-request timing should not leak
which route was used or whether tickets were required. Different
``delivery_path``\\ s (e.g. cache hit vs indrex query) ARE expected to
differ — see HARDENING_CHECKLIST §7. We assert only that *within* a
single delivery_path, two scenarios with the same path don't produce
distinguishable p95 latency. If the bench finds a leak, that's a
separate PR; this tool is the measurement, not a fix.

Stdlib only — no third-party deps, no pytest.

Usage:
    python bench/search_timing.py             # full run (N=500), assert
    python bench/search_timing.py --quick     # CI mode (N=50)
    python bench/search_timing.py --no-asserts  # report-only

Exit code:
    0 — bench ran cleanly and (if asserts on) all checks passed.
    1 — assertion failed (timing leak suspected).
    2 — bench failed to run (setup error).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import statistics
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator
from unittest.mock import patch

# Make `import swf.search` work when this file is run as a script.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from swf.search import web_search  # noqa: E402
from swf.search import lan_friend_direct  # noqa: E402
from swf.search.policy import BUILT_IN_POLICIES, SearchPolicy  # noqa: E402
from swf.search.response import (  # noqa: E402
    DeliveryPath, OriginPath, PrivacyLevel, SearchAttempt,
)
from swf.search.route import RouteOutcome  # noqa: E402


def _no_cache_local_only() -> SearchPolicy:
    """A `local_only`-style policy that DOES NOT cache. Used for the
    LOCAL_INDREX scenarios so each call really hits the indrex code
    path (rather than serving from the cache after the first call)."""
    return SearchPolicy.parse("local_only_no_cache", {
        "route_order": ["LOCAL_INDREX"],
        "allow": {
            "local_cache": False, "local_indrex": True,
            "lan_friend_dcnet": False,
            "lan_friend_direct_placeholder": False,
            "self_public_egress": False,
        },
        "public_egress": {"mode": "deny"},
        "cache": {
            "allow_result_cache": False,
            "allowed_origin_paths": [],
            "disclose_origin_paths": True,
        },
        "friend_query_visibility": {"allow_query_visible_to_friends": False},
        "anonymous_tickets": {"require_for_lan_friend_search": False},
        "routing_goal": "privacy_first",
    })


_BENCH_POLICIES: dict[str, SearchPolicy] = {
    **BUILT_IN_POLICIES,
    "local_only_no_cache": _no_cache_local_only(),
}


# ─── scenario plumbing ───────────────────────────────────────────────

DEFAULT_N = 500
QUICK_N = 50

# Per §27.30 wording in the task: same delivery_path scenarios must not
# differ in p95 by more than this many milliseconds. Different delivery
# paths are documented as inherently distinguishable in HARDENING §7.
P95_THRESHOLD_MS = 5.0


def _seed_indrex(world_knowledge_dir: Path) -> Path:
    """Build a fresh indrex db. Mirrors ``tests/search/test_router.py``
    ``_seed_indrex`` so the bench measures the same code paths the unit
    tests exercise."""
    world_knowledge_dir.mkdir(parents=True, exist_ok=True)
    db = world_knowledge_dir / "index.db"
    if db.exists():
        db.unlink()
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE VIRTUAL TABLE pages USING fts5(
              url UNINDEXED, title, content,
              fetched_at UNINDEXED,
              tokenize='porter unicode61')"""
    )
    conn.execute(
        """CREATE TABLE page_cids (
               url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
               computed_at TEXT NOT NULL)"""
    )
    # Seed enough overlapping rows so two different queries can each
    # produce a sufficient hit (the §14 sufficiency check needs ≥3
    # results by default). Mirrors `tests/search/test_router.py::
    # _seed_indrex` for the first three rows; adds three more for the
    # alt-query scenario.
    rows = [
        ("https://example.com/dp1",
         "Differential privacy I", "differential privacy bounds tutorial"),
        ("https://docs.example.org/dp2",
         "Differential privacy II", "differential privacy noise mechanism"),
        ("https://arxiv.org/abs/dp3",
         "Differential privacy III", "lower bounds on differential privacy queries"),
        ("https://example.com/ml1",
         "Machine learning I", "machine learning gradient descent overview"),
        ("https://docs.example.org/ml2",
         "Machine learning II", "machine learning regularization techniques"),
        ("https://arxiv.org/abs/ml3",
         "Machine learning III", "machine learning convergence analysis"),
    ]
    for u, t, c in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (u, t, c, "2026-04-01T00:00:00Z"),
        )
    conn.commit()
    conn.close()
    return db


@contextmanager
def _isolated_state() -> Iterator[Path]:
    """Per-bench temp tree: indrex db + cache db + cache secret. Restores
    the prior environment on exit so re-runs are independent.
    """
    tmp = Path(tempfile.mkdtemp(prefix="swf-timing-bench-"))
    wk = tmp / "world_knowledge"
    saved = {
        k: os.environ.get(k) for k in (
            "RA_WORLD_KNOWLEDGE_DIR", "SWF_CACHE_DB",
            "SWF_CACHE_SECRET_FILE", "SWF_QUERY_HMAC_SECRET",
            "SWF_FRIEND_PEERS",
        )
    }
    os.environ["RA_WORLD_KNOWLEDGE_DIR"] = str(wk)
    os.environ["SWF_CACHE_DB"] = str(tmp / "search_cache.db")
    os.environ["SWF_CACHE_SECRET_FILE"] = str(tmp / "secret.bin")
    os.environ["SWF_QUERY_HMAC_SECRET"] = "x" * 32
    os.environ["SWF_FRIEND_PEERS"] = "http://stub-peer:7777"
    try:
        _seed_indrex(wk)
        yield tmp
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _synthetic_friend_outcome(ctx, **_kwargs) -> RouteOutcome:
    """Mock for ``lan_friend_direct.search`` — returns a fixed outcome
    with no network access. Simulates the placeholder transport's shape
    without the I/O so we measure the router's own dispatch overhead."""
    now_ms = int(time.time() * 1000)
    attempt = SearchAttempt(
        path=DeliveryPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        status="unavailable",
        started_ms=now_ms, completed_ms=now_ms, duration_ms=0,
        reason="bench_stub",
        results_count=0, network_used=False, public_egress_used=False,
    )
    return RouteOutcome(
        attempt=attempt,
        results=[],
        origin_paths=[OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER],
        dominant_origin_path=OriginPath.LAN_FRIEND_DIRECT_PLACEHOLDER,
        privacy_level=PrivacyLevel.NOT_ANONYMOUS_PLACEHOLDER,
        network_used=False,
    )


# Each scenario is a (name, delivery_path, callable, prep) tuple. The
# callable is invoked under timing; prep is a one-shot setup hook
# (e.g. priming the cache for the LOCAL_CACHE replay scenario).

def _scenarios() -> list[dict[str, Any]]:
    """Return the scenario definitions. We instantiate the callables
    lazily so the same query strings are reused per run.
    """
    return [
        {
            "name": "local_indrex_hit",
            "delivery_path": "LOCAL_INDREX",
            # `local_only_no_cache` skips the cache entirely so every
            # call hits the indrex code path. The same-path comparison
            # below depends on this.
            "prep": None,
            "call": lambda: web_search("differential privacy",
                                       policy_name="local_only_no_cache",
                                       policies=_BENCH_POLICIES),
        },
        {
            "name": "local_indrex_hit_alt_query",
            "delivery_path": "LOCAL_INDREX",
            "prep": None,
            "call": lambda: web_search("machine learning",
                                       policy_name="local_only_no_cache",
                                       policies=_BENCH_POLICIES),
        },
        {
            "name": "local_cache_replay",
            "delivery_path": "LOCAL_CACHE",
            # Prime the cache: a first call under `local_only` lands on
            # LOCAL_INDREX and (per the policy's cache.allowed_origin
            # _paths) writes the result back to the cache. Subsequent
            # calls then short-circuit through LOCAL_CACHE since it
            # comes first in route_order.
            "prep": lambda: web_search("differential privacy",
                                       policy_name="local_only"),
            "call": lambda: web_search("differential privacy",
                                       policy_name="local_only"),
        },
        {
            "name": "empty_query_rejection",
            "delivery_path": "NO_RESULT",
            "prep": None,
            "call": lambda: web_search("   ", policy_name="default"),
        },
        {
            "name": "unknown_policy_rejection",
            "delivery_path": "NO_RESULT",
            "prep": None,
            "call": lambda: web_search("anything",
                                       policy_name="not_a_real_policy"),
        },
        {
            "name": "lan_friend_direct_placeholder",
            "delivery_path": "NO_RESULT",
            # The mock returns no results, so the router exhausts the
            # route_order and lands on NO_RESULT. The scenario still
            # exercises the friend handler dispatch.
            "prep": None,
            "call": lambda: web_search("placeholder transport probe",
                                       policy_name="dev_placeholder_friends"),
        },
    ]


# ─── timing harness ──────────────────────────────────────────────────

def _run_scenario(call: Callable[[], Any], n: int) -> list[float]:
    """Run ``call`` ``n`` times and return per-call latency in
    microseconds. Uses ``time.perf_counter_ns`` for stable timing.
    """
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        try:
            call()
        except Exception:
            # The bench is supposed to be lenient about call-level
            # exceptions — a router that crashes on a known input is a
            # bug, but the timing is still informative.
            pass
        t1 = time.perf_counter_ns()
        samples.append((t1 - t0) / 1000.0)
    return samples


def _summary(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"n": 0, "mean": 0.0, "stddev": 0.0,
                "p50": 0.0, "p95": 0.0, "p99": 0.0,
                "min": 0.0, "max": 0.0}
    s_sorted = sorted(samples)
    n = len(s_sorted)

    def _pct(p: float) -> float:
        # Nearest-rank percentile; stable across stdlib versions and
        # avoids the `statistics.quantiles` interpolation surprises on
        # small N.
        k = max(0, min(n - 1, math.ceil(p / 100.0 * n) - 1))
        return s_sorted[k]

    return {
        "n": n,
        "mean": statistics.fmean(s_sorted),
        "stddev": statistics.pstdev(s_sorted) if n > 1 else 0.0,
        "p50": _pct(50),
        "p95": _pct(95),
        "p99": _pct(99),
        "min": s_sorted[0],
        "max": s_sorted[-1],
    }


def _format_table(report: dict[str, Any]) -> str:
    header = (
        f"{'scenario':<34} {'path':<22} {'n':>5} "
        f"{'p50_us':>9} {'p95_us':>9} {'p99_us':>9} "
        f"{'mean_us':>9} {'sd_us':>9}"
    )
    lines = [header, "-" * len(header)]
    for row in report["scenarios"]:
        s = row["summary"]
        lines.append(
            f"{row['name']:<34} {row['delivery_path']:<22} "
            f"{s['n']:>5d} {s['p50']:>9.1f} {s['p95']:>9.1f} "
            f"{s['p99']:>9.1f} {s['mean']:>9.1f} {s['stddev']:>9.1f}"
        )
    return "\n".join(lines)


def _check_same_path_p95(report: dict[str, Any]) -> list[str]:
    """Group scenarios by ``delivery_path`` and assert that any pair
    within a group has p95 within ``P95_THRESHOLD_MS``. Returns a list
    of human-readable violation strings (empty = clean)."""
    by_path: dict[str, list[dict[str, Any]]] = {}
    for row in report["scenarios"]:
        by_path.setdefault(row["delivery_path"], []).append(row)

    violations: list[str] = []
    threshold_us = P95_THRESHOLD_MS * 1000.0
    for path, rows in by_path.items():
        if len(rows) < 2:
            continue
        for i in range(len(rows)):
            for j in range(i + 1, len(rows)):
                a, b = rows[i], rows[j]
                delta = abs(a["summary"]["p95"] - b["summary"]["p95"])
                if delta > threshold_us:
                    violations.append(
                        f"path={path}: |p95({a['name']}) - p95({b['name']})| "
                        f"= {delta / 1000.0:.2f}ms > {P95_THRESHOLD_MS}ms"
                    )
    return violations


# ─── entry point ─────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quick", action="store_true",
        help=f"Reduce N to {QUICK_N} for CI smoke runs (default N={DEFAULT_N}).",
    )
    parser.add_argument(
        "--asserts", dest="asserts", action="store_true", default=True,
        help="Enforce same-path p95 threshold (default).",
    )
    parser.add_argument(
        "--no-asserts", dest="asserts", action="store_false",
        help="Skip the p95 threshold assertion; just print the report.",
    )
    parser.add_argument(
        "--report", default=str(_REPO_ROOT / "bench" / "timing_report.json"),
        help="Path to write the JSON report.",
    )
    args = parser.parse_args(argv)

    n = QUICK_N if args.quick else DEFAULT_N

    try:
        with _isolated_state(), \
             patch.object(lan_friend_direct, "search", _synthetic_friend_outcome):
            scenarios = _scenarios()
            results: list[dict[str, Any]] = []
            for sc in scenarios:
                if sc["prep"] is not None:
                    sc["prep"]()
                # One untimed sanity call to verify the scenario lands on
                # the delivery_path we claim. Bench is meaningless if a
                # "LOCAL_INDREX" scenario actually hit the cache.
                got = sc["call"]().delivery_path.value
                if got != sc["delivery_path"]:
                    print(
                        f"scenario {sc['name']!r}: expected "
                        f"delivery_path={sc['delivery_path']}, got {got}",
                        file=sys.stderr,
                    )
                    return 2
                samples = _run_scenario(sc["call"], n)
                results.append({
                    "name": sc["name"],
                    "delivery_path": sc["delivery_path"],
                    "summary": _summary(samples),
                })
    except Exception as e:  # pragma: no cover - bench setup failure
        print(f"bench setup failed: {e!r}", file=sys.stderr)
        return 2

    report: dict[str, Any] = {
        "schema": "swf.search.timing_bench/v1",
        "spec": "SPEC_v0.3 §27.30",
        "n_per_scenario": n,
        "p95_threshold_ms": P95_THRESHOLD_MS,
        "scenarios": results,
    }
    print(_format_table(report))

    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nwrote: {report_path}")

    violations = _check_same_path_p95(report)
    if violations:
        print("\nTIMING DISTINGUISHABILITY DETECTED (same-path pairs):",
              file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        if args.asserts:
            return 1
        return 0
    print(
        "\nok — no two same-path scenarios differ by more than "
        f"{P95_THRESHOLD_MS}ms at p95."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
