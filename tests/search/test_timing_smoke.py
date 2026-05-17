"""Smoke test for ``bench/search_timing.py``.

The bench itself lives under ``bench/`` (NOT ``tests/``) because it's an
opt-in measurement tool, not a unit test of correctness. This file is
the unit-test seam: we run the bench in ``--quick`` mode (N=50) via
subprocess, assert exit 0, and verify the JSON report has the expected
scenario set. If a future change breaks the bench's setup or moves a
scenario, this fails fast.

The full-fat run (N=500) is meant to be invoked manually or by CI on a
hardening pass; the smoke is sized so it won't dominate `pytest -q`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BENCH = _REPO_ROOT / "bench" / "search_timing.py"

# Same scenario names defined in `bench/search_timing.py::_scenarios`.
EXPECTED_SCENARIOS = {
    "local_indrex_hit",
    "local_indrex_hit_alt_query",
    "local_cache_replay",
    "empty_query_rejection",
    "unknown_policy_rejection",
    "lan_friend_direct_placeholder",
}


@pytest.fixture
def report_path(tmp_path: Path) -> Path:
    return tmp_path / "timing_report.json"


def test_search_timing_bench_quick_smoke(report_path: Path):
    """Running `python bench/search_timing.py --quick` exits 0 and
    writes a JSON report with all expected scenarios."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_REPO_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, str(_BENCH), "--quick", "--report", str(report_path)]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True,
                          timeout=120)
    assert proc.returncode == 0, (
        f"bench exited non-zero ({proc.returncode}).\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert report_path.exists(), "bench did not write the JSON report"

    report = json.loads(report_path.read_text())
    assert report["schema"] == "swf.search.timing_bench/v1"
    assert report["n_per_scenario"] == 50  # --quick reduces N

    names = {row["name"] for row in report["scenarios"]}
    assert names == EXPECTED_SCENARIOS, (
        f"missing scenarios: {EXPECTED_SCENARIOS - names}; "
        f"unexpected: {names - EXPECTED_SCENARIOS}"
    )

    # Every scenario must report its summary block. We don't pin
    # specific latency numbers (machine-dependent); we pin the SHAPE
    # so the bench can't silently drop a column the parent tooling
    # depends on.
    for row in report["scenarios"]:
        s = row["summary"]
        for k in ("n", "p50", "p95", "p99", "mean", "stddev", "min", "max"):
            assert k in s, f"missing key {k!r} in scenario {row['name']!r}"
        assert s["n"] == 50
