"""Session-wide test isolation.

Pass-4 finding #7: tests that touch `swf.identity`, `swf.search.local_cache`,
or any helper that calls `Path.home()` without going through the env
overrides materialized real files in the developer's `~/.config/swf/`
and `~/.local/share/swf/`. Running `HOME=$(mktemp -d) pytest` produced
real `identity.key`, `cache_secret.bin`, and `search_cache.db` in the
temp HOME — confirming the leak was not contained.

This autouse session fixture re-points `HOME` and every SWF state-dir
env var at a session-scoped tmp directory. Per-test fixtures still
get their own tmp dirs via `monkeypatch.setenv`; this is the safety
net for tests that forget.
"""
from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(autouse=True, scope="session")
def _isolate_swf_home():
    """Redirect HOME at session start so any swf.* helper that resolves
    a default path against `Path.home()` lands under a session tmp,
    NOT under the developer's real home.

    Why ONLY HOME and not SWF_CONFIG_DIR/SWF_STATE_DIR: the per-DB env
    overrides take precedence inside `swf.paths`, but tests that need
    HOME to be the sole source of truth (notably the subprocess-based
    `swf-node --check` tests) break if a session env var fights their
    `monkeypatch.setenv("HOME", tmp_path)`. After PR #36, every state
    helper goes through `swf.paths.state_dir()`, which falls back to
    `Path.home() / ".local/share/swf"` — so redirecting HOME alone is
    sufficient for the leak protection.
    """
    session_tmp = Path(tempfile.mkdtemp(prefix="swf-test-session-"))
    saved_home = os.environ.get("HOME")
    os.environ["HOME"] = str(session_tmp)
    yield
    if saved_home is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = saved_home
    import shutil
    shutil.rmtree(session_tmp, ignore_errors=True)


@pytest.fixture(autouse=True, scope="session")
def _bootstrap_swf_logging():
    """#79: bootstrap the `swf.*` logger tree so module-level loggers
    write `[component] msg` lines to stderr — preserving the legacy
    `sys.stderr.write` shape that capsys-based tests grep for.

    Production wiring is in `peer_server.main()` / `peer_cli.main()`;
    in-process tests don't go through those entry points, so without
    this fixture every `logger.info(...)` would either be dropped (no
    handler) or surface only at WARNING+ via stdlib's lastResort
    handler — both of which silently break the capsys-based stderr
    assertions in `tests/test_metrics.py`, `tests/bundles/test_puller.py`,
    `tests/hivemind/test_mdns.py`, and friends.

    Idempotent: re-importing across tests is fine; `bootstrap()` itself
    is a no-op after the first call (level resolution still re-runs
    so an env var change is picked up).
    """
    from swf._logging import bootstrap
    bootstrap()
    yield


@pytest.fixture(autouse=True)
def _reset_swf_module_state():
    """#78: stop the peer-scraper daemon thread between tests and
    clear module-level once-per-process flags / caches.

    Without this, a test that calls `peer_scraper.start()` (e.g. the
    network-resilience suite) leaves the scraper thread alive into
    subsequent tests. The thread's `_emit` resolves
    `indrex.db_path()` at emit time — i.e. against the *next* test's
    `RA_WORLD_KNOWLEDGE_DIR` — and writes events into that test's DB.
    The visible failure is `test_vacuum_events_keeps_recent` seeing
    more rows than the 50 it just emitted.

    Module-level once-per-process gates also need resetting so each
    test sees the boot-time recovery paths fire fresh.

    #93 phase 7+ follow-up: also drop the shared bundle-reservoir
    cache after every test. Tests that POST to `/bundles` or
    `/hivemind/transcripts` without staging a `.reservoir.yml` leave
    the cache populated as `Reservoir(keys=[])`, which then shadows
    the next test's `SWF_RESERVOIR_FILE` env var (the cache is the
    fast-path; a non-None entry, even an empty one, prevents the
    next call from re-reading the file). Resetting at teardown means
    every test that needs the reservoir cache loads it freshly under
    its own fixture's env.

    Alchemist-cache unify follow-up: same pattern for the lifted
    alchemist cache. Now that `peer_server`, the puller, and the
    hivemind route all share `swf.bundles.alchemists._ALCHEMISTS_CACHE`,
    a single autouse teardown protects every test from cache leakage —
    no matter which call site triggered the load.

    #78 residual: PR #87 covered the peer-scraper thread + once-flags
    + discovery cache. Three more module-level state holders were
    surviving teardown and could rotate-fail the tests listed in #78:

      1. `bundles.puller._thread` — the bundle puller's daemon loop.
         Symmetric to peer_scraper.start() / stop(); started by tests
         in `tests/bundles/test_puller.py` (those clean up themselves)
         and by `peer_server._start_full_subsystems` (not exercised
         from in-process tests, but adding the stop here is safe and
         future-proofs against any test that does start it).

      2. `event_bus._emit_count` and `event_bus._recent` — module-
         level counters / deque. `_emit_count` is what
         `test_emit_triggers_opportunistic_vacuum` reasons about;
         monkeypatch.setattr(_emit_count, 0) within that test only
         saves+restores the value seen at test start, which can be
         large if a prior test (or a leaked daemon-thread emit) bumped
         it. The `_recent` deque doesn't drive any test assertion
         directly but a stale entry leaking across tests is the kind
         of state we want zeroed for hygiene. Both are reset to their
         module-init values.

      3. `peer_scraper._tick_count` — drives the prune-every-N branch
         (`_tick_count % PRUNE_EVERY_TICKS == 1`). Tests that exercise
         the first-tick prune path (e.g. `test_full_first_tick_keeps_yaml_peer`)
         monkeypatch this to 0 and rely on `_tick` advancing it from
         there; if a prior full-suite test leaked `_tick` calls into
         it, the value at test-start could be in the prune-firing
         window even before the test's `_tick`. Reset to 0 for
         determinism.
    """
    yield
    try:
        from swf import peer_scraper
        peer_scraper.stop()
        peer_scraper._yaml_bootstrap_done = False
        peer_scraper._orphan_reset_done = False
        peer_scraper._self_purge_done = False
        with peer_scraper._tick_count_lock:
            peer_scraper._tick_count = 0
        with peer_scraper._discovery_cache_lock:
            peer_scraper._discovery_cache.clear()
            peer_scraper._discovery_cache_ts = 0.0
        with contextlib.suppress(AttributeError):
            peer_scraper._self_pubkey.cache_clear()
    except Exception:
        pass
    try:
        from swf.bundles import puller as _puller
        _puller.stop_puller()
    except Exception:
        pass
    try:
        from swf import event_bus
        with event_bus._emit_count_lock:
            event_bus._emit_count = 0
        event_bus._recent.clear()
        # `event_bus._subscribers` is a module-level list of live
        # queue.Queue objects. `subscribe()` removes via finally,
        # but a test exception that escapes its try/finally (timeout
        # path, async cleanup gap) leaks a queue into the next test's
        # `emit()` fan-out. Clear unconditionally — defense in depth
        # for a future flake we haven't reproduced yet (#114 PR body).
        with event_bus._subscribers_lock:
            event_bus._subscribers.clear()
    except Exception:
        pass
    try:
        from swf import discovery
        discovery.clear_ip_change_hooks()
    except Exception:
        pass
    try:
        from swf.bundles.reservoir import reset_reservoir_cache_for_tests
        reset_reservoir_cache_for_tests()
    except Exception:
        pass
    try:
        from swf.bundles.alchemists import reset_alchemists_cache_for_tests
        reset_alchemists_cache_for_tests()
    except Exception:
        pass
    try:
        # `swf.hivemind.sink._SIGNING_KEY_CACHE` is a module-level
        # cached Ed25519PrivateKey. The cache key is the resolved
        # path; if a test loads a different seed at the same path
        # (or the same seed at a different path) without resetting,
        # the next call returns the previous test's key. The reset
        # hook exists in the module; the wiring into the autouse
        # teardown was missing (#114 PR body).
        from swf.hivemind.sink import reset_signing_key_cache_for_tests
        reset_signing_key_cache_for_tests()
    except Exception:
        pass
