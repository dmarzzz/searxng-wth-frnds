"""Regression tests for the autouse `_reset_swf_module_state` teardown
in `tests/conftest.py`.

When the bundle subsystem grew, several module-level globals were
accumulating across test boundaries. PR #87 covered the load-bearing
cases; PR #114 added three more (`bundles.puller._thread`,
`event_bus._emit_count`, `peer_scraper._tick_count`); this PR closes
the residual two flagged in #114's body but not yet wired:

  * `event_bus._subscribers` — list of live subscriber queues. The
    `subscribe()` generator removes via finally, but an exception
    escape leaks a queue.

  * `hivemind.sink._SIGNING_KEY_CACHE` — module-level cached signing
    key. The reset hook exists in the module but wasn't called from
    the autouse teardown.

These tests pin that the autouse fixture clears both. If a future
refactor splits the teardown or moves the cleanup elsewhere, the
tests fail with a clear "future-flake risk" message.

The tests deliberately work by checking the post-teardown state from
a SEPARATE test function — pytest runs each test through its own
autouse cycle, so by the time the second test runs, the prior test's
state should already be gone.
"""
from __future__ import annotations

import queue


def test_event_bus_subscribers_polluted_by_first_test():
    """First test in the pair: leak a subscriber queue WITHOUT the
    finally cleanup that `subscribe()` provides. Direct list mutation
    simulates the exception-escape race.

    The autouse teardown after this test must clear the leaked entry,
    so the paired test below sees an empty list."""
    from swf import event_bus
    leaked: queue.Queue = queue.Queue(maxsize=1)
    with event_bus._subscribers_lock:
        event_bus._subscribers.append(leaked)
        assert leaked in event_bus._subscribers


def test_event_bus_subscribers_cleared_by_teardown_in_prior_test():
    """Second test in the pair (alphabetical ordering puts this AFTER
    the leaker — `_cleared_` < `_polluted_` is false; `_cleared_`
    sorts later in pytest's default collection order, but pytest
    actually runs in file-source order, so the function above runs
    first). The autouse teardown should have wiped the leaked entry."""
    from swf import event_bus
    with event_bus._subscribers_lock:
        # The leaked queue from the previous test should be gone.
        # Other tests may have legitimately left their own subscribers
        # if they don't go through the autouse cycle, but in practice
        # nothing in the rest of the suite holds a `_subscribers` row
        # at autouse-teardown time. Assert the list is empty.
        assert event_bus._subscribers == [], (
            "subscribers leaked across tests — autouse teardown is "
            "supposed to clear the list (see conftest.py)"
        )


def test_hivemind_signing_key_polluted_by_first_test():
    """First test in the pair: poison the hivemind signing-key cache
    with a sentinel."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from swf.hivemind import sink
    sentinel = Ed25519PrivateKey.generate()
    sink._SIGNING_KEY_CACHE = sentinel
    sink._SIGNING_KEY_CACHE_PATH = type("FakePath", (), {})()
    assert sink._SIGNING_KEY_CACHE is sentinel


def test_hivemind_signing_key_cleared_by_teardown_in_prior_test():
    """Second test: the autouse teardown must have called
    `reset_signing_key_cache_for_tests()` between the two test
    functions, so the cache is clear."""
    from swf.hivemind import sink
    assert sink._SIGNING_KEY_CACHE is None, (
        "signing key leaked across tests — autouse teardown should "
        "call reset_signing_key_cache_for_tests (see conftest.py)"
    )
    assert sink._SIGNING_KEY_CACHE_PATH is None
