"""In-process node event ring buffer (docs/SYNC.md §12 + §13).

A tiny ring of the most recent daemon events, surfaced over the
read-only `GET /node/log` endpoint (and the back-compat
`GET /sync/log`, which filters down to category="sync") so the SROS
renderer can show a single unified "what the daemon is doing right
now" feed — sync activity, mDNS discovery, peer health, ingest, web
search.

Originally introduced in v0.11.3 for sync events only. v0.12.0
generalized it to a node-wide log by adding a `category` field and
spreading emit sites across discovery, scraping, bundle pulling, and
search.

Design constraints:
  * The emit path may be on a hot loop (sync ticks, mDNS callbacks).
    Lock contention has to be minimal: a single `threading.Lock`,
    increment seq, append to deque. No JSON encoding, no logging,
    no I/O inside the lock.
  * The ring is per-process. Restarts wipe it. That is intentional —
    this is a live observability surface for the renderer, NOT a
    durable journal.
  * `seq` is a hand-rolled monotonic int. We do NOT rely on `ts_ms`
    for ordering or cursor semantics; two events at the same wall ms
    must still be totally ordered for resumable polling.

Public surface:
  * `emit_node_event(kind, *, category, payload=None, **kwargs)` —
    primary emitter used by the sync loop, mDNS browser, peer
    scrapers, bundle puller, and web-search handler. `payload=` is
    the collision-safe channel for payloads whose field names
    overlap with the function signature (e.g. the `scraper_pulled`
    event's `kind: "pages"|"bundles"`).
  * `emit_sync_event(kind, **payload)` — deprecated alias that
    auto-fills `category="sync"`. Kept so older call sites that
    import the v0.11.3 name keep working.
  * `get_node_events(since_seq=..., since_ms=..., limit=...,
    categories=...)` — snapshot read used by the `/node/log`
    endpoint.
  * `get_sync_events(...)` — deprecated alias that filters to
    category="sync" for back-compat with the v0.11.3 `/sync/log`.
  * `tail_seq()` — highest seq in the ring (or 0 if empty), exposed
    so endpoint handlers can hand the client a resume cursor even
    when the filtered slice is empty.
  * `reset_event_log_for_tests()` — clears the ring + counter
    between tests.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

# Renderer-tail, not a journal. 200 keeps memory bounded (~200 small
# dicts) and matches the default poll limit so a slow client never
# pulls a partial window.
_RING_MAXLEN = 200

# Enumerated categories. Not enforced at emit time (the emit hot path
# stays cheap) — used by the renderer + endpoint filter to slice the
# stream. Keep in lockstep with docs/SYNC.md §13.
NODE_EVENT_CATEGORIES: frozenset[str] = frozenset({
    "sync", "mdns", "health", "ingest", "search", "error",
})

# Module-level state. Guarded by `_event_lock`.
_event_ring: deque[dict[str, Any]] = deque(maxlen=_RING_MAXLEN)
_event_lock = threading.Lock()
_event_seq = 0  # monotonic counter; never decreases, never wraps in practice


def emit_node_event(
    kind: str,
    *,
    category: str,
    payload: dict[str, Any] | None = None,
    **kwargs: Any,
) -> None:
    """Append a node event to the ring buffer.

    `category` is one of `NODE_EVENT_CATEGORIES` (see docs/SYNC.md
    §13.1). The emit path does NOT validate the value — a typo in a
    new emit site would otherwise crash the daemon's actual work.
    Callers are expected to use the canonical names.

    The event payload can be supplied two ways, and they merge:

    - `**kwargs` — convenient for emit sites whose field names don't
      collide with Python keyword args (this is most of them).
    - `payload=` — required when a payload field name collides with
      the function signature itself (e.g. the `scraper_pulled`
      event's `kind: "pages"|"bundles"` field clashes with the
      positional `kind` parameter). Callers pass
      `payload={"kind": "pages", ...}`.

    The critical section is: bump seq, build dict, append. We don't
    log here; existing subsystem-specific log lines (e.g. the sync
    loop's `[sync-loop] tick visited=N pulled=K applied=M`) continue
    to emit independently so ops users see the same signals they
    always did.

    Reserved fields (`seq`, `kind`, `category`, `ts_ms`) cannot be
    overwritten by caller payload — collisions silently drop the
    caller's value.
    """
    global _event_seq
    with _event_lock:
        _event_seq += 1
        evt: dict[str, Any] = {
            "seq": _event_seq,
            "kind": kind,
            "category": category,
            "ts_ms": int(time.time() * 1000),
        }
        # `payload` merges first (the explicit dict form is the
        # collision-safe channel); then **kwargs overlays any
        # convenience fields. Reserved field protection applies to
        # both.
        merged: dict[str, Any] = {}
        if payload:
            merged.update(payload)
        merged.update(kwargs)
        for k, v in merged.items():
            if k in ("seq", "kind", "category", "ts_ms"):
                continue
            evt[k] = v
        _event_ring.append(evt)


def emit_sync_event(kind: str, **payload: Any) -> None:
    """Deprecated alias for `emit_node_event(kind, category="sync")`.

    Kept for back-compat with v0.11.3 call sites (sync loop,
    `/sync/local_record` handler) that imported this name before
    the generalization in v0.12.0. New code should call
    `emit_node_event` directly with an explicit `category`.
    """
    emit_node_event(kind, category="sync", **payload)


def get_node_events(
    *,
    since_seq: int | None = None,
    since_ms: int | None = None,
    limit: int = _RING_MAXLEN,
    categories: frozenset[str] | set[str] | tuple[str, ...] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """Snapshot the ring under the lock, filter outside.

    `since_seq` is the primary cursor — monotonic, no ts collisions.
    `since_ms` is a fallback for clients that don't track seq (e.g.
    a fresh renderer connection that just wants the last few seconds).
    If both are set, `since_seq` wins.

    `categories` filters the result to events whose `category` is in
    the set. Passing `None` (or empty) returns all categories.
    Events emitted before v0.12.0 (which lack the `category` field)
    are kept when no filter is requested and dropped when a filter is
    requested; in practice the ring is per-process so a running
    daemon never holds pre-v0.12.0 events alongside post-v0.12.0
    ones, but the filter is defensive.

    `limit` caps the returned slice (newest-favouring tail).
    """
    with _event_lock:
        events = list(_event_ring)
    if since_seq is not None:
        events = [e for e in events if e["seq"] > since_seq]
    elif since_ms is not None:
        events = [e for e in events if e["ts_ms"] > since_ms]
    if categories:
        cat_set = frozenset(categories)
        events = [e for e in events if e.get("category") in cat_set]
    if limit < 0:
        limit = 0
    return events[-limit:] if limit else []


def get_sync_events(
    *,
    since_seq: int | None = None,
    since_ms: int | None = None,
    limit: int = _RING_MAXLEN,
) -> list[dict[str, Any]]:
    """Deprecated alias: `get_node_events(..., categories={"sync"})`.

    Kept for back-compat with v0.11.3 call sites + the
    `/sync/log` endpoint, which is the v0.12.0 back-compat alias for
    `/node/log?category=sync`.
    """
    return get_node_events(
        since_seq=since_seq,
        since_ms=since_ms,
        limit=limit,
        categories=frozenset({"sync"}),
    )


def tail_seq() -> int:
    """Highest seq currently in the ring, or 0 if empty.

    Exposed so the `/node/log` + `/sync/log` endpoints can return a
    resume cursor even when the filtered window is empty (the
    renderer pins the cursor forward so the next poll never re-fetches
    the same events).
    """
    with _event_lock:
        if not _event_ring:
            return 0
        return int(_event_ring[-1]["seq"])


def reset_event_log_for_tests() -> None:
    """Test-only: clear the ring + counter.

    Production code never calls this. The event subsystem assumes
    seq is monotonic for the process lifetime.
    """
    global _event_seq
    with _event_lock:
        _event_ring.clear()
        _event_seq = 0


__all__ = [
    "NODE_EVENT_CATEGORIES",
    "emit_node_event",
    "emit_sync_event",
    "get_node_events",
    "get_sync_events",
    "reset_event_log_for_tests",
    "tail_seq",
]
