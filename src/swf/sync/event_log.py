"""In-process sync event ring buffer (docs/SYNC.md §12).

A tiny ring of the most recent sync-loop events, surfaced over the
read-only `GET /sync/log` endpoint so the SROS renderer can show a
live "network activity" feed + per-peer heartbeat pulses.

Design constraints:
  * The emit path is on the sync hot loop. Lock contention has to be
    minimal: a single `threading.Lock`, increment seq, append to
    deque. No JSON encoding, no logging, no I/O inside the lock.
  * The ring is per-process. Restarts wipe it. That is intentional —
    this is a live debug surface for the renderer, NOT a durable
    journal. Durable history lives in the `sync_records` table.
  * `seq` is a hand-rolled monotonic int. We do NOT rely on `ts_ms`
    for ordering or cursor semantics; two events at the same wall ms
    must still be totally ordered for resumable polling.

Public surface:
  * `emit_sync_event(kind, **payload)` — called by the sync loop
    and the local-write HTTP handler.
  * `get_sync_events(since_seq=..., since_ms=..., limit=...)` —
    snapshot read used by the `/sync/log` endpoint.
  * `tail_seq()` — highest seq in the ring (or 0 if empty), exposed
    so the endpoint can hand the client a resume cursor even when
    the filtered slice is empty.
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

# Module-level state. Guarded by `_event_lock`.
_event_ring: deque[dict[str, Any]] = deque(maxlen=_RING_MAXLEN)
_event_lock = threading.Lock()
_event_seq = 0  # monotonic counter; never decreases, never wraps in practice


def emit_sync_event(kind: str, **payload: Any) -> None:
    """Append a sync event to the ring buffer.

    Called from the sync loop's per-peer iteration, from
    `apply_envelope` callers that want to surface a write, and from
    the `POST /sync/local_record` HTTP handler.

    The critical section is: bump seq, build dict, append. We don't
    log here; the sync loop continues to emit its own
    `[sync-loop] tick visited=N pulled=K applied=M` line via
    `logger.info` so ops users see the same signal they always did.
    """
    global _event_seq
    with _event_lock:
        _event_seq += 1
        evt: dict[str, Any] = {
            "seq": _event_seq,
            "kind": kind,
            "ts_ms": int(time.time() * 1000),
        }
        # Caller payload merges last so it can't accidentally
        # overwrite our reserved fields.
        for k, v in payload.items():
            if k in ("seq", "kind", "ts_ms"):
                continue
            evt[k] = v
        _event_ring.append(evt)


def get_sync_events(
    *,
    since_seq: int | None = None,
    since_ms: int | None = None,
    limit: int = _RING_MAXLEN,
) -> list[dict[str, Any]]:
    """Snapshot the ring under the lock, filter outside.

    `since_seq` is the primary cursor — monotonic, no ts collisions.
    `since_ms` is a fallback for clients that don't track seq (e.g.
    a fresh renderer connection that just wants the last few seconds).
    If both are set, `since_seq` wins.

    `limit` caps the returned slice (newest-favouring tail).
    """
    with _event_lock:
        events = list(_event_ring)
    if since_seq is not None:
        events = [e for e in events if e["seq"] > since_seq]
    elif since_ms is not None:
        events = [e for e in events if e["ts_ms"] > since_ms]
    if limit < 0:
        limit = 0
    return events[-limit:] if limit else []


def tail_seq() -> int:
    """Highest seq currently in the ring, or 0 if empty.

    Exposed so the `/sync/log` endpoint can return a resume cursor
    even when the filtered window is empty (the renderer pins the
    cursor forward so the next poll never re-fetches the same
    events).
    """
    with _event_lock:
        if not _event_ring:
            return 0
        return int(_event_ring[-1]["seq"])


def reset_event_log_for_tests() -> None:
    """Test-only: clear the ring + counter.

    Production code never calls this. The sync subsystem assumes
    seq is monotonic for the process lifetime.
    """
    global _event_seq
    with _event_lock:
        _event_ring.clear()
        _event_seq = 0


__all__ = [
    "emit_sync_event",
    "get_sync_events",
    "reset_event_log_for_tests",
    "tail_seq",
]
