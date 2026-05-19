"""Background sync loop (spec §4.3 + §4.6).

Every `SWF_SYNC_POLL_INTERVAL_SECS` seconds (default 30), for each
peer known via mDNS / config / Tailscale:

  1. GET `<peer>/sync/manifest`.
  2. Diff against the local manifest. Short-circuit on equal
     `manifest_hash`.
  3. For each record where the remote has newer (or divergent)
     versions, GET `<peer>/sync/record/<id>?since=<local_latest_ts>`.
  4. Apply each envelope via `swf.sync.store.apply_envelope` (which
     runs the full verify pipeline).

Sequential per peer, single thread. No bursts. Per-peer 5s rate-limit
gate (spec §4.6) keeps us from hammering a single peer when something
upstream is wrong.

Peer enumeration is INJECTABLE for tests: pass a `discover_fn`
callable returning a list of `(url, pubkey | None)` tuples. The
production default is `swf.discovery.discover_all_peers`, with the
spec's two filters applied (cohort-keys membership + the eventual
mDNS `sync=v1` TXT key — Phase 2 keeps the TXT key opt-in via the
existing discovery layer; we filter on cohort-keys membership here).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from . import is_lan_trust_mode
from .cohort_keys import CohortKeys, load_cohort_keys_cached
from .event_log import emit_node_event, emit_sync_event
from .schema import ensure_schema
from .store import apply_envelope, build_manifest

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL_SECS = 30.0

# Per-peer manifest fetch rate-limit. Spec §4.6: 1 manifest req / 5s.
_PEER_RATE_LIMIT_SECS = 5.0

# Per-peer HTTP timeout. LAN round-trips are sub-second; a flaky peer
# shouldn't stall the loop forever.
_HTTP_TIMEOUT_SECS = 5.0

# Response size cap. Manifests are small (O(records) × 200 bytes);
# record pulls are bounded by the spec's 4 MiB per-page cap.
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Default page size for /sync/record/. Spec §4.2 caps at 1000; we ask
# for 100 so a single tick doesn't drain a backlog in one request.
_DEFAULT_RECORD_LIMIT = 100


# ── HTTP helper ───────────────────────────────────────────────────────


def _http_get_json(url: str, *, timeout: float = _HTTP_TIMEOUT_SECS) -> dict | None:
    """GET `url`, parse as JSON. Returns None on any failure.

    Mirrors `swf.bundles.puller._http_get_json`'s hardening:
      * scheme MUST be http/https
      * Content-Length > _MAX_RESPONSE_BYTES rejected before reading
      * body capped at _MAX_RESPONSE_BYTES
      * never raises
    """
    try:
        from urllib.parse import urlparse
        if urlparse(url).scheme not in ("http", "https"):
            return None
    except Exception:
        return None
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            try:
                declared = int(resp.headers.get("Content-Length") or "0")
            except ValueError:
                declared = 0
            if declared > _MAX_RESPONSE_BYTES:
                return None
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                return None
            return json.loads(raw.decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError,
            json.JSONDecodeError, UnicodeDecodeError):
        return None


# ── per-peer sync ─────────────────────────────────────────────────────


def sync_with_peer(
    conn: sqlite3.Connection,
    *,
    peer_url: str,
    cohort_keys=None,
    record_limit: int = _DEFAULT_RECORD_LIMIT,
    peer_pubkey: str | None = None,
) -> tuple[int, int]:
    """Run one diff + pull pass against `peer_url`.

    Returns `(records_pulled, envelopes_applied)`. Never raises.

    Sequence (spec §4.3):
      1. Fetch remote manifest. If unreachable, return (0, 0).
      2. Compute local manifest. Short-circuit on identical hashes.
      3. For each `record_id` where the remote disagrees, pull the
         envelope chain `wall_ts_ms > local_latest_ts` and feed each
         envelope through `apply_envelope`.
      4. Sequential — we don't fan out parallel pulls. The puller side
         is bounded; one round-trip per record.

    Side effect: emits ring-buffer events (docs/SYNC.md §12) for
    `manifest_fetched` / `peer_unreachable` / `pulled`. `peer_pubkey`
    is optional — used as the stable peer identifier in event
    payloads; falls back to `peer_url` for unkeyed peers.
    """
    lan_trust = is_lan_trust_mode()
    if cohort_keys is None:
        cohort_keys = load_cohort_keys_cached()
    if not cohort_keys and not lan_trust:
        # No cohort known → nothing we'd accept. Skip the peer.
        # LAN-trust mode bypasses this: any signed envelope from any
        # discovered peer is acceptable, cohort-keys is unused
        # (spec §11).
        return (0, 0)
    if cohort_keys is None:
        # LAN-trust on but no cohort file at all → pass an empty
        # CohortKeys placeholder; apply_envelope ignores it under
        # LAN-trust.
        cohort_keys = CohortKeys()

    base = peer_url.rstrip("/")
    peer_label = peer_pubkey or ""
    # Stable per-peer identifier for the reachability transition
    # map. Mirrors `_tick`'s `peer_key = pubkey or url`.
    peer_key = peer_pubkey or base

    remote = _http_get_json(f"{base}/sync/manifest")
    if not isinstance(remote, dict):
        # _record_peer_status emits `peer_unreachable` ONLY on the
        # reachable→unreachable transition (or first-ever observation),
        # so a peer that stays down across many ticks no longer floods
        # the traffic feed.
        _record_peer_status(
            peer_key, "unreachable",
            peer_url=base, peer_pubkey=peer_label,
            reason="manifest_fetch_failed",
        )
        return (0, 0)

    remote_records = remote.get("records")
    if not isinstance(remote_records, dict):
        _record_peer_status(
            peer_key, "unreachable",
            peer_url=base, peer_pubkey=peer_label,
            reason="malformed_manifest",
        )
        return (0, 0)

    emit_sync_event(
        "manifest_fetched",
        peer_pubkey=peer_label,
        peer_url=base,
        record_count=len(remote_records),
    )
    # Successful manifest fetch → reachable. The helper emits a
    # `peer_reachable` edge event iff the previous status was
    # `unreachable`.
    _record_peer_status(
        peer_key, "reachable",
        peer_url=base, peer_pubkey=peer_label,
    )

    # Compute local manifest. Short-circuit on identical `manifest_hash`.
    try:
        ensure_schema(conn)
        local = build_manifest(conn)
    except sqlite3.OperationalError:
        return (0, 0)
    local_records = local.get("records") or {}

    if remote.get("manifest_hash") and remote["manifest_hash"] == local.get("manifest_hash"):
        return (0, 0)

    pulled = 0
    applied = 0
    for record_id, remote_meta in remote_records.items():
        if not isinstance(record_id, str) or not isinstance(remote_meta, dict):
            continue
        local_meta = local_records.get(record_id)

        # 1. New record we don't have at all → pull from since=0.
        # 2. Same latest hash → skip.
        # 3. Remote newer → pull since local's latest_wall_ts_ms.
        # 4. Remote older → skip (they'll pull from us on their tick).
        # 5. Same wall_ts_ms, different content_hash → tiebreak (§5.1):
        #    lex larger content_hash wins. If remote's is larger, we
        #    pull.
        if local_meta is None:
            since_ms = 0
        else:
            if remote_meta.get("latest_content_hash") == local_meta.get("latest_content_hash"):
                continue
            try:
                remote_ts = int(remote_meta.get("latest_wall_ts_ms") or 0)
                local_ts = int(local_meta.get("latest_wall_ts_ms") or 0)
            except (TypeError, ValueError):
                continue
            if remote_ts > local_ts:
                since_ms = local_ts
            elif remote_ts < local_ts:
                continue
            else:
                # ms collision — apply LWW tiebreaker.
                if str(remote_meta.get("latest_content_hash", "")) > str(
                    local_meta.get("latest_content_hash", ""),
                ):
                    # Step back one ms so the remote envelope falls in
                    # `wall_ts_ms > since` predicate.
                    since_ms = max(0, local_ts - 1)
                else:
                    continue

        # Pull the record's envelope chain. We never paginate past
        # `record_limit` in one tick — the next tick picks up the rest.
        page = _http_get_json(
            f"{base}/sync/record/{record_id}?since={int(since_ms)}&limit={int(record_limit)}",
        )
        if not isinstance(page, dict):
            continue
        envelopes = page.get("envelopes")
        if not isinstance(envelopes, list):
            continue
        pulled += 1

        for env in envelopes:
            if not isinstance(env, dict):
                continue
            try:
                result = apply_envelope(conn, env, cohort_keys=cohort_keys)
            except Exception as exc:  # pragma: no cover — defensive
                logger.error("apply_envelope crashed: %s", exc)
                continue
            if result.ok and result.was_new:
                applied += 1
                # Per-envelope renderer signal. Skip duplicates
                # (was_new=False) so the feed doesn't pulse on
                # replay traffic.
                try:
                    wall_ts = int(env.get("wall_ts_ms") or 0)
                except (TypeError, ValueError):
                    wall_ts = 0
                emit_sync_event(
                    "pulled",
                    peer_pubkey=peer_label,
                    peer_url=base,
                    record_id=record_id,
                    wall_ts_ms=wall_ts,
                    content_hash=str(env.get("content_hash") or ""),
                )

    return (pulled, applied)


# ── background thread ────────────────────────────────────────────────


_thread: threading.Thread | None = None
_stop = threading.Event()
_thread_lock = threading.Lock()
_last_tick_lock = threading.Lock()
_last_tick_visited = 0
_last_tick_pulled = 0
_last_tick_applied = 0

# Per-peer last-attempt timestamps for the 5s rate-limit (spec §4.6).
_peer_attempt_ts: dict[str, float] = {}
_peer_attempt_lock = threading.Lock()

# Per-peer reachability state for `peer_reachable` edge detection.
# Values: "reachable" | "unreachable". Absent key = never contacted →
# the first event emitted is whichever side of the boundary the next
# fetch lands on (no event is fired for the very first contact attempt
# beyond the natural `manifest_fetched` / `peer_unreachable`).
_peer_status: dict[str, str] = {}
_peer_status_lock = threading.Lock()


def _record_peer_status(
    peer_key: str,
    new_status: str,
    *,
    peer_url: str,
    peer_pubkey: str,
    reason: str | None = None,
) -> None:
    """Update `_peer_status[peer_key]` and emit transition events.

    Emits `peer_unreachable` ONLY on `reachable → unreachable` (or the
    first-ever unreachable observation for a peer). Emits
    `peer_reachable` ONLY on `unreachable → reachable`. Same-state
    observations (e.g. unreachable → unreachable on every tick when a
    peer stays down) are SILENT — the renderer's traffic feed would
    otherwise drown in repeats while the user's other-mac sleeps for
    an hour.
    """
    with _peer_status_lock:
        prev = _peer_status.get(peer_key)
        _peer_status[peer_key] = new_status
    if new_status == "reachable" and prev == "unreachable":
        emit_node_event(
            "peer_reachable",
            category="health",
            peer_pubkey=peer_pubkey,
            peer_url=peer_url,
        )
    elif new_status == "unreachable" and prev != "unreachable":
        # First time we observe a peer down — or it was previously
        # reachable and just went down. Either way, this is the edge
        # transition worth surfacing. Subsequent ticks that keep
        # finding it down don't re-emit; the renderer keeps it dimmed
        # until a `peer_reachable` event clears the down state.
        emit_node_event(
            "peer_unreachable",
            category="health",
            peer_pubkey=peer_pubkey,
            peer_url=peer_url,
            reason=reason or "unreachable",
        )


def reset_peer_status_for_tests() -> None:
    """Test-only: clear the per-peer reachability map.

    Tests that run multiple `_tick` invocations against synthetic
    peer lists want a clean slate between cases.
    """
    with _peer_status_lock:
        _peer_status.clear()


def loop_stats() -> tuple[int, int, int]:
    """Return `(visited, pulled, applied)` from the most recent tick.

    Used by tests + the metrics surface to confirm the loop ran.
    """
    with _last_tick_lock:
        return _last_tick_visited, _last_tick_pulled, _last_tick_applied


def is_thread_alive() -> bool:
    """True iff the sync-loop daemon thread is currently running."""
    with _thread_lock:
        t = _thread
    return t is not None and t.is_alive()


def _peer_in_rate_limit_window(peer_key: str, *, now: float) -> bool:
    """Return True if `peer_key` was contacted within the last 5s."""
    with _peer_attempt_lock:
        ts = _peer_attempt_ts.get(peer_key)
    return ts is not None and (now - ts) < _PEER_RATE_LIMIT_SECS


def _mark_peer_attempt(peer_key: str, *, now: float) -> None:
    with _peer_attempt_lock:
        _peer_attempt_ts[peer_key] = now


def _default_discover() -> list[tuple[str, str | None]]:
    """Production peer discovery: cohort-keys ∩ `discover_all_peers()`.

    In LAN-trust mode (`SWF_TRUST_LAN_PEERS=1`, spec §11) the cohort
    filter is skipped — every mDNS-discovered peer is included
    verbatim. The apply pipeline still verifies signatures on every
    pulled envelope.
    """
    try:
        from swf.discovery import discover_all_peers
    except Exception as exc:
        logger.error("discover_all_peers import failed: %s", exc)
        return []
    try:
        peers = discover_all_peers()
    except Exception as exc:
        logger.error("discover_all_peers raised: %s", exc)
        return []

    if is_lan_trust_mode():
        # LAN-trust: trust every discovered peer. The apply path
        # accepts any signed envelope, so cohort filtering would only
        # block useful sync attempts.
        return [
            (getattr(p, "url", ""), getattr(p, "pubkey", None))
            for p in peers
            if getattr(p, "url", "")
        ]

    cohort = load_cohort_keys_cached()
    cohort_pubkeys = cohort.pubkeys if cohort else frozenset()

    out: list[tuple[str, str | None]] = []
    for p in peers:
        pubkey = getattr(p, "pubkey", None)
        url = getattr(p, "url", "")
        if not url:
            continue
        # If we have any cohort known, only sync with cohort members.
        # An empty cohort means we'd refuse every envelope anyway —
        # don't bother polling.
        if cohort_pubkeys:
            # `DiscoveredPeer.pubkey` is base64url; cohort uses
            # ed25519:<hex>. We accept the union of formats: if the
            # peer's pubkey converts to a cohort entry, include it.
            # If we can't tell (pubkey is None), include it anyway —
            # the verify pipeline will reject anything off the cohort
            # list at envelope receive time.
            if pubkey is None:
                out.append((url, None))
                continue
            # Try direct match first (config peers may already use
            # the cohort format).
            if pubkey in cohort_pubkeys:
                out.append((url, pubkey))
                continue
            # Convert base64url → hex and recheck. This is a
            # best-effort bridge; if the peer ships an unrecognized
            # format we still try the sync (apply_envelope will reject
            # off-cohort authors).
            try:
                from swf.identity import _b64url_decode
                raw = _b64url_decode(pubkey)
                if len(raw) == 32:
                    hex_form = "ed25519:" + raw.hex()
                    if hex_form in cohort_pubkeys:
                        out.append((url, hex_form))
                        continue
            except Exception:
                pass
            # Fall through: try anyway — the apply path is the
            # authoritative gate.
        out.append((url, pubkey))
    return out


def _tick(
    db_path: Path,
    discover_fn: Callable[[], list[tuple[str, str | None]]],
) -> None:
    """One sync round: walk every discovered peer sequentially."""
    global _last_tick_visited, _last_tick_pulled, _last_tick_applied

    tick_started = time.monotonic()
    visited = 0
    pulled_total = 0
    applied_total = 0
    try:
        peers = discover_fn()
    except Exception as exc:
        logger.error("discover_fn raised: %s", exc)
        peers = []

    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
    except sqlite3.OperationalError as exc:
        logger.error("open db failed: %s", exc)
        return
    conn.row_factory = sqlite3.Row

    try:
        ensure_schema(conn)
        cohort_keys = load_cohort_keys_cached()
        lan_trust = is_lan_trust_mode()
        if not cohort_keys and not lan_trust:
            # Spec §8.2: missing cohort-keys is not a daemon failure.
            # We still tick; the loop just no-ops. Logging here would
            # be too spammy at 30s — `_default_discover` already logs.
            # LAN-trust mode (§11) keeps the loop running with an
            # empty cohort — every signed peer is acceptable.
            return
        if cohort_keys is None or not cohort_keys:
            # LAN-trust path: hand `sync_with_peer` a placeholder
            # cohort so it doesn't fall through its own no-cohort
            # early-exit.
            cohort_keys = CohortKeys()
        now = time.time()
        for url, pubkey in peers:
            peer_key = pubkey or url
            if _peer_in_rate_limit_window(peer_key, now=now):
                continue
            _mark_peer_attempt(peer_key, now=now)
            visited += 1
            try:
                pulled, applied = sync_with_peer(
                    conn, peer_url=url, cohort_keys=cohort_keys,
                    peer_pubkey=pubkey,
                )
            except Exception as exc:
                logger.error("sync_with_peer(%s) failed: %s", url, exc)
                # Defensive: mark the peer unreachable. _record_peer_status
                # emits the `peer_unreachable` event only on the
                # reachable→unreachable transition, so repeated crashes
                # across consecutive ticks don't spam the feed.
                _record_peer_status(
                    peer_key, "unreachable",
                    peer_url=url, peer_pubkey=pubkey or "",
                    reason="sync_with_peer_crashed",
                )
                continue
            pulled_total += pulled
            applied_total += applied
    finally:
        conn.close()

    with _last_tick_lock:
        _last_tick_visited = visited
        _last_tick_pulled = pulled_total
        _last_tick_applied = applied_total

    duration_ms = int((time.monotonic() - tick_started) * 1000)
    # Always emit a `tick` event — the renderer uses these as the
    # heartbeat for the sync subsystem itself (a node with no peers
    # still pulses every 30s).
    emit_sync_event(
        "tick",
        visited=visited,
        pulled=pulled_total,
        applied=applied_total,
        duration_ms=duration_ms,
    )

    if visited or pulled_total or applied_total:
        logger.info(
            "tick visited=%d pulled=%d applied=%d",
            visited, pulled_total, applied_total,
        )


def _loop(
    db_path: Path,
    interval_secs: float,
    discover_fn: Callable[[], list[tuple[str, str | None]]],
) -> None:
    """Background loop body."""
    while not _stop.is_set():
        try:
            _tick(db_path, discover_fn)
        except Exception as exc:
            logger.error("loop error: %s", exc)
        _stop.wait(timeout=interval_secs)


def start_sync_loop(
    *,
    db_path: Path | None = None,
    interval_secs: float | None = None,
    discover_fn: Callable[[], list[tuple[str, str | None]]] | None = None,
) -> None:
    """Start the background sync-loop daemon thread.

    Idempotent — calling twice while a thread is alive is a no-op.
    Production wiring is in `peer_server.main` after `serve_in_thread`.

    `discover_fn` defaults to `_default_discover` (the cohort-filtered
    union of mDNS + config peers); tests inject a stub returning a
    fixed peer list so the harness doesn't depend on real mDNS.

    `interval_secs` defaults to `SWF_SYNC_POLL_INTERVAL_SECS` (env)
    or 30s. Setting `SWF_SYNC_POLL_INTERVAL_SECS=0` disables the
    loop entirely (test convenience; production should leave it on).
    """
    global _thread

    if interval_secs is None:
        try:
            interval_secs = float(os.environ.get("SWF_SYNC_POLL_INTERVAL_SECS",
                                                 DEFAULT_POLL_INTERVAL_SECS))
        except ValueError:
            interval_secs = DEFAULT_POLL_INTERVAL_SECS

    if interval_secs <= 0:
        logger.info("sync loop disabled (interval=%s)", interval_secs)
        return

    with _thread_lock:
        if _thread is not None and _thread.is_alive():
            return
        if db_path is None:
            from swf.indrex import db_path as _idx_db
            db_path = _idx_db()
        if discover_fn is None:
            discover_fn = _default_discover
        _stop.clear()
        _thread = threading.Thread(
            target=_loop,
            args=(db_path, float(interval_secs), discover_fn),
            daemon=True,
            name="swf-sync-loop",
        )
        _thread.start()


def stop_sync_loop() -> None:
    """Signal the background loop to exit and wait briefly for the
    thread to die. For tests + clean shutdown."""
    global _thread
    _stop.set()
    with _thread_lock:
        t = _thread
        _thread = None
    if t is not None and t.is_alive():
        t.join(timeout=2.0)
    with _peer_attempt_lock:
        _peer_attempt_ts.clear()
    with _peer_status_lock:
        _peer_status.clear()
