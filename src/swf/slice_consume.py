"""Slice consumer: pull signed slices from peers, verify, merge entries.

Runs periodically (cron / manual via `swf-peer sync-content`). For each
peer in `peers.yaml`:

  1. GET /slices/head → current (seq, hash, cursor).
  2. If peer's head seq > last pulled seq for this peer, fetch each
     missing slice in order via GET /slices/<seq>.
  3. Verify each slice: signature (against peer's pinned pubkey if
     known, else fail-closed), merkle root, prev_hash link.
  4. Insert verified entries into our local search_results table,
     tagged with the peer's name. Queries automatically surface them.

State per peer at `~/.config/swf/consumer-state/<peer_name>.json`:
  {"last_seq": 3, "last_hash": "<b64url>"}
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from swf.canonical import canonical_url_safe
from swf.peers import Peer, load_peers
from swf.slice import verify_slice

_UA = "searxng-wth-frnds/slice-consumer"

logger = logging.getLogger(__name__)


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level handles the gate.
    logger.debug("%s", msg)


def _state_dir() -> Path:
    base = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    d = base / "consumer-state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_path(peer_name: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-._" else "_" for c in peer_name)
    return _state_dir() / f"{safe}.json"


def load_peer_state(peer_name: str) -> dict:
    p = _state_path(peer_name)
    if not p.exists():
        return {"last_seq": -1, "last_hash": ""}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"last_seq": -1, "last_hash": ""}


def save_peer_state(peer_name: str, state: dict) -> None:
    _state_path(peer_name).write_text(json.dumps(state, indent=2))


def _http_get_json(url: str, timeout: float = 5.0) -> dict | None:
    req = urllib.request.Request(
        url, headers={"User-Agent": _UA, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        _log(f"HTTP {exc.code} for {url}")
        return None
    except Exception as exc:
        _log(f"GET {url} failed: {exc}")
        return None


def _insert_entries_into_search_results(
    peer_name: str, entries: list[dict]
) -> int:
    """Materialize slice entries as rows in our local search_results
    FTS5 table so they surface through `local_search` and the
    `web_search` fan-out just like our own cached results."""
    if not entries:
        return 0
    # Each entry becomes a search_results row under a synthetic query
    # key so they dedupe within a peer+url pair. Using the peer name as
    # the pseudo-query keeps these grouped and distinguishable from our
    # own caches.
    synthetic_query = f"_friend:{peer_name}"
    rows = []
    for e in entries:
        canon = canonical_url_safe(e.get("url") or "")
        if not canon:
            continue
        rows.append(
            {
                "url": canon,
                "title": e.get("_title") or canon,
                "snippet": e.get("_snippet") or "",
            }
        )
    if not rows:
        return 0

    from swf.web.index import record_search_results

    return record_search_results(
        query=synthetic_query,
        results=rows,
        engines=f"friend:{peer_name}",
    )


@dataclass
class SyncOutcome:
    peer: str
    head_seq: int
    pulled: int
    verified: int
    merged: int
    error: str | None = None


def sync_from_peer(peer: Peer) -> SyncOutcome:
    """Pull missing slices from one peer, verify, merge."""
    base = peer.canonical()

    head = _http_get_json(f"{base}/slices/head")
    if head is None:
        return SyncOutcome(
            peer=peer.name, head_seq=-1, pulled=0, verified=0, merged=0,
            error="head unreachable",
        )
    head_seq = int(head.get("seq", -1))
    if head_seq < 0:
        return SyncOutcome(
            peer=peer.name, head_seq=-1, pulled=0, verified=0, merged=0,
            error="peer has no slices yet",
        )

    state = load_peer_state(peer.name)
    local_seq = int(state.get("last_seq", -1))
    if head_seq <= local_seq:
        return SyncOutcome(
            peer=peer.name, head_seq=head_seq, pulled=0, verified=0, merged=0,
            error=None,
        )

    pulled = 0
    verified = 0
    merged = 0
    last_hash = state.get("last_hash", "")
    last_seq = local_seq

    for seq in range(local_seq + 1, head_seq + 1):
        slice_json = _http_get_json(f"{base}/slices/{seq}")
        if slice_json is None:
            break
        pulled += 1

        ok, reason = verify_slice(
            slice_json,
            expected_author_pubkey=peer.pubkey,  # None OK when not pinned
            expected_prev_hash=last_hash if seq > 0 else "",
        )
        if not ok:
            _log(f"{peer.name} slice {seq} failed verify: {reason}")
            return SyncOutcome(
                peer=peer.name,
                head_seq=head_seq,
                pulled=pulled,
                verified=verified,
                merged=merged,
                error=f"slice {seq} failed verify: {reason}",
            )
        verified += 1

        entries = slice_json.get("entries", [])
        merged += _insert_entries_into_search_results(peer.name, entries)

        # Advance state after each successful verify. If a later slice
        # breaks, we keep what we already merged.
        last_hash = _slice_content_hash(slice_json)
        last_seq = seq
        save_peer_state(
            peer.name,
            {"last_seq": last_seq, "last_hash": last_hash},
        )

    return SyncOutcome(
        peer=peer.name,
        head_seq=head_seq,
        pulled=pulled,
        verified=verified,
        merged=merged,
    )


def _slice_content_hash(slice_json: dict) -> str:
    """sha256 b64url of the canonical JSON including sig. Matches
    `Slice.content_hash()`."""
    from swf.slice import Slice, canonical_json, sha256_b64

    s = Slice(
        author=slice_json["author"],
        seq=int(slice_json["seq"]),
        ts=slice_json["ts"],
        prev_hash=slice_json.get("prev_hash", ""),
        entries=list(slice_json.get("entries", [])),
        merkle_root=slice_json["merkle_root"],
        sig=slice_json.get("sig", ""),
    )
    return sha256_b64(canonical_json(s.to_dict(include_sig=True)))


def sync_all_peers() -> list[SyncOutcome]:
    """Sync each configured peer. Returns a list of outcomes for
    logging / CLI display."""
    cfg = load_peers()
    return [sync_from_peer(p) for p in cfg.enabled_peers]
