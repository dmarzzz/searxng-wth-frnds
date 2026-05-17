"""Best-effort peer-to-peer bundle propagation (#93 phase 6).

When a bundle lands locally — either via `POST /bundles` or via the
`hivemind` sink's direct `bundles.insert` — we fan it out to every
known LAN peer's `/bundles` endpoint. The fan-out runs on a daemon
thread so the original POST returns 201 immediately; peer round-trips
do NOT block the response.

This module is the **push** side of bundle replication. It is parallel
to (and intentionally separate from) `swf.peer_scraper`, which is the
**pull** side for the legacy search-result indrex bundles. The two
share the same `peers` table (pubkey + trust_level + nickname) but no
code, no transport, no event taxonomy — bundle propagation is its own
narrow concern.

Convergence + loop prevention
─────────────────────────────

A naive "always re-broadcast every bundle I receive" design would
storm the LAN forever in any cycle (and almost every real LAN graph
has cycles once you have ≥3 peers). We rely on TWO mechanisms:

  1. **was_new gating at the call site.** The wiring in
     `peer_server._do_bundles_post` and `hivemind.sink` only invokes
     `propagate_bundle` when `bundles.insert` returned
     `was_new=True`. If a peer receives a bundle it already has,
     `bundles.insert` is a no-op (idempotent on cid) and propagation
     is suppressed. In a connected graph this guarantees convergence
     in O(diameter) hops with at most one outbound POST per peer per
     bundle.

  2. **`exclude_pubkeys` author-skip.** When peer A originated the
     bundle and broadcasts it to B, B will (on first receipt) try to
     re-broadcast it. Without a guard, B's broadcast hits A again,
     A's `bundles.insert` returns `was_new=False` and the chain
     terminates — but we can save the round-trip by passing the
     bundle's `author.pubkey` in `exclude_pubkeys`, so B never even
     POSTs back to A. This is the natural backpressure-saving
     short-circuit.

Known limitation: if multiple peers in the LAN share the same author
pubkey (rare but possible — e.g. an alchemist running two boxes), the
`exclude_pubkeys` filter will skip them all on the first hop. The
`was_new` mechanism will still deliver the bundle eventually via a
different path (any peer that receives it from a neighbor that ISN'T
filtered will re-broadcast normally). For v1 this is accepted; a
future revision could key the dedup on `(author.pubkey, signed_at)`
or carry a hop-list header.

Failure handling
────────────────

`propagate_bundle` is **best-effort**. Per-peer failures (network
error, 4xx, timeout) are recorded in the returned summary dict but
never raise. A caller that wants to react to failures can inspect
the dict; the production wiring at `_do_bundles_post` ignores it
because the POST has already been answered to the client by the time
propagation runs.

There is no retry. Phase 6 ships push-only delivery; durability for
peers that were offline at broadcast time is a follow-up (active
gossip / pull-side bundle replication — out of scope for #93).
"""
from __future__ import annotations

import contextlib
import json
import logging
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Per-peer HTTP timeout for bundle propagation. LAN round-trips should
# be sub-second; 5s is generous enough to absorb a single retransmit
# without making the broadcast thread linger forever on a flaky peer.
_DEFAULT_TIMEOUT_SECS = 5.0

# Body size cap. Mirrors `peer_server._Handler._MAX_BUNDLE_BYTES` —
# we already accepted the envelope locally under that limit, so a
# remote peer's enforcement matches ours and there's no point sending
# anything we'd refuse to accept.
_MAX_BUNDLE_BYTES = 4 * 1024 * 1024


def _post_bundle_to_peer(
    peer_url: str,
    body: bytes,
    *,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
) -> int | str:
    """POST `body` (the canonical envelope JSON) to `<peer_url>/bundles`.

    Returns either an integer HTTP status code or a short string tag
    describing the failure mode:

      "no_url"           — the peer's resolved URL was empty
      "scheme_invalid"   — URL not http/https (SSRF guard)
      "body_too_large"   — body exceeds _MAX_BUNDLE_BYTES (programmer
                           bug; we filter at the call site too)
      "timeout"          — the round-trip timed out
      "connect_failed"   — TCP connect / DNS / general URLError
      "io_error"         — OSError (e.g. ECONNRESET mid-write)
      "unknown_error"    — anything else (logged + swallowed)

    Never raises.
    """
    if not peer_url:
        return "no_url"
    try:
        from urllib.parse import urlparse
        if urlparse(peer_url).scheme not in ("http", "https"):
            return "scheme_invalid"
    except Exception:
        return "scheme_invalid"
    if len(body) > _MAX_BUNDLE_BYTES:
        return "body_too_large"

    target = peer_url.rstrip("/") + "/bundles"
    req = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_secs) as resp:
            # Drain the body so the connection can be reused / closed
            # cleanly; we don't need the response payload (cid echo).
            with contextlib.suppress(Exception):
                resp.read(1024 * 16)
            return int(resp.status)
    except urllib.error.HTTPError as e:
        # 4xx / 5xx land here. The peer rejected the bundle for some
        # reason (alchemist mismatch, version not monotonic, …) — we
        # record the status but don't retry; the issue is structural.
        with contextlib.suppress(Exception):
            e.read(1024)
        return int(e.code)
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None)
        # urllib raises URLError(reason=socket.timeout(...)) for
        # request timeouts. Differentiate so the operator can tell
        # "peer was busy" from "peer was unreachable".
        if reason is not None and "timed out" in str(reason).lower():
            return "timeout"
        return "connect_failed"
    except TimeoutError:
        return "timeout"
    except OSError:
        return "io_error"
    except Exception as exc:
        logger.error("unexpected error to %s: %s", target, exc)
        return "unknown_error"


def _envelope_bytes(envelope: dict[str, Any]) -> bytes:
    """Encode `envelope` as JSON for the wire.

    We deliberately use plain `json.dumps` rather than the canonical
    encoder — the wire form just has to round-trip; the receiving peer
    re-canonicalizes on its own when it computes the cid + verifies
    the signature. Using plain `json.dumps` keeps the propagation path
    independent of the canonicalizer (separation of concerns: the
    canonicalizer's contract is signing, not transport).
    """
    return json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def propagate_bundle(
    envelope: dict[str, Any],
    *,
    db_path: Path,
    exclude_pubkeys: set[str] | None = None,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
) -> dict[str, int | str]:
    """Best-effort POST `envelope` to every known peer's `/bundles`.

    Walks the local `peers` table (via `swf.peer_scraper.list_peers`),
    resolves each peer's URL via `swf.peer_scraper._resolve_peer_url`
    (the same discovery cache the puller uses), and POSTs the envelope
    to each `<peer_url>/bundles` endpoint.

    Skipped peers:
      * pubkey in `exclude_pubkeys` (caller-supplied; typically the
        bundle's `author.pubkey` to avoid bouncing back to origin and
        the local node's own pubkey for self-loop safety)
      * trust_level == "banned"
      * empty resolved URL (peer not currently reachable via mDNS)

    Returns a summary dict `{peer_pubkey: status_int_or_error_string}`.
    Skipped peers are recorded with an explanatory tag (e.g.
    `"excluded"`, `"banned"`, `"no_url"`); attempted peers carry the
    HTTP status code they returned (typically 201) or an error tag.

    Never raises. Individual peer failures are recorded but do not
    abort the broadcast — the caller (typically a daemon thread) is
    not interested in a single peer's failure.

    `db_path` is the indrex DB path; passed explicitly so this function
    is testable without depending on env state.
    """
    excluded = set(exclude_pubkeys or ())
    summary: dict[str, int | str] = {}

    # Lazy imports keep this module's startup cost zero for nodes
    # that never propagate (peer_server import path).
    from swf.peer_scraper import _resolve_peer_url, list_peers

    try:
        peers = list_peers(db_path)
    except Exception as exc:
        logger.error("list_peers failed: %s", exc)
        return summary

    if not peers:
        return summary

    body = _envelope_bytes(envelope)

    for peer in peers:
        pubkey = peer.pubkey
        if not pubkey:
            continue
        if pubkey in excluded:
            summary[pubkey] = "excluded"
            continue
        # `trust_level == "banned"` peers are excluded uniformly here,
        # independent of the SWF_ENABLE_PEER_TRUST opt-in flag the
        # puller honors. The push side is more conservative on
        # purpose: a banned peer should not receive any of our
        # bundles, period — that's the contract of "banned".
        if (peer.trust_level or "known") == "banned":
            summary[pubkey] = "banned"
            continue

        peer_url = ""
        try:
            peer_url = _resolve_peer_url(peer)
        except Exception as exc:
            logger.error(
                "resolve_peer_url failed for %s: %s",
                pubkey[:12], exc,
            )
        # Allow a stored `base_url` to win when discovery has nothing.
        # `peer_scraper.list_peers` doesn't populate `base_url` from the
        # peers table (the column doesn't exist), so this is reserved
        # for the test harness's direct injection path: tests stuff
        # entries into `peer_scraper._discovery_cache` so
        # `_resolve_peer_url` returns the test URL.
        if not peer_url and peer.base_url:
            peer_url = peer.base_url
        if not peer_url:
            summary[pubkey] = "no_url"
            continue

        status = _post_bundle_to_peer(
            peer_url, body, timeout_secs=timeout_secs,
        )
        summary[pubkey] = status

    return summary


def propagate_bundle_async(
    envelope: dict[str, Any],
    *,
    db_path: Path,
    exclude_pubkeys: set[str] | None = None,
    timeout_secs: float = _DEFAULT_TIMEOUT_SECS,
) -> threading.Thread:
    """Fire-and-forget wrapper: spawn a daemon thread that runs
    `propagate_bundle` and discards the result.

    The thread is started before this function returns; the caller
    can keep the handle for testing (`thread.join(timeout=N)`) but
    production callers ignore it.

    Wrapped in a try/except so a thread-spawn failure (e.g. an OS
    that refuses thread creation) cannot break the HTTP response that
    triggered the propagation.
    """
    def _runner() -> None:
        try:
            propagate_bundle(
                envelope,
                db_path=db_path,
                exclude_pubkeys=exclude_pubkeys,
                timeout_secs=timeout_secs,
            )
        except Exception as exc:
            logger.error("runner crashed: %s", exc)

    t = threading.Thread(
        target=_runner, name="bundle-propagation", daemon=True,
    )
    try:
        t.start()
    except Exception as exc:
        logger.error("thread start failed: %s", exc)
    return t


__all__ = [
    "propagate_bundle",
    "propagate_bundle_async",
]
