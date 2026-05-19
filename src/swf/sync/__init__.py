"""swf-node sync substrate (Phase 2).

Implements the LAN-trust signed-record sync protocol specified in
`docs/SYNC.md` (on the `docs/phase-2-sync-spec` branch). The substrate
provides:

  - signed envelope shape + canonicalization + content-hash (`envelope`)
  - sqlite schema for the per-record append-only log and the
    one-author-per-record pin (`schema`)
  - cohort-keys file loader with mtime-based hot-reload (`cohort_keys`)
  - apply / accept logic with LWW, fork detection, dedup (`store`)
  - background sync loop that polls peers (`sync_loop`)

HTTP endpoints (`/sync/manifest`, `/sync/record/<id>`,
`POST /sync/local_record`) live in `swf.peer_server` and call into this
package — same layout as the bundle substrate (`swf.bundles`) the spec
deliberately mirrors.

The package is designed to be removed cleanly — `rm -rf src/swf/sync/`
plus `DROP TABLE sync_records; DROP TABLE sync_record_authors;` and the
peer-server `/sync/*` handlers is the entire uninstall. No existing
modules touch this code.
"""
from __future__ import annotations

import os

from .cohort_keys import (
    CohortKeys,
    load_cohort_keys,
    load_cohort_keys_cached,
    reset_cohort_keys_cache_for_tests,
)
from .envelope import (
    MAX_ENVELOPE_BYTES,
    SYNC_MAGIC,
    SYNC_RECORD_KINDS,
    canonicalize,
    content_hash,
    envelope_hash,
    sign_envelope,
    verify_envelope_signature,
)
from .event_log import (
    emit_sync_event,
    get_sync_events,
    reset_event_log_for_tests,
    tail_seq,
)
from .schema import ensure_schema
from .store import (
    ApplyResult,
    apply_envelope,
    build_manifest,
    get_record_envelopes,
    get_record_history,
    is_record_forked,
    latest_envelope,
    pinned_author,
)

# ── LAN-trust mode (spec §11) ─────────────────────────────────────────
#
# Opt-in dev flag for single-user multi-device deployments (e.g. Shape
# Rotator OS on two personal laptops on the same WiFi). When set, the
# daemon:
#   1. Bypasses the cohort-keys gate for local-record writes
#      (POST /sync/local_record). The envelope is still self-signed by
#      the local identity, just not cross-checked against the cohort.
#   2. Skips single-writer-pinning in `apply_envelope`. Any cohort
#      member (or any signed peer in LAN-trust mode) may write any
#      record_id; multiple authors per record_id are accepted as a
#      chain, LWW by wall_ts_ms applies normally, no fork warnings.
#   3. Bypasses the cohort-keys author whitelist for incoming sync
#      (sync_loop pull path). Any signed envelope from any discovered
#      peer is acceptable.
#
# What is NOT bypassed: ed25519 signature verification. Unsigned or
# tampered envelopes are still rejected — that's the wire-integrity
# check, not the access-control check.
#
# Security tradeoff: anyone on your LAN with knowledge of your
# `/sync/local_record` agent-bearer token, or any peer they can stand up
# on the LAN that your node will discover via mDNS, can write any record
# to your store. Use only on trusted networks.

_LAN_TRUST_TRUTHY = frozenset({"1", "true", "yes", "on"})


def is_lan_trust_mode() -> bool:
    """Return True iff `SWF_TRUST_LAN_PEERS` is set to a truthy value.

    Truthy values (case-insensitive): ``1``, ``true``, ``yes``, ``on``.
    Any other value (including empty / unset) means LAN-trust is off
    and the cohort-keys gate + single-writer pin remain in force.

    Re-read on every call — tests and operators can flip the flag at
    runtime without bouncing the daemon (the env-var read is cheap and
    every gate site consults this function fresh).
    """
    return (os.environ.get("SWF_TRUST_LAN_PEERS") or "").strip().lower() in _LAN_TRUST_TRUTHY


__all__ = [
    "ApplyResult",
    "CohortKeys",
    "MAX_ENVELOPE_BYTES",
    "SYNC_MAGIC",
    "SYNC_RECORD_KINDS",
    "apply_envelope",
    "build_manifest",
    "canonicalize",
    "content_hash",
    "emit_sync_event",
    "ensure_schema",
    "envelope_hash",
    "get_record_envelopes",
    "get_record_history",
    "get_sync_events",
    "is_lan_trust_mode",
    "is_record_forked",
    "latest_envelope",
    "load_cohort_keys",
    "load_cohort_keys_cached",
    "pinned_author",
    "reset_cohort_keys_cache_for_tests",
    "reset_event_log_for_tests",
    "sign_envelope",
    "tail_seq",
    "verify_envelope_signature",
]
