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
    "ensure_schema",
    "envelope_hash",
    "get_record_envelopes",
    "get_record_history",
    "is_record_forked",
    "latest_envelope",
    "load_cohort_keys",
    "load_cohort_keys_cached",
    "pinned_author",
    "reset_cohort_keys_cache_for_tests",
    "sign_envelope",
    "verify_envelope_signature",
]
