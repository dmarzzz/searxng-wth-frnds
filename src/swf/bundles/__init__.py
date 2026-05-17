"""swf-node bundle substrate (#93).

This package implements the `swf-bundle-v1` envelope LOCKED CONTRACT
described in `docs/SHAPE-ROTATOR-OS-SPEC.md` §3.1, §3.5, §3.6, §3.7
(in shape-rotator-wrld-knwldge-viz). It provides:

  - canonicalization, content-id, and shape validation (`envelope`)
  - pure-crypto signing / verification (`signing`)
  - the alchemist signing-list loader (`alchemists`)
  - the encryption-key reservoir loader (`reservoir`, phase 7)
  - producer-side age-v1 encryption (`encryption`, phase 7)
  - SQLite storage in the existing indrex DB (`store`)
  - the full verify pipeline (`verify`)
  - peer-to-peer propagation (`propagation`)

The package is designed to be removed cleanly: `rm -rf src/swf/bundles/`
plus `DROP TABLE bundles` and the hivemind/peer-server bundle routes is
the entire uninstall. No existing search modules touch this code; the
encryption integration adds a `pyrage` runtime dep but no other surface
area in the wider codebase.
"""
from __future__ import annotations

from .alchemists import (
    AlchemistList,
    is_alchemist_pubkey,
    load_alchemists,
    load_alchemists_cached,
    reset_alchemists_cache_for_tests,
)
from .encryption import (
    ENCRYPTION_ALG,
    build_encryption_block,
    encrypt_payload,
)
from .envelope import (
    BUNDLE_KINDS,
    BUNDLE_MAGIC,
    canonicalize,
    cid_for,
    validate_shape,
)
from .propagation import propagate_bundle, propagate_bundle_async
from .puller import (
    DEFAULT_PULL_INTERVAL_SECS,
    pull_from_peer,
    puller_stats,
    start_puller,
    stop_puller,
)
from .puller import (
    is_thread_alive as puller_thread_alive,
)
from .reservoir import (
    Reservoir,
    ReservoirEntry,
    load_reservoir,
    load_reservoir_cached,
    reset_reservoir_cache_for_tests,
)
from .signing import sign_envelope, verify_envelope_signature
from .store import (
    ensure_schema,
    get_by_cid,
    insert,
    latest_version,
    list_,
    list_with_rowid,
)
from .verify import VerifyReason, VerifyResult, verify_bundle

__all__ = [
    "BUNDLE_MAGIC",
    "BUNDLE_KINDS",
    "canonicalize",
    "cid_for",
    "validate_shape",
    "sign_envelope",
    "verify_envelope_signature",
    "load_alchemists",
    "load_alchemists_cached",
    "reset_alchemists_cache_for_tests",
    "is_alchemist_pubkey",
    "AlchemistList",
    "load_reservoir",
    "load_reservoir_cached",
    "reset_reservoir_cache_for_tests",
    "Reservoir",
    "ReservoirEntry",
    "encrypt_payload",
    "build_encryption_block",
    "ENCRYPTION_ALG",
    "ensure_schema",
    "insert",
    "get_by_cid",
    "list_",
    "list_with_rowid",
    "latest_version",
    "verify_bundle",
    "VerifyResult",
    "VerifyReason",
    "propagate_bundle",
    "propagate_bundle_async",
    "pull_from_peer",
    "puller_stats",
    "puller_thread_alive",
    "start_puller",
    "stop_puller",
    "DEFAULT_PULL_INTERVAL_SECS",
]
