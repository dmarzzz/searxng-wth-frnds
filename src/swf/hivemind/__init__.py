"""swf-node hivemind sink (phase 5 of #93).

Implements §4.3 of `docs/SHAPE-ROTATOR-OS-SPEC.md` (in
shape-rotator-wrld-knwldge-viz):

  - voxterm clients post unsigned transcript-batch payloads to
    `POST /hivemind/transcripts`
  - sink validates, wraps in a `kind: transcript.batch` envelope,
    signs with the convent box's alchemist Ed25519 key, runs the
    phase-1 verifier, and stores via `swf.bundles.insert`
  - convent box advertises `_shape-rotator-hivemind._tcp.local.` via
    mDNS so voxterm clients can discover the sink without manual
    config

The package is designed to be removed cleanly: `rm -rf
src/swf/hivemind/` plus drop the `do_POST` dispatch line and the
`--hivemind-sink` CLI flag in `peer_server.py` is the entire uninstall.
No existing modules touch this code.

Public surface:
    - validate_payload(payload) -> (ok, reason)
    - SinkConfig                  — {signing_key_path, alchemists}
    - load_signing_key(path)      — read 32-byte Ed25519 seed
    - persist_transcript_batch(payload, *, sink_cfg, encrypt=False)
        -> (status_int, response_dict)
    - reset_signing_key_cache_for_tests()
    - start_advertisement(*, port, node_name, pubkey_hex, bind=None)
        -> handle (or None on loopback)
    - HIVEMIND_SERVICE_TYPE       — `_shape-rotator-hivemind._tcp.local.`
"""
from __future__ import annotations

from .mdns import HIVEMIND_SERVICE_TYPE, start_advertisement
from .sink import (
    SinkConfig,
    load_signing_key,
    persist_transcript_batch,
    reset_signing_key_cache_for_tests,
    validate_payload,
)

__all__ = [
    "HIVEMIND_SERVICE_TYPE",
    "SinkConfig",
    "load_signing_key",
    "persist_transcript_batch",
    "reset_signing_key_cache_for_tests",
    "start_advertisement",
    "validate_payload",
]
