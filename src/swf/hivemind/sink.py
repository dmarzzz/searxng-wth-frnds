"""Hivemind sink: validate -> wrap -> [encrypt] -> sign -> verify -> store.

Phase 5+7 of #93. Spec §4.3. The sink takes an UNSIGNED voxterm transcript
batch payload, wraps it in a `kind: transcript.batch` envelope per spec
§3.1 + §3.5, signs with the convent box's alchemist Ed25519 key, runs
the phase-1 verifier, and persists via `swf.bundles.insert`.

Design choices:

  * No HTTP round-trip back to `/bundles`. The spec language ("POSTs to
    its own swf-node /bundles") is informal; mechanically, going over
    the local socket would add failure modes (connection refused,
    timeouts) and round-trip cost without buying anything — the
    storage is the same SQLite DB. We call `verify_bundle` + `insert`
    directly, then emit `bundle_added` so phase 4's SSE stream wakes
    up exactly as it does for a real `POST /bundles`.

  * The convent box's alchemist private key is loaded from the path
    `$SWF_CONVENT_SIGNING_KEY` (or `~/.config/swf/convent-signing.key`
    as the default fallback). The file is 32 raw bytes — the Ed25519
    seed. We cache the loaded key (analogous to the alchemists.yml
    cache in `peer_server.py`) and expose `reset_signing_key_cache_for_tests`
    so each test's tmp seed file is honored.

  * Encryption (`?encrypt=true` query param OR `{"encrypt": true}` body
    field) is fully implemented in phase 7: the inner voxterm payload
    bytes are age-v1 encrypted to ALL pubkeys in the loaded reservoir
    (per spec §3.6 — every encrypted bundle ships to every reservoir
    key). The reservoir is loaded from `$SWF_RESERVOIR_FILE` (with the
    same `SWF_CONFIG_DIR` / `~/.config/swf` lookup chain as
    alchemists.yml) and cached on the same lazy-load pattern as the
    signing key. If `encrypt=true` is requested but the reservoir is
    empty (file missing or zero keys), the sink returns 503
    `encryption_not_configured` so a cooperating client knows to
    retry once the operator has staged the reservoir — distinct from
    the previous phase-5 501 stub which signaled "this code path
    isn't implemented yet".

Schema validation (the unsigned voxterm payload, NOT the bundle envelope):

  * `record_id`: non-empty string
  * `batch_index`: int OR the literal string `"redacted"` (spec §3.5)
  * `started_at`: non-empty string (we treat as opaque ISO-8601)
  * `ended_at`: non-empty string
  * `location`: optional string
  * `origin_device`: optional string (forgeable per §3.5; opaque
    metadata)
  * `segments`: list of `{t: float, speaker: str, text: str}`. May be
    empty when `batch_index == "redacted"`.

Envelope-level `version` for transcript.batch:
  Spec §3.5 says "Batches MUST be append-only — `version` increments
  are NOT used; `batch_index` does." But phase-1's verifier still
  enforces strict-greater envelope-level `version` per (kind,
  record_id). Resolution per phase-1's `verify.py` docstring: bump
  envelope `version` in lockstep with `batch_index`. We set
  `version = batch_index` when batch_index is an int. For the
  `batch_index = "redacted"` retroactive-seal case, we look up the
  highest existing version for this (kind, record_id) and add 1, so
  the redaction always lands strictly later than every prior batch.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from swf import bundles as _bundles
from swf.bundles.alchemists import AlchemistList
from swf.bundles.reservoir import (
    Reservoir,
)
from swf.bundles.reservoir import (
    load_reservoir_cached as _shared_load_reservoir_cached,
)
from swf.bundles.reservoir import (
    reset_reservoir_cache_for_tests as _shared_reset_reservoir_cache,
)

logger = logging.getLogger(__name__)

# ── schema validation ─────────────────────────────────────────────────────


_REDACTED = "redacted"


def validate_payload(payload: Any) -> tuple[bool, str]:
    """Walk the voxterm transcript-batch payload; return `(ok, tag)`.

    Reason tags (machine-matchable):
        ""                    — ok
        "not_object"          — top-level must be a JSON object
        "missing_record_id"   — `record_id` absent or not a string
        "empty_record_id"     — `record_id` is the empty string
        "bad_batch_index"     — neither int nor the literal "redacted"
        "missing_started_at"  — `started_at` absent or empty
        "missing_ended_at"    — `ended_at` absent or empty
        "bad_location"        — present but not a string
        "bad_origin_device"   — present but not a string
        "missing_segments"    — `segments` absent or wrong type
        "bad_segment"         — a segment is malformed (any of t/speaker/text)
        "non_empty_segments_for_redacted_only"
                              — caller submitted batch_index="redacted"
                                with non-empty segments. Spec §3.5 says
                                redacted batches are sealed — the empty
                                envelope payload is the right
                                semantics. We accept either, but if a
                                client tries to mix the two we 400.
                                (Currently a noop; see below.)
    """
    if not isinstance(payload, dict):
        return False, "not_object"

    record_id = payload.get("record_id")
    if not isinstance(record_id, str):
        return False, "missing_record_id"
    if not record_id:
        return False, "empty_record_id"

    batch_index = payload.get("batch_index")
    if isinstance(batch_index, bool):
        # bool is a subclass of int; reject it explicitly so a
        # `batch_index: true` doesn't sneak through as version=1.
        return False, "bad_batch_index"
    if not (isinstance(batch_index, int) or batch_index == _REDACTED):
        return False, "bad_batch_index"
    if isinstance(batch_index, int) and batch_index < 0:
        return False, "bad_batch_index"

    started_at = payload.get("started_at")
    if not isinstance(started_at, str) or not started_at:
        return False, "missing_started_at"

    ended_at = payload.get("ended_at")
    if not isinstance(ended_at, str) or not ended_at:
        return False, "missing_ended_at"

    location = payload.get("location")
    if location is not None and not isinstance(location, str):
        return False, "bad_location"

    origin_device = payload.get("origin_device")
    if origin_device is not None and not isinstance(origin_device, str):
        return False, "bad_origin_device"

    segments = payload.get("segments")
    if not isinstance(segments, list):
        return False, "missing_segments"

    for seg in segments:
        if not isinstance(seg, dict):
            return False, "bad_segment"
        # `t` must be a number (int OR float). bool excluded.
        t = seg.get("t")
        if isinstance(t, bool) or not isinstance(t, (int, float)):
            return False, "bad_segment"
        speaker = seg.get("speaker")
        text = seg.get("text")
        if not isinstance(speaker, str) or not isinstance(text, str):
            return False, "bad_segment"

    # Spec §3.5: empty segments list is legitimate ONLY for the
    # `batch_index="redacted"` retroactive-seal case. We don't actively
    # reject empty segments on numeric batches — a producer might
    # legitimately want to checkpoint a quiet window — but we DO
    # document the contract here so future readers don't assume the
    # opposite.
    return True, ""


# ── signing-key management ────────────────────────────────────────────────


_DEFAULT_SIGNING_KEY_PATH = Path.home() / ".config" / "swf" / "convent-signing.key"


def signing_key_path() -> Path:
    """Resolve the convent box's signing-key path.

    Lookup order:
      1. `SWF_CONVENT_SIGNING_KEY` env var — explicit override
      2. `~/.config/swf/convent-signing.key` — default fallback
    """
    env = os.environ.get("SWF_CONVENT_SIGNING_KEY")
    if env:
        return Path(env)
    return _DEFAULT_SIGNING_KEY_PATH


_SIGNING_KEY_CACHE: Ed25519PrivateKey | None = None
_SIGNING_KEY_CACHE_PATH: Path | None = None


def load_signing_key(path: Path | None = None) -> Ed25519PrivateKey:
    """Load the convent box's Ed25519 signing key.

    The file is 32 raw bytes (the Ed25519 seed) — easy to generate
    with `python -c 'import secrets; open(...).write(secrets.token_bytes(32))'`.
    PEM is NOT supported in phase 5 to keep the implementation small;
    if an operator hands us a PEM file we raise so the failure is
    obvious instead of silently signing with garbage.

    Cached at module level so the YAML parse cost is paid once per
    process. Tests use `reset_signing_key_cache_for_tests` to drop
    the cache between cases that point at different tmp seed files.
    """
    global _SIGNING_KEY_CACHE, _SIGNING_KEY_CACHE_PATH

    target = path if path is not None else signing_key_path()
    if (
        _SIGNING_KEY_CACHE is not None
        and target == _SIGNING_KEY_CACHE_PATH
    ):
        return _SIGNING_KEY_CACHE

    if not target.exists():
        raise FileNotFoundError(
            f"convent signing key not found at {target}; set "
            f"SWF_CONVENT_SIGNING_KEY or place a 32-byte seed at "
            f"{_DEFAULT_SIGNING_KEY_PATH}",
        )
    raw = target.read_bytes()
    if len(raw) != 32:
        raise ValueError(
            f"convent signing key at {target} is {len(raw)} bytes; "
            f"expected 32 (raw Ed25519 seed). PEM is not supported.",
        )
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    _SIGNING_KEY_CACHE = priv
    _SIGNING_KEY_CACHE_PATH = target
    return priv


def reset_signing_key_cache_for_tests() -> None:
    """Drop the cached signing key. Tests call this between cases so
    each tmp seed file is loaded freshly."""
    global _SIGNING_KEY_CACHE, _SIGNING_KEY_CACHE_PATH
    _SIGNING_KEY_CACHE = None
    _SIGNING_KEY_CACHE_PATH = None


def signing_key_cached() -> bool:
    """True iff a convent signing key is currently cached in this process.

    Read-only introspection used by the metrics collector
    (`bundles.signing_key_loaded` gauge in `/metrics/snapshot`). Does
    NOT trigger a load — a missing seed file simply reports False so
    operators can see at-a-glance that the convent box hasn't been
    bootstrapped without us paying the file-IO cost on every tick.
    """
    return _SIGNING_KEY_CACHE is not None


# ── reservoir-cache management ────────────────────────────────────────────
#
# Phase 7. The reservoir is loaded lazily on the first encrypt-true POST
# (so an unencrypted-only sink never reads the file). The cache itself
# now lives in `swf.bundles.reservoir` so a single process-wide cache
# is shared by every bundle ingest channel (sink, pull puller,
# `POST /bundles` verifier). The wrappers below preserve this module's
# import surface (the `load_reservoir_cached` / `reset_reservoir_cache_for_tests`
# names are public + used by tests) so the lift is transparent to
# existing callers. The loader itself stays forgiving (missing file ->
# empty reservoir + warning); the sink's `?encrypt=true` path checks
# for emptiness and returns 503 in that case.


def load_reservoir_cached() -> Reservoir:
    """Lazy-load + cache the reservoir. Reads `SWF_RESERVOIR_FILE` (and
    fallback paths) on the first call. Delegates to the shared cache
    in `swf.bundles.reservoir` so the sink, the puller, and the
    `POST /bundles` verifier all read the same parse result."""
    return _shared_load_reservoir_cached()


def reset_reservoir_cache_for_tests() -> None:
    """Drop the cached reservoir. Tests call this between cases so
    each tmp `.reservoir.yml` is honored."""
    _shared_reset_reservoir_cache()


def signing_pubkey_hex(priv: Ed25519PrivateKey) -> str:
    """Return the canonical `<hex>` (64 chars) for the public half of
    `priv`. The full `ed25519:<hex>` form is built at the call site —
    we keep the raw hex here so callers can cheaply reuse it (mDNS
    TXT record uses the bare hex form, the envelope's
    `author.pubkey` uses the prefixed form)."""
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


# ── sink config ───────────────────────────────────────────────────────────


@dataclass
class SinkConfig:
    """Runtime config the sink needs.

    `signing_key` is the Ed25519 private key. `alchemists` is the loaded
    AlchemistList — the convent's pubkey MUST be in it or the
    phase-1 verifier rejects every bundle we sign. The peer-server
    startup path validates this invariant before binding the socket.
    """

    signing_key: Ed25519PrivateKey
    alchemists: AlchemistList

    @property
    def author_pubkey(self) -> str:
        """The canonical `ed25519:<hex>` form for the author field."""
        return f"ed25519:{signing_pubkey_hex(self.signing_key)}"


# ── envelope construction + persist ───────────────────────────────────────


def _now_iso_z() -> str:
    """RFC3339 / ISO-8601 with `Z` suffix. Matches the envelope's
    `author.signed_at` shape used by phase-1 tests + the cohort spec."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _open_writer_conn() -> sqlite3.Connection:
    """Open a writer connection to the indrex DB. Mirrors the
    `_open_writer` helper in `swf.bundles.store`. We can't reuse that
    one because it's private; the public `bundles.insert(envelope)`
    accepts a `conn=None` short-cut but we need to do the prev_cid
    lookup inside the same transaction so we open our own connection."""
    from swf.indrex import db_path
    conn = sqlite3.connect(str(db_path()), timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def _build_envelope(
    payload: dict[str, Any],
    *,
    sink_cfg: SinkConfig,
    version: int,
    prev_cid: str | None,
    recipients: list[str] | None = None,
) -> dict[str, Any]:
    """Assemble the bundle envelope, sign it, return the dict.

    The envelope's `payload` is the canonical JSON of the voxterm
    payload (with `record_type` and `schema_version` flattened in
    per spec §3.5), base64-encoded. We use `swf.bundles.canonicalize`
    for the inner JSON so payload bytes are byte-stable across
    re-serialization.

    When `recipients` is non-None and non-empty, the inner JSON bytes
    are age-v1 encrypted to every recipient before base64-encoding,
    and the envelope's `encryption` field is populated per spec §3.6.
    The `recipients` list is the reservoir's full pubkey set (not a
    subset) — see `swf.bundles.reservoir`.
    """
    inner: dict[str, Any] = {
        "record_id": payload["record_id"],
        "record_type": "transcript",
        "schema_version": 1,
        "batch_index": payload["batch_index"],
        "started_at": payload["started_at"],
        "ended_at": payload["ended_at"],
        "segments": payload.get("segments", []),
    }
    if "location" in payload and payload["location"] is not None:
        inner["location"] = payload["location"]
    if "origin_device" in payload and payload["origin_device"] is not None:
        inner["origin_device"] = payload["origin_device"]

    inner_bytes = _bundles.canonicalize(inner, drop_signature=False)

    if recipients:
        # age-v1 encrypt-to-all-reservoir-keys. The ciphertext goes
        # into the envelope's `payload` field as opaque bytes; the
        # `encryption` block lists every recipient so a consumer can
        # quickly tell whether one of their reservoir keys can
        # decrypt without trying.
        ciphertext = _bundles.encrypt_payload(inner_bytes, recipients)
        payload_b64 = base64.b64encode(ciphertext).decode("ascii")
        encryption_block: dict[str, Any] | None = (
            _bundles.build_encryption_block(recipients)
        )
    else:
        payload_b64 = base64.b64encode(inner_bytes).decode("ascii")
        encryption_block = None

    env: dict[str, Any] = {
        "magic": _bundles.BUNDLE_MAGIC,
        "kind": "transcript.batch",
        "record_id": payload["record_id"],
        "version": int(version),
        "author": {
            "pubkey": sink_cfg.author_pubkey,
            "signed_at": _now_iso_z(),
        },
        # `prev_cid` is only included when a prior batch exists — phase-1
        # `validate_shape` accepts both the absent and the explicit-null
        # forms, but the absent form keeps the canonical bytes shorter.
        "encryption": encryption_block,
        "payload": payload_b64,
    }
    if prev_cid is not None:
        env["prev_cid"] = prev_cid

    env["signature"] = _bundles.sign_envelope(env, priv=sink_cfg.signing_key)
    return env


def _resolve_version(
    conn: sqlite3.Connection,
    *,
    record_id: str,
    batch_index: int | str,
) -> int:
    """Map the voxterm `batch_index` to the envelope `version` we want
    to emit, with monotonicity already accounted for.

    For an integer `batch_index`, we use that as the version. The
    phase-1 verifier will independently reject if a higher version
    was already accepted (a cooperating producer never collides;
    a misbehaving one is the verifier's problem, not ours).

    For the literal `"redacted"` (spec §3.5 retroactive-seal), we
    look up the highest existing version for `(transcript.batch,
    record_id)` and add 1. If no prior batch exists (operator
    redacts a record that was never recorded — odd but legal), we
    start at 0.
    """
    if isinstance(batch_index, int) and not isinstance(batch_index, bool):
        return batch_index
    # The "redacted" path.
    prior = _bundles.latest_version(
        conn, kind="transcript.batch", record_id=record_id,
    )
    return 0 if prior is None else (prior + 1)


def _resolve_prev_cid(
    conn: sqlite3.Connection,
    *,
    record_id: str,
) -> str | None:
    """Return the cid of the most-recently-stored `transcript.batch`
    bundle for `record_id`, or None if this is the first batch for
    the record. Used to chain envelopes via `prev_cid`."""
    prior_rows = _bundles.list_(
        conn, kind="transcript.batch", record_id=record_id, limit=1,
    )
    if not prior_rows:
        return None
    prior_env = prior_rows[0]
    return _bundles.cid_for(prior_env)


def persist_transcript_batch(
    payload: dict[str, Any],
    *,
    sink_cfg: SinkConfig,
    encrypt: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Validate, wrap, [encrypt], sign, verify, store. The single sink entry point.

    Returns `(http_status, body_dict)` so the HTTP route layer is a
    thin shim. We don't raise for protocol-level errors (malformed
    payload, reservoir empty) — those are normal outcomes that need
    a status code. We DO raise for genuinely unexpected failures
    (verify pass passes shape/sig/monotonicity but `bundles.insert`
    then fails — should never happen because the verifier already
    canonicalized successfully).

    `encrypt=True` triggers the age-v1 path: the inner voxterm payload
    bytes are encrypted to every pubkey in the loaded reservoir
    (phase 7, spec §3.6). If the reservoir is empty (file missing or
    no entries) we return 503 `encryption_not_configured` —
    operator-fixable. The verifier is also passed the reservoir so a
    misconfigured producer can't sneak a recipient past us.
    """
    recipients: list[str] | None = None
    reservoir: Reservoir | None = None
    if encrypt:
        reservoir = load_reservoir_cached()
        recipients = reservoir.pubkeys()
        if not recipients:
            # The reservoir hasn't been staged. 503 (vs 501) signals
            # "service unavailable, retry later" — the operator can
            # drop a `.reservoir.yml` in place and the sink will pick
            # it up on the next process. This is distinct from the
            # phase-5 stub which returned 501 to mean "unimplemented".
            return 503, {
                "error": "encryption_not_configured",
                "reason": "reservoir_empty_or_missing",
            }

    ok, reason = validate_payload(payload)
    if not ok:
        return 400, {"error": "invalid_payload", "reason": reason}

    record_id = payload["record_id"]
    batch_index = payload["batch_index"]

    conn = _open_writer_conn()
    try:
        _bundles.ensure_schema(conn)
        version = _resolve_version(
            conn, record_id=record_id, batch_index=batch_index,
        )
        prev_cid = _resolve_prev_cid(conn, record_id=record_id)
        envelope = _build_envelope(
            payload,
            sink_cfg=sink_cfg,
            version=version,
            prev_cid=prev_cid,
            recipients=recipients,
        )

        # Run the phase-1 verifier on our own envelope. Belt-and-suspenders:
        # we know we just signed it, but the verifier also checks
        # alchemist whitelist + monotonicity — both of which can fail
        # legitimately (operator forgot to add the convent's pubkey to
        # alchemists.yml; a concurrent batch raced us). The
        # envelope-author check failing means the operator misconfigured
        # the box, which is a 500 from voxterm's perspective.
        result = _bundles.verify_bundle(
            envelope,
            alchemists=sink_cfg.alchemists,
            conn=conn,
            # When encrypting, pass the reservoir so the recipients-in-
            # reservoir cross-check fires. We just produced these
            # recipients ourselves (they ARE the reservoir), so the
            # check is belt-and-suspenders, but that's the same
            # rationale the existing alchemist+signature checks use.
            reservoir=reservoir,
        )
        if not result.ok:
            if result.reason in (
                _bundles.VerifyReason.AUTHOR_NOT_ALCHEMIST,
                _bundles.VerifyReason.SIGNATURE_INVALID,
            ):
                # Misconfigured convent box. Do NOT leak the raw
                # verifier reason as the canonical client error tag —
                # the client can't fix this — but include it in
                # `detail` for the operator's logs.
                return 500, {
                    "error": "sink_misconfigured",
                    "detail": result.reason,
                }
            if result.reason == _bundles.VerifyReason.VERSION_NOT_MONOTONIC:
                # A concurrent batch (or a re-POST of an older
                # batch_index) raced us. Surface 409 so a cooperating
                # voxterm client can re-derive batch_index and retry.
                return 409, {
                    "error": "version_not_monotonic",
                    "cid": result.cid,
                }
            # Any remaining shape failure means our wrapping logic is
            # buggy — that's a 500, not a 400, since the schema layer
            # already accepted the inputs.
            return 500, {
                "error": "envelope_build_failed",
                "detail": result.reason,
            }

        cid, was_new = _bundles.insert(envelope, conn=conn)
        conn.commit()
    finally:
        conn.close()

    # Mirror phase-3's `bundle_added` emit so phase-4's SSE subscribers
    # see hivemind-sourced bundles exactly as they would direct
    # `POST /bundles` writes. Best-effort: a bus failure does NOT
    # fail the POST since the bundle is already durably stored.
    try:
        from swf import event_bus
        event_bus.emit("bundle_added", {
            "cid": cid,
            "kind": envelope["kind"],
            "record_id": envelope["record_id"],
            "version": envelope["version"],
            "author_pubkey": envelope["author"]["pubkey"],
            "signed_at": envelope["author"]["signed_at"],
        })
    except Exception as exc:
        logger.error("bundle_added emit failed: %s", exc)

    # #93 phase 6: peer-to-peer propagation. The sink is a producer —
    # voxterm-driven transcript batches originate here, so they need
    # to fan out to LAN peers exactly like a direct `POST /bundles`
    # would. We mirror the `_do_bundles_post` wiring: only NEW bundles
    # propagate (`was_new` short-circuit), and we exclude the
    # envelope's own author pubkey so the receiving end doesn't
    # bounce the bundle back to us.
    if was_new:
        try:
            from swf.bundles import propagate_bundle_async
            from swf.indrex import db_path as _idx_db
            propagate_bundle_async(
                envelope,
                db_path=_idx_db(),
                exclude_pubkeys={envelope["author"]["pubkey"]},
            )
        except Exception as exc:
            # Same contract as peer_server: a propagation spawn
            # failure must not fail the response — the bundle is
            # durably stored.
            logger.error("bundle propagation spawn failed: %s", exc)

    return 201, {"cid": cid}


# ── unused but exposed for tests / introspection ─────────────────────────


def decode_envelope_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    """Inverse of `_build_envelope`'s payload step: decode + json-parse
    the inner voxterm payload from a stored `transcript.batch` envelope.

    Useful in tests + diagnostics; the spec doesn't require swf-node to
    expose this on the wire (renderers do their own decode), so it's
    not part of the HTTP surface."""
    raw = base64.b64decode(envelope["payload"])
    return json.loads(raw.decode("utf-8"))
