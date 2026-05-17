"""HTTP-layer glue for `POST /hivemind/transcripts`.

Phase 5 of #93. Spec §4.3. The handler runs:

  1. Content-Type gate (JSON-only, mirror phase 3 conventions).
  2. Body-size gate (1 MiB cap; phase 3's bundle cap is 4 MiB minus
     envelope overhead).
  3. Read + JSON parse.
  4. `?encrypt=true` query-param check.
  5. Delegate to `sink.persist_transcript_batch`, which validates
     schema, builds + signs the envelope, runs the verifier, and
     persists.

The sink module owns all the substantive logic. This file just maps
HTTP plumbing → sink call → HTTP response, so the bare-minimum
peer_server.py dispatch stays a one-liner.
"""
from __future__ import annotations

import contextlib
import json
import logging
from typing import Any
from urllib.parse import parse_qs, urlparse

from .sink import SinkConfig, load_signing_key, persist_transcript_batch

logger = logging.getLogger(__name__)

#: Voxterm transcript batches are small (≤30 segments × a few KB each).
#: 1 MiB is the spec's per-bundle envelope budget (4 MiB) minus a
#: pessimistic envelope-overhead allowance. Keeps memory bounded
#: against a slow-loris adversary that declares a huge Content-Length.
_MAX_HIVEMIND_BYTES = 1 * 1024 * 1024


def _build_sink_config_lazy(handler: Any) -> SinkConfig | tuple[int, dict]:
    """Lazy-load + cache the SinkConfig on the server instance.

    We attach the config to `handler.server` (the ThreadingHTTPServer
    instance) instead of module-state so a test that spins up a fresh
    server gets a fresh config without race-y global resets. The
    process-wide alchemist cache (in `swf.bundles.alchemists`) is
    reused — both the `POST /bundles` verifier and this route share
    a single parsed `.alchemists.yml`.

    Returns `SinkConfig` on success, or `(status, body)` on a
    misconfiguration we can return as a JSON error.
    """
    server = handler.server
    cached = getattr(server, "_hivemind_sink_cfg", None)
    if cached is not None:
        return cached

    # Lazy imports keep `swf.hivemind` importable in environments
    # where the alchemist YAML hasn't been written yet (CI, fresh
    # checkout). The route handler only fires when --hivemind-sink is
    # set, so by the time we get here the operator has committed to
    # the convent-box config.
    try:
        priv = load_signing_key()
    except FileNotFoundError as exc:
        return 500, {"error": "sink_misconfigured", "detail": str(exc)}
    except ValueError as exc:
        return 500, {"error": "sink_misconfigured", "detail": str(exc)}

    # Pull from the shared `swf.bundles.alchemists` cache so a single
    # YAML load serves the `POST /bundles` path, the pull puller, and
    # this hivemind route. Lifted from peer_server in the alchemist-
    # cache unify pass (mirror of the reservoir lift in #105).
    from swf.bundles import load_alchemists_cached
    alchemists = load_alchemists_cached()

    cfg = SinkConfig(signing_key=priv, alchemists=alchemists)
    server._hivemind_sink_cfg = cfg
    return cfg


def _do_hivemind_transcripts(handler: Any) -> None:
    """Handle `POST /hivemind/transcripts`.

    `handler` is a `swf.peer_server._Handler` instance. We don't import
    that class here (would create a circular dep) — instead we duck-
    type against its `_respond`, `headers`, `rfile`, `connection`,
    `path` attributes.

    Errors (in order of check):
      415 — non-JSON Content-Type
      413 — body > 1 MiB
      400 — malformed JSON / payload schema failure
      503 — `?encrypt=true` requested but the reservoir is empty (file
            missing or no entries). Operator stages `.reservoir.yml`
            and the sink picks it up on the next process boot.
      409 — concurrent batch raced us (version_not_monotonic)
      500 — sink misconfigured (signing key missing / pubkey not in
            alchemists.yml). Operator-fixable; the client retrying
            won't help.
      201 — `{"cid": "..."}`
    """
    # 1. Content-Type
    ctype_raw = handler.headers.get("Content-Type") or ""
    ctype = ctype_raw.split(";", 1)[0].strip().lower()
    if ctype != "application/json":
        return handler._respond(415, {
            "error": "unsupported_media_type",
            "expected": "application/json",
        })

    # 2. Body size
    try:
        n = int(handler.headers.get("Content-Length") or "0")
    except ValueError:
        n = 0
    if n > _MAX_HIVEMIND_BYTES:
        # Drain to keep the kernel from RST-ing the client mid-write.
        # Bounded chunks so memory stays small regardless of `n`.
        with contextlib.suppress(OSError):
            handler.connection.settimeout(15)
        remaining = n
        chunk = 64 * 1024
        try:
            while remaining > 0:
                got = handler.rfile.read(min(remaining, chunk))
                if not got:
                    break
                remaining -= len(got)
        except Exception:
            pass
        handler.close_connection = True
        return handler._respond(413, {
            "error": "payload_too_large",
            "max_bytes": _MAX_HIVEMIND_BYTES,
        })

    # 3. Read + parse
    with contextlib.suppress(OSError):
        handler.connection.settimeout(15)
    try:
        raw = handler.rfile.read(n) if n > 0 else b""
    except Exception as exc:
        return handler._respond(400, {
            "error": "malformed_json",
            "detail": f"read failed: {exc}",
        })
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return handler._respond(400, {"error": "malformed_json"})
    if not isinstance(payload, dict):
        return handler._respond(400, {"error": "malformed_json"})

    # 4. `?encrypt=true` query param OR `{"encrypt": true}` body field
    encrypt_flag = False
    try:
        qs = parse_qs(urlparse(handler.path).query)
        if (qs.get("encrypt") or [""])[0].lower() in ("1", "true", "yes"):
            encrypt_flag = True
    except Exception:
        pass
    if isinstance(payload.get("encrypt"), bool) and payload["encrypt"]:
        encrypt_flag = True

    # 5. Build (or fetch cached) SinkConfig.
    cfg_or_err = _build_sink_config_lazy(handler)
    if not isinstance(cfg_or_err, SinkConfig):
        status, body = cfg_or_err
        return handler._respond(status, body)
    sink_cfg = cfg_or_err

    # The `encrypt` field on the inner payload is meta — strip it so
    # it doesn't leak into the signed transcript-batch body.
    payload.pop("encrypt", None)

    # 6. Delegate.
    try:
        status, body = persist_transcript_batch(
            payload, sink_cfg=sink_cfg, encrypt=encrypt_flag,
        )
    except Exception:
        logger.exception("persist_transcript_batch crashed")
        return handler._respond(500, {"error": "sink_internal_error"})

    return handler._respond(status, body)
