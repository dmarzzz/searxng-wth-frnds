"""SPEC v0.3 §24 structured audit emitter.

The router calls :func:`emit` after every :func:`router.web_search` call,
once per response, regardless of branch (success / error / no_results /
confirmation_required). It writes a single JSON line to a stdlib logger
named ``swf.search.audit`` at INFO.

§24 is explicit about what is allowed in ``search_completed``:

    request_id, query_hmac, policy, delivery_path, origin_paths,
    public_egress_used, duration_ms

…and what is **disallowed**: raw queries, raw snippets, full friend
URLs, peer IP addresses, ticket tokens / nullifiers, receipt tokens /
nullifiers, local filesystem paths.

The allowlist is hardcoded; we never reflect into the response for any
field outside it. The logger has ``propagate=False`` so the audit
stream doesn't leak into the root logger by default — operators wire
their own handler via :func:`add_handler`.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from .response import SearchResponse

# §24 allowlist. Order matches the spec example for readability of the
# emitted JSON line; the test pins the exact key set, not the order.
_ALLOWED_FIELDS: tuple[str, ...] = (
    "event",
    "request_id",
    "query_hmac",
    "policy",
    "delivery_path",
    "origin_paths",
    "public_egress_used",
    "duration_ms",
)


AUDIT_LOGGER: logging.Logger = logging.getLogger("swf.search.audit")
# §24: the audit stream is its own sink. Do not let it surface through
# the root logger by default — operators must opt in via add_handler().
AUDIT_LOGGER.propagate = False
# Default level so a handler attached later sees INFO records. The
# stdlib default for un-configured loggers is WARNING, which would
# drop our INFO emissions before any handler ran.
if AUDIT_LOGGER.level == logging.NOTSET:
    AUDIT_LOGGER.setLevel(logging.INFO)


def add_handler(handler: logging.Handler) -> None:
    """Attach a handler to the audit logger.

    Operators route the audit stream to a sink (file, syslog, etc.)
    without rebinding ``AUDIT_LOGGER``. Re-adding the same handler is a
    no-op.
    """
    if handler not in AUDIT_LOGGER.handlers:
        AUDIT_LOGGER.addHandler(handler)


def emit(response: SearchResponse, *, event: str = "search_completed") -> None:
    """Emit a §24-compliant audit event for ``response``.

    Exactly one log record is produced per call. The record's message is
    a single JSON object whose keys are drawn ONLY from the §24
    allowlist. The query_hmac is taken from ``response.debug`` (where
    every router branch already records it); if absent — e.g. a future
    branch forgets to populate it — the field is emitted as ``None``
    rather than reaching for any other identifier.
    """
    payload: dict[str, Any] = {
        "event": event,
        "request_id": response.request_id,
        "query_hmac": (response.debug or {}).get("query_hmac"),
        "policy": (response.policy or {}).get("effective")
                  or (response.policy or {}).get("requested"),
        "delivery_path": response.delivery_path.value,
        "origin_paths": [p.value for p in response.origin_paths],
        "public_egress_used": response.public_egress_used_this_request,
        "duration_ms": max(0, response.completed_ms - response.created_ms),
    }

    # Defensive: enforce the allowlist at emit time too. If a future
    # edit adds a key above that's not in _ALLOWED_FIELDS, drop it
    # rather than ship it.
    payload = {k: v for k, v in payload.items() if k in _ALLOWED_FIELDS}

    # Pass-4 finding #1: a misbehaving handler (full disk, broken
    # syslog socket, raising filter) MUST NOT bubble out and fail the
    # user-facing request. The audit stream is best-effort by spec
    # §24 — drop and warn to a SEPARATE logger so the audit logger's
    # broken handler can't recurse into our own warning.
    try:
        AUDIT_LOGGER.info(json.dumps(payload, separators=(",", ":")))
    except Exception as e:  # noqa: BLE001
        # `swf.search.audit` propagate=False means caplog can't see
        # this; route the warning through a sibling logger that flows
        # to the swf root handler instead.
        _AUDIT_FALLBACK_LOGGER.warning("emit failed (audit dropped): %r", e)


_AUDIT_FALLBACK_LOGGER: logging.Logger = logging.getLogger(
    "swf.search.audit_fallback",
)
