"""Bootstrap stdlib logging for swf-node CLI entry points (#79).

Module call sites use `logger = logging.getLogger(__name__)` everywhere
(e.g. `swf.peer_server`, `swf.peer_scraper`, `swf.bundles.puller`).
This module wires those loggers up to a single stderr handler with a
formatter that preserves the legacy `[component] msg` line shape, so
operators who grep for `[peer-server]` / `[peer-scraper]` / `[bundle-puller]`
keep working byte-for-byte.

Why bother with backwards-compat: PR #79 replaces ~90 `sys.stderr.write`
sites with `logger.info/warning/error/debug`. The boot line
`[peer-server] listening on http://...` is grep-load-bearing for every
operator script we ship; if we change its shape we break their watchdogs.

The bootstrap is idempotent (safe to call twice) and runs ONLY from
the entry-point side (`peer_server.main()`, `peer_cli.main()`). It
deliberately does not run on import — embedders who use swf as a
library configure logging themselves.

Verbose / quiet env vars (precedence: explicit level > verbose flags):

    SWF_LOG_LEVEL / LOGLEVEL  → explicit level (DEBUG/INFO/WARNING/ERROR)
    SWF_VERBOSE / RA_VERBOSE  → DEBUG when set
    SWF_QUIET                 → WARNING when set
    (default)                 → INFO

The `swf.search.audit` logger is left alone: per §24 it has its own
sink with `propagate=False`. Our root handler never sees its records.
"""
from __future__ import annotations

import logging
import os
import sys

#: Map our `swf.<sub>` logger names to the legacy `[bracket]` prefix
#: that operator log-greps look for. New modules should append here so
#: their logs stay grep-discoverable.
_NAME_TO_PREFIX: dict[str, str] = {
    "swf.peer_server": "peer-server",
    "swf.peer_scraper": "peer-scraper",
    "swf.event_bus": "event-bus",
    "swf.discovery": "discovery",
    "swf.friends": "friends",
    "swf.local_friends": "local_friends",
    "swf.fanout": "fanout",
    "swf.slice_consume": "slice-consume",
    "swf.community_full.metrics": "metrics",
    "swf.hivemind.mdns": "hivemind-mdns",
    "swf.hivemind.route": "hivemind",
    "swf.hivemind.sink": "hivemind",
    "swf.search.audit": "audit",
    "swf.search.audit_fallback": "audit",
    "swf.search.public_egress": "public_egress",
    "swf.bundles.puller": "bundle-puller",
    "swf.bundles.propagation": "bundle-propagation",
    "swf.web.fetch": "fetch",
    "swf.web.knowledge": "knowledge",
    "swf.web.providers": "providers",
    "swf.web.index": "index",
    "swf.peer_cli": "peer-cli",
}


def _prefix_for(name: str) -> str:
    """Return the legacy `[component]` prefix for `name`, falling back
    to the trailing component of the dotted name. Operators grep on
    these — adding a new module without updating `_NAME_TO_PREFIX`
    still produces a sensible bracket prefix derived from `__name__`."""
    if name in _NAME_TO_PREFIX:
        return _NAME_TO_PREFIX[name]
    # `swf.foo.bar` → `bar`; `swf.foo` → `foo`
    tail = name.rsplit(".", 1)[-1]
    return tail.replace("_", "-") if tail else name


class _BracketPrefixFormatter(logging.Formatter):
    """Emit messages as `[component] msg` so the new logger output
    is grep-compatible with the pre-#79 `sys.stderr.write` lines.

    For DEBUG records the formatter prepends a `DEBUG ` token so a
    verbose operator can tell debug spam from baseline ops chatter
    without having to read the level off a separate column. WARNING /
    ERROR records are similarly tagged — `[peer-server] WARN: ...`
    matches the previous hand-rolled convention in places like
    `peer_server` and `peer-scraper`.
    """

    def format(self, record: logging.LogRecord) -> str:
        prefix = _prefix_for(record.name)
        msg = record.getMessage()
        # Tag the message with a level marker for non-INFO records so
        # operators can distinguish info / warn / error / debug at a
        # glance. INFO records stay bare to match the pre-#79 shape.
        if record.levelno >= logging.ERROR:
            line = f"[{prefix}] error: {msg}"
        elif record.levelno >= logging.WARNING:
            line = f"[{prefix}] WARN: {msg}"
        elif record.levelno <= logging.DEBUG:
            line = f"[{prefix}] DEBUG: {msg}"
        else:
            line = f"[{prefix}] {msg}"
        if record.exc_info:
            line = f"{line}\n{self.formatException(record.exc_info)}"
        return line


class _LazyStderrHandler(logging.Handler):
    """`logging.StreamHandler` binds `self.stream` at construction time,
    so a handler created at process start writes to the original
    stderr fd forever — and pytest's `capsys` (which monkeypatches
    `sys.stderr` per-test) cannot capture our output.

    This handler resolves `sys.stderr` on every emit, so capsys-based
    tests keep working without an explicit `force=True` reset. The
    cost is one attribute lookup per log record — negligible at the
    rates swf-node logs at.
    """

    def emit(self, record: logging.LogRecord) -> None:
        import contextlib
        try:
            msg = self.format(record)
            stream = sys.stderr
            stream.write(msg + "\n")
            with contextlib.suppress(Exception):
                stream.flush()
        except Exception:
            self.handleError(record)


def _resolve_level() -> int:
    """Compute the effective logger level from env vars.

    Precedence: explicit `SWF_LOG_LEVEL` / `LOGLEVEL` wins. Otherwise
    `SWF_VERBOSE` / `RA_VERBOSE` flips DEBUG, `SWF_QUIET` flips WARNING.
    Default is INFO.
    """
    explicit = (
        os.environ.get("SWF_LOG_LEVEL")
        or os.environ.get("LOGLEVEL")
    )
    if explicit:
        explicit = explicit.strip().upper()
        if explicit in ("DEBUG", "INFO", "WARNING", "WARN", "ERROR", "CRITICAL"):
            return logging.WARNING if explicit == "WARN" else getattr(
                logging, explicit,
            )
    if (
        os.environ.get("SWF_VERBOSE")
        or os.environ.get("RA_VERBOSE")
    ):
        return logging.DEBUG
    if os.environ.get("SWF_QUIET"):
        return logging.WARNING
    return logging.INFO


_BOOTSTRAPPED = False


def bootstrap(*, force: bool = False) -> None:
    """Wire the `swf.*` logger tree to a stderr handler. Idempotent.

    Call from each `swf-*` console-script entry point at the very top
    of `main()`. Library callers (anyone who imports `swf.*` without
    going through a CLI) are NOT bootstrapped — they choose their own
    handlers. Per stdlib convention.

    `force=True` clears any existing handlers first; useful for tests
    that need to re-bootstrap after environment changes.
    """
    global _BOOTSTRAPPED
    root = logging.getLogger("swf")
    if force:
        for h in list(root.handlers):
            root.removeHandler(h)
        _BOOTSTRAPPED = False

    if _BOOTSTRAPPED:
        # Update level to reflect any env-var changes since the first
        # bootstrap; handler stays in place.
        root.setLevel(_resolve_level())
        return

    handler = _LazyStderrHandler()
    handler.setFormatter(_BracketPrefixFormatter())
    root.addHandler(handler)
    root.setLevel(_resolve_level())
    # Keep `propagate=True` so pytest's `caplog` (which hooks the bare
    # root logger) can capture our records. The bare root has no
    # handler in production, so propagation up to it is a no-op — no
    # double-printing risk. The lastResort handler only fires when NO
    # handler in the chain handled the record; ours did.
    root.propagate = True
    _BOOTSTRAPPED = True


def reset_for_tests() -> None:
    """Drop the bootstrap state so the next `bootstrap()` call rebuilds
    handlers from scratch. Used by the test autouse-teardown when a
    test mutates env vars that affect the level resolution."""
    global _BOOTSTRAPPED
    root = logging.getLogger("swf")
    for h in list(root.handlers):
        root.removeHandler(h)
    _BOOTSTRAPPED = False
