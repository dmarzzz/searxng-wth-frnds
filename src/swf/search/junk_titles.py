"""Junk-title detection for the swf-node index pipeline (#84).

The right place to drop noise pages is at index time, not at every
downstream consumer. Two known categories of noise:

- HTTP error responses indexed as if they were content (titles like
  `404 Not Found`, `Page not found`).
- Lab / publication landing pages whose <title> is literally
  `Publications` or `Welcome`.

These pages have no semantic content and poison TF-IDF on consumers
(see shape-rotator-wrld-knwldge-viz#42 for the visible symptoms — the
viz repo ships the same blocklist as a defensive mitigation).

Filter by *trimmed, lowercased* title for predictable behaviour:
"Welcome to the Jungle (1991 film)" survives, but a page titled exactly
"Welcome" does not.

Public surface:

    is_junk_title(title) -> bool
    junk_title_reason(title) -> str | None     # diagnostic (for logs)
    JUNK_TITLE_EXACT, JUNK_TITLE_MIN_LEN       # config (override-friendly)
"""
from __future__ import annotations

import re

# Exact-match set, applied to the trimmed lowercase title. These all
# represent placeholder / nav / error responses with no content.
JUNK_TITLE_EXACT: frozenset[str] = frozenset({
    "404", "404 not found", "not found", "page not found",
    "publications", "welcome", "untitled", "untitled document",
    "loading…", "loading...", "loading",
    "access denied", "forbidden", "403 forbidden",
    "500 internal server error", "internal server error",
    "service unavailable", "503 service unavailable",
    "bad gateway", "502 bad gateway",
    "gateway timeout", "504 gateway timeout",
})

# `404`, `Error 500`, `503 Service Unavailable`, etc. — broad enough
# to catch the long tail without sniping legitimate titles. Anchored
# to start so "the 404 movie" survives but "404" / "Error 500 Server
# Error" don't.
_HTTP_STATUS_RE = re.compile(
    r"^(error\s+)?[345]\d\d"
    r"(\s+(not\s+found|forbidden|server\s+error|"
    r"unavailable|bad\s+gateway|gateway\s+timeout))?$"
)


def junk_title_reason(title: str) -> str | None:
    """Return a short reason string if `title` is junk, else None.
    Used by the indexer log so operators can audit which pages were
    skipped and why."""
    if not title:
        return "empty"
    t = str(title).strip().lower()
    if not t:
        return "empty"
    if t in JUNK_TITLE_EXACT:
        return f"exact_match({t!r})"
    if _HTTP_STATUS_RE.match(t):
        return f"http_status({t!r})"
    return None


def is_junk_title(title: str) -> bool:
    """True iff `title` matches a known junk pattern."""
    return junk_title_reason(title) is not None
