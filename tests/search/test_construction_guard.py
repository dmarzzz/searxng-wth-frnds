"""TODO-10 pre-commit-style guard.

Every `SearchResponse` must be constructed via `SearchResponse.make()`
so the §29.2 invariants run. A direct `SearchResponse(...)` call
bypasses `validate_invariants` and could silently let a privacy-
laundering envelope escape.

This test greps the package for direct calls. It runs on every
`pytest` invocation, which is cheaper than a CI hook and always-on
locally. The single legitimate use (the `make()` classmethod itself)
is excluded by `_LEGITIMATE_LOCATIONS`.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

import swf.search

# Walk the search package source tree.
_SRC_ROOT = Path(swf.search.__file__).parent

# Only `response.py:make()` is allowed to call the SearchResponse
# constructor directly — that's where the invariants run. Any other
# call site must use `.make(...)`.
_LEGITIMATE_LOCATIONS: set[str] = {
    "response.py",
}

# Match `SearchResponse(` but NOT `SearchResponse.make(` /
# `SearchResponse.something(` / `class SearchResponse`. The pattern
# requires `SearchResponse` immediately followed by `(`.
_PATTERN = re.compile(r"\bSearchResponse\(")


def test_no_direct_search_response_constructions():
    """Fail loudly if any module under `swf.search` constructs
    `SearchResponse(...)` directly. The only allowed call site is
    `response.py:make()`."""
    offenders: list[tuple[str, int, str]] = []
    for py in _SRC_ROOT.rglob("*.py"):
        if py.name in _LEGITIMATE_LOCATIONS:
            continue
        for lineno, line in enumerate(py.read_text().splitlines(), start=1):
            stripped = line.strip()
            # Skip comments and import lines (the latter never have `(`).
            if stripped.startswith("#"):
                continue
            if _PATTERN.search(line):
                offenders.append((str(py.relative_to(_SRC_ROOT.parent.parent)),
                                  lineno, stripped))
    if offenders:
        report = "\n".join(f"  {f}:{ln}  {src}" for f, ln, src in offenders)
        pytest.fail(
            "Direct SearchResponse(...) construction detected. Use "
            "SearchResponse.make(...) so §29.2 invariants run.\n" + report
        )


def test_legitimate_response_make_is_present():
    """Sanity: the allow-listed `make()` classmethod still exists."""
    response_py = (_SRC_ROOT / "response.py").read_text()
    assert "def make(cls" in response_py, \
        "SearchResponse.make() classmethod is missing — that's the " \
        "only allowed entry point for response construction."


def test_router_uses_make_consistently():
    """Belt-and-suspenders: confirm router.py only uses .make()."""
    router_py = (_SRC_ROOT / "router.py").read_text()
    assert "SearchResponse.make" in router_py
    # Direct constructor not present
    assert not _PATTERN.search(router_py)
