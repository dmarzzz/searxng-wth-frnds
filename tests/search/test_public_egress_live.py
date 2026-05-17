"""TODO-14: live SearXNG end-to-end tests for SELF_PUBLIC_EGRESS.

The Phase 2 suite in `test_public_egress.py` is mock-only — it
monkeypatches `urllib.request.urlopen` so we can run unit tests without
docker. That's good for CI speed but blind to upstream regressions:
DuckDuckGo or Brave changing their JSON shape, SearXNG renaming a
field, etc.

This module fills that gap. Every test is decorated with
`@pytest.mark.searxng_live` so the default `pytest -q` run skips them
(see `pyproject.toml`). To run them locally:

    docker compose -f docker-compose.searxng-test.yml up -d
    pytest -m searxng_live

CI exercises them via `.github/workflows/searxng-live.yml`. The
fixture's settings file is `searxng-test/settings.yml`, which enables
ONLY the engines listed in `public_egress.DEFAULT_ENGINES`
(duckduckgo + brave) — the allowlist test below is what catches drift
between fixture config and production allowlist.

These tests deliberately do NOT assert against the content of any
specific result row. Live search is non-deterministic: the wrong
strategy is to bake in expectations like "first result is Wikipedia".
We only assert structural / contractual properties:
  - the call returns a RouteOutcome with status="ok" and >=1 result
  - the engines that show up are a subset of our allowlist
  - a hostile/long query doesn't crash the engine
"""
from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest

from swf.search import (
    DeliveryPath,
    OriginPath,
    PrivacyLevel,
    build_context,
)
from swf.search.public_egress import DEFAULT_ENGINES, search

# Live tests share one base URL; tests can override per-call but the
# default matches the docker-compose fixture.
LIVE_SEARXNG_URL = os.environ.get("SWF_SEARXNG_URL", "http://127.0.0.1:8888")


def _ctx(query: str):
    return build_context(query, policy_name="default", hmac_secret=b"x" * 32)


def _searxng_is_up() -> bool:
    """Best-effort liveness probe so the test gives a clean skip
    (rather than a confusing connection-refused traceback) when the
    `searxng_live` marker is selected but docker isn't actually up.
    The user is opting into live tests by passing -m, so they DO want
    a failure if docker is down — but skipping with a clear message
    beats a stack trace from urllib."""
    try:
        with urllib.request.urlopen(
            f"{LIVE_SEARXNG_URL}/healthz", timeout=2.0
        ) as resp:
            return resp.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


@pytest.fixture(scope="module", autouse=True)
def _require_live_searxng():
    if not _searxng_is_up():
        pytest.skip(
            f"live SearXNG not reachable at {LIVE_SEARXNG_URL} — "
            "bring it up with "
            "`docker compose -f docker-compose.searxng-test.yml up -d`"
        )


# ─── live tests ─────────────────────────────────────────────────────


@pytest.mark.searxng_live
def test_basic_query_returns_results():
    """A boring query against the live SearXNG should produce at
    least one result. We don't assert on result content (live search
    is non-deterministic) — just on the contract that the JSON parsed
    cleanly into our normalized shape."""
    out = search(_ctx("decentralized search engines"),
                 base_url=LIVE_SEARXNG_URL)
    assert out.attempt.path == DeliveryPath.SELF_PUBLIC_EGRESS, (
        "delivery path label must survive end-to-end"
    )
    assert out.attempt.status == "ok", (
        f"expected ok, got status={out.attempt.status} "
        f"reason={out.attempt.reason!r}"
    )
    assert len(out.results) >= 1, (
        "live ddg+brave should produce at least one row for a generic "
        "query; if this is flaking, the upstream engines may be down"
    )
    # Every result must carry the right path metadata.
    first = out.results[0]
    assert first.delivery_path == DeliveryPath.SELF_PUBLIC_EGRESS
    assert first.origin_path == OriginPath.SELF_PUBLIC_EGRESS
    assert first.canonical_url.startswith(("http://", "https://"))
    assert out.privacy_level == PrivacyLevel.PUBLIC_FROM_SELF


@pytest.mark.searxng_live
def test_engines_allowlist_respected():
    """The fixture's settings.yml enables only duckduckgo + brave (the
    DEFAULT_ENGINES). The response must NOT carry any engine outside
    that allowlist — otherwise we have configuration drift between
    `public_egress.DEFAULT_ENGINES` and the SearXNG settings, which is
    exactly the regression this fixture exists to catch."""
    out = search(_ctx("python programming"),
                 base_url=LIVE_SEARXNG_URL)
    assert out.attempt.status == "ok", (
        f"need a successful query to inspect engines; got "
        f"status={out.attempt.status} reason={out.attempt.reason!r}"
    )
    engines_returned = set(out.extras["egress"]["engines_returned"])
    allowlist = set(DEFAULT_ENGINES)
    # `engines_returned` may be a STRICT subset of the allowlist (one
    # engine could time out or rate-limit on a given run). What it
    # MUST NOT be is a superset.
    extras = engines_returned - allowlist
    assert not extras, (
        f"SearXNG returned engines outside the allowlist: {extras}. "
        f"Either DEFAULT_ENGINES drifted from "
        f"searxng-test/settings.yml, or SearXNG is silently fanning "
        f"out to default engines. This is the exact regression this "
        f"fixture exists to catch."
    )
    # And we should have heard from at least one of the two — total
    # silence means the engines aren't actually wired up.
    assert engines_returned, (
        "no engines reported in egress.engines_returned — fixture "
        "settings.yml may have all engines disabled"
    )


@pytest.mark.searxng_live
def test_long_malformed_query_does_not_crash_engine():
    """A pathologically long query should produce a graceful response
    (ok / no_results / bad_request) rather than a 5xx or a parser
    crash. SearXNG itself can refuse oversize queries; that's fine —
    what we need is for `public_egress.search` to translate any
    upstream-failure into a sane RouteOutcome with the right
    `suspicious_failure` flag.

    Specifically: a 4xx from SearXNG is NOT suspicious (it's the user
    doing something silly); a 5xx or timeout WOULD be."""
    # 4096-char query of mixed unicode / punctuation — well past
    # SearXNG's typical limits but legal HTTP.
    weird = ("decentralized " * 200) + ("✨🦀" * 200) + ("'\"<>?#" * 50)
    out = search(_ctx(weird), base_url=LIVE_SEARXNG_URL,
                 timeout_s=10.0)
    # Either we got ok / no_results, or we got a benign error that
    # the router treats as non-suspicious. The forbidden states are
    # status="timeout" or any suspicious_failure=True — those would
    # mean the long query took the whole engine down.
    assert out.attempt.status in {"ok", "no_results", "error"}, (
        f"unexpected status {out.attempt.status} on long query"
    )
    if out.attempt.status == "error":
        assert out.attempt.suspicious_failure is False, (
            f"long query produced a suspicious_failure "
            f"({out.attempt.reason!r}) — that means SearXNG 5xx'd or "
            f"timed out, which is a real bug worth investigating"
        )
