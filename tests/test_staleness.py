"""Tests for the temporal-marker staleness heuristic in web_search."""

from datetime import datetime

import pytest

from swf.web.providers import _query_is_time_sensitive


class TestExplicitMarkers:
    @pytest.mark.parametrize(
        "q",
        [
            "latest mixnet papers",
            "the LATEST research on anonymity",
            "what happened today in ethereum",
            "ethereum gas prices right now",
            "recent changes to openssh",
            "recently published security advisories",
            "current state of TLSNotary",
            "breaking news on searxng",
            "this week in crypto",
            "as of February, is Loopix deployed",
        ],
    )
    def test_marker_detected(self, q):
        assert _query_is_time_sensitive(q) is not None, q


class TestNotTemporal:
    @pytest.mark.parametrize(
        "q",
        [
            "what is a mixnet",
            "history of onion routing",
            "Chaum 1981 untraceable electronic mail",
            "RFC 6962 specification",
            "Merkle tree structure",
        ],
    )
    def test_no_marker(self, q):
        assert _query_is_time_sensitive(q) is None, q


class TestWordBoundary:
    """Single-word markers must respect word boundaries, not substring match."""

    def test_nowhere_is_not_now(self):
        assert _query_is_time_sensitive("nowhere to run") is None

    def test_todays_is_not_today(self):
        # "today's" has "today" as a prefix. Our regex uses \b which counts
        # the apostrophe as a word boundary; test the fact.
        assert _query_is_time_sensitive("today's news") is not None


class TestYearHeuristic:
    def test_current_year_triggers(self):
        year = datetime.now().year
        q = f"state of Ethereum rollups {year}"
        marker = _query_is_time_sensitive(q)
        assert marker == str(year)

    def test_prev_year_triggers(self):
        year = datetime.now().year - 1
        q = f"gas prices summary {year}"
        assert _query_is_time_sensitive(q) == str(year)

    def test_old_year_does_not_trigger(self):
        # Five years back is clearly historical, not time-sensitive.
        old = datetime.now().year - 5
        q = f"DNS resolvers {old}"
        assert _query_is_time_sensitive(q) is None

    def test_four_digit_non_year_substring_is_fine(self):
        # Something like "port 8080 config" should not trigger.
        assert _query_is_time_sensitive("port 8080 configuration") is None


class TestCaseInsensitive:
    def test_uppercase_marker(self):
        assert _query_is_time_sensitive("LATEST NEWS") is not None

    def test_mixed_case(self):
        assert _query_is_time_sensitive("Recent Developments") is not None
