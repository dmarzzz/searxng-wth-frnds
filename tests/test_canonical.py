"""Tests for swf.canonical."""

import pytest

from swf.canonical import canonical_url, canonical_url_safe


class TestScheme:
    def test_lowercases_scheme(self):
        assert canonical_url("HTTPS://example.com/") == "https://example.com/"
        assert canonical_url("HtTp://example.com/foo") == "http://example.com/foo"


class TestHost:
    def test_lowercases_host(self):
        assert canonical_url("https://Example.COM/foo") == "https://example.com/foo"

    def test_preserves_userinfo(self):
        assert (
            canonical_url("https://Alice@Example.COM/")
            == "https://Alice@example.com/"
        )

    def test_ipv6(self):
        assert (
            canonical_url("https://[2001:db8::1]:443/x")
            == "https://[2001:db8::1]/x"
        )


class TestDefaultPorts:
    def test_drops_http_80(self):
        assert canonical_url("http://example.com:80/foo") == "http://example.com/foo"

    def test_drops_https_443(self):
        assert (
            canonical_url("https://example.com:443/foo")
            == "https://example.com/foo"
        )

    def test_keeps_nondefault_port(self):
        assert (
            canonical_url("http://example.com:8080/foo")
            == "http://example.com:8080/foo"
        )
        assert (
            canonical_url("https://example.com:8443/foo")
            == "https://example.com:8443/foo"
        )


class TestFragment:
    def test_drops_fragment(self):
        assert (
            canonical_url("https://example.com/foo#section-3")
            == "https://example.com/foo"
        )

    def test_drops_empty_fragment(self):
        assert canonical_url("https://example.com/foo#") == "https://example.com/foo"


class TestTrackingParams:
    def test_strips_utm(self):
        assert (
            canonical_url("https://example.com/foo?utm_source=x&utm_campaign=y")
            == "https://example.com/foo"
        )

    def test_strips_fbclid_gclid(self):
        assert (
            canonical_url("https://example.com/foo?fbclid=abc&gclid=def")
            == "https://example.com/foo"
        )

    def test_preserves_real_params(self):
        # `q` is a real param; utm_source is tracking.
        got = canonical_url("https://example.com/s?q=hello&utm_source=feed")
        assert got == "https://example.com/s?q=hello"

    def test_youtube_si_stripped(self):
        assert (
            canonical_url("https://youtu.be/abc123?si=trackingtoken")
            == "https://youtu.be/abc123"
        )


class TestQueryOrdering:
    def test_sorts_query_params(self):
        # Same semantic query, different order on input.
        a = canonical_url("https://example.com/s?b=2&a=1")
        b = canonical_url("https://example.com/s?a=1&b=2")
        assert a == b == "https://example.com/s?a=1&b=2"

    def test_sorts_repeated_keys(self):
        got = canonical_url("https://example.com/s?tag=b&tag=a")
        assert got == "https://example.com/s?tag=a&tag=b"


class TestPath:
    def test_strips_trailing_slash(self):
        assert canonical_url("https://example.com/foo/") == "https://example.com/foo"

    def test_preserves_root_slash(self):
        assert canonical_url("https://example.com/") == "https://example.com/"

    def test_collapses_duplicate_slashes(self):
        assert (
            canonical_url("https://example.com//foo///bar/")
            == "https://example.com/foo/bar"
        )

    def test_empty_path_becomes_root(self):
        assert canonical_url("https://example.com") == "https://example.com/"


class TestEncoding:
    def test_percent_encoding_consistency(self):
        # Input has mixed-case percent encoding; output should be normalized.
        a = canonical_url("https://example.com/path%2dwith%2Dhyphen")
        b = canonical_url("https://example.com/path-with-hyphen")
        assert a == b


class TestIdempotence:
    @pytest.mark.parametrize(
        "url",
        [
            "https://example.com/foo",
            "http://example.com:8080/path?q=1",
            "https://User@Example.com/a/b/c#frag",
            "https://example.com/?utm_source=twitter",
            "https://example.com//double//slash/",
            "https://youtu.be/abc?si=xyz&v=123",
        ],
    )
    def test_idempotent(self, url):
        once = canonical_url(url)
        twice = canonical_url(once)
        assert once == twice


class TestInvalid:
    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            canonical_url("")

    def test_rejects_none(self):
        with pytest.raises(ValueError):
            canonical_url(None)  # type: ignore[arg-type]

    def test_rejects_relative(self):
        with pytest.raises(ValueError):
            canonical_url("/foo/bar")

    def test_safe_returns_none_on_invalid(self):
        assert canonical_url_safe("") is None
        assert canonical_url_safe("/foo") is None
        assert canonical_url_safe("not a url") is None

    def test_safe_returns_canonical_on_valid(self):
        assert (
            canonical_url_safe("HTTPS://Example.com/") == "https://example.com/"
        )


class TestMergerScenario:
    """The exact scenario that motivated canonicalization.

    SearXNG dedups by URL-string-exact. If our local index stores
    `https://example.com/foo` and Google returns
    `https://example.com/foo/?utm_source=newsletter#h1`, the two must
    canonicalize to the same string or the weight boost silently fails.
    """

    def test_trailing_slash_merges_with_non_trailing(self):
        local = canonical_url("https://example.com/foo")
        google = canonical_url(
            "https://example.com/foo/?utm_source=newsletter#h1"
        )
        assert local == google
