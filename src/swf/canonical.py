"""Canonical URL normalization.

One function applied once on ingest, then URLs are compared byte-equal
thereafter. Single source of truth for `swf/web/*` and
`swf/local_index.py`. Rules are specified in `INDREX.md` under
"Derivative decisions." Keep this module small and the rules explicit.

The rules exist because searxng's result merger (`searx/results.py`)
dedups by URL-string-exact over `netloc|path|params|query|fragment`.
If our local index stores `https://example.com/foo` and Google returns
`https://example.com/foo/` (trailing slash), they will NOT merge, and
the `weight: 4.0` boost that should float local hits to the top
silently does nothing. Canonicalization on ingest is load-bearing.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, quote, unquote, urlparse, urlunparse

# Tracking parameters stripped on ingest. Order is irrelevant; exact
# match only. Wildcards handled explicitly.
_TRACKING_EXACT = frozenset(
    {
        "fbclid",
        "gclid",
        "dclid",
        "msclkid",
        "mc_cid",
        "mc_eid",
        "_hsenc",
        "_hsmi",
        "mkt_tok",
        "ref",
        "ref_src",
        "igshid",
        "igsh",
        "si",  # youtube share token
        "yclid",
        "gbraid",
        "wbraid",
    }
)

# Prefix-matched tracking params. `utm_*` is the headline case.
_TRACKING_PREFIXES = ("utm_",)


def _is_tracking_param(key: str) -> bool:
    if key in _TRACKING_EXACT:
        return True
    lowered = key.lower()
    return any(lowered.startswith(p) for p in _TRACKING_PREFIXES)


def _collapse_slashes(path: str) -> str:
    if "//" not in path:
        return path
    out = []
    prev_slash = False
    for ch in path:
        if ch == "/":
            if not prev_slash:
                out.append(ch)
            prev_slash = True
        else:
            out.append(ch)
            prev_slash = False
    return "".join(out)


def _strip_trailing_slash(path: str) -> str:
    # Keep the root "/" exactly; strip trailing slash on any longer path.
    if len(path) > 1 and path.endswith("/"):
        return path.rstrip("/")
    return path


_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _normalize_netloc(scheme: str, netloc: str) -> str:
    """Lowercase host, drop default ports, preserve userinfo if present."""
    if not netloc:
        return ""
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        userinfo = userinfo + "@"
    # IPv6 literals come wrapped in [].
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            return userinfo + hostport.lower()
        host = hostport[: close + 1]
        rest = hostport[close + 1 :]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port = hostport.partition(":")
    host = host.lower()
    if port and _DEFAULT_PORTS.get(scheme.lower()) == port:
        port = ""
    return userinfo + (f"{host}:{port}" if port else host)


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    filtered = [(k, v) for k, v in pairs if not _is_tracking_param(k)]
    # Stable sort by key then value so semantically-equal queries hash equal.
    filtered.sort(key=lambda kv: (kv[0], kv[1]))
    out = []
    for k, v in filtered:
        k_enc = quote(k, safe="")
        v_enc = quote(v, safe="")
        out.append(f"{k_enc}={v_enc}" if v != "" else k_enc)
    return "&".join(out)


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Decode and re-encode consistently. Keep unreserved chars per RFC 3986
    # plus the path-reserved chars that don't carry semantic weight.
    decoded = unquote(path)
    reencoded = quote(decoded, safe="/-._~!$&'()*+,;=:@")
    reencoded = _collapse_slashes(reencoded)
    reencoded = _strip_trailing_slash(reencoded)
    return reencoded or "/"


def canonical_url(url: str) -> str:
    """Return the canonical form of a URL for storage and comparison.

    Idempotent: `canonical_url(canonical_url(x)) == canonical_url(x)`.

    Rules applied, in order:
      1. Lowercase scheme and host.
      2. Drop default port (80 for http, 443 for https).
      3. Drop URL fragment.
      4. Strip known tracking query params (utm_*, fbclid, gclid, ...).
      5. Sort remaining query params by key then value.
      6. Collapse duplicate slashes in path.
      7. Strip trailing `/` on path (except when path is exactly `/`).
      8. Re-encode path and query consistently.

    Raises `ValueError` on URLs without a scheme or netloc.
    """
    if not url or not isinstance(url, str):
        raise ValueError(f"canonical_url expects a non-empty string, got {url!r}")

    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"canonical_url requires scheme + netloc: {url!r}")

    scheme = parsed.scheme.lower()
    netloc = _normalize_netloc(scheme, parsed.netloc)
    path = _normalize_path(parsed.path)
    query = _normalize_query(parsed.query)

    # Fragment is always dropped.
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def canonical_url_safe(url: str) -> str | None:
    """Like `canonical_url` but returns None instead of raising.

    Use this at ingest boundaries where an invalid URL should skip the
    record rather than blow up the pipeline.
    """
    try:
        return canonical_url(url)
    except ValueError:
        return None
