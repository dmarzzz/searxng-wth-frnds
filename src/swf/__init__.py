"""swf-node — self-sovereign LAN-first peer search.

See `INDREX.md` for the full spec. This package exposes:

    from swf.canonical import canonical_url
    # searxng engine adapter lives at swf/local_index.py, bind-mounted into searxng

Version is sourced from installed package metadata (single source of
truth: `pyproject.toml`). Falls back to a placeholder for editable
checkouts where metadata is unavailable.
"""

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version
    try:
        __version__ = _pkg_version("swf-node")
    except PackageNotFoundError:
        try:
            __version__ = _pkg_version("searxng-wth-frnds")  # legacy name
        except PackageNotFoundError:
            __version__ = "0.0.0+unknown"
except Exception:
    __version__ = "0.0.0+unknown"
