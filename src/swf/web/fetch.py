"""URL fetching: local extraction first, network intermediary only as fallback.

Pipeline per URL:
    1. cache lookup (`.ra_cache/fetch/`)
    2. raw HTML fetch (plain urllib) + trafilatura extraction — OSS, local
    3. if step 2 returns empty (SPA, PDF, paywall), fall back to Jina Reader
    4. on success: cache + write-through to world_knowledge/

This keeps the default path fully self-sovereign — Jina is only touched
when local extraction fails.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from swf.web.knowledge import world_write

_CACHE_DIR = Path(os.environ.get("RA_CACHE_DIR", ".ra_cache/fetch"))
_CACHE_TTL = int(os.environ.get("RA_CACHE_TTL_SEC", str(60 * 60 * 24 * 7)))  # 7 days

logger = logging.getLogger(__name__)


def _log(msg: str) -> None:
    # #79: legacy verbose-gated info log. The logger level handles the gate.
    logger.debug("%s", msg)


def _cache_path_for(url: str) -> Path:
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:20]
    return _CACHE_DIR / f"{h}.txt"


def _read_cache(url: str) -> tuple[str, str] | None:
    """Return (text, extractor) or None. Extractor is stored on first line."""
    p = _cache_path_for(url)
    if not p.exists():
        return None
    if (time.time() - p.stat().st_mtime) > _CACHE_TTL:
        return None
    try:
        raw = p.read_text(encoding="utf-8")
    except Exception:
        return None
    # Header format: first line "#extractor:<name>" then blank line then body.
    if raw.startswith("#extractor:"):
        head, _, body = raw.partition("\n\n")
        extractor = head.split(":", 1)[1].strip()
        return body, extractor
    return raw, "unknown"


def _write_cache(url: str, text: str, extractor: str) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path_for(url).write_text(
            f"#extractor:{extractor}\n\n{text}", encoding="utf-8"
        )
    except Exception:
        pass


_UA = (
    "Mozilla/5.0 (research-agent web_search) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def _fetch_html(url: str, timeout: int = 25) -> str:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Accept": "text/html,application/xhtml+xml,application/pdf",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        ctype = resp.headers.get("Content-Type", "")
        raw = resp.read()
    # We let trafilatura handle HTML → text. For other types, we bail out
    # so Jina Reader gets a chance (it handles PDFs cleanly).
    if "html" not in ctype.lower() and "xml" not in ctype.lower():
        raise RuntimeError(f"non-html content-type {ctype!r} — falling through to Jina")
    # Best-effort decode.
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _extract_trafilatura(html: str, url: str) -> tuple[str, str]:
    """Return (markdown, title) or ("", "") on failure."""
    try:
        import trafilatura
    except Exception as exc:
        _log(f"trafilatura unavailable: {exc}")
        return "", ""

    try:
        text = trafilatura.extract(
            html,
            url=url,
            output_format="markdown",
            include_links=True,
            include_tables=True,
            with_metadata=False,
            favor_recall=True,
        )
        meta = trafilatura.extract_metadata(html)
        title = (meta.title if meta else "") or ""
        return (text or ""), title
    except Exception as exc:
        _log(f"trafilatura failed for {url}: {exc}")
        return "", ""


def _fetch_jina(url: str, timeout: int = 30) -> str:
    """Last-resort fallback. Only touches r.jina.ai when local extraction fails."""
    if os.environ.get("RA_DISABLE_JINA") in ("1", "true", "yes"):
        raise RuntimeError("RA_DISABLE_JINA set — refusing Jina fallback")

    proxy_url = f"https://r.jina.ai/{url}"
    req = urllib.request.Request(
        proxy_url,
        headers={"User-Agent": "research-agent-web_search", "Accept": "text/plain, text/markdown"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


_ARXIV_PDF_RE = re.compile(
    # Captures both modern numeric ids (2104.05849) and old-style ids with
    # subject prefix (cs.DC/0508053). Trailing version suffix (v1, v2, ...)
    # and `.pdf` extension are stripped from the captured id.
    r"^https?://(?:www\.|export\.)?arxiv\.org/pdf/([\w./]+?)(?:v\d+)?(?:\.pdf)?/?$",
    re.IGNORECASE,
)


def _arxiv_abs_url_for_pdf(url: str) -> str | None:
    """If `url` is an arxiv PDF URL, return the corresponding abstract page
    URL (which carries proper title metadata in its HTML <head>). Otherwise
    return None.

    Examples:
        https://arxiv.org/pdf/2104.05849            → https://arxiv.org/abs/2104.05849
        https://arxiv.org/pdf/2104.05849.pdf        → https://arxiv.org/abs/2104.05849
        https://arxiv.org/pdf/2104.05849v3          → https://arxiv.org/abs/2104.05849
        https://export.arxiv.org/pdf/cs.DC/0508053  → https://arxiv.org/abs/cs.DC/0508053

    The PDF body has the paper text but trafilatura+Jina don't preserve the
    paper title from it — pages end up with placeholder titles ("Document"
    or the URL) and cluster by stray body text rather than topic. The abs
    page is an HTML page; trafilatura extracts the proper title from
    <title> + <meta name="citation_title">.
    """
    if not url:
        return None
    m = _ARXIV_PDF_RE.match(url.strip())
    if not m:
        return None
    arxiv_id = m.group(1)
    return f"https://arxiv.org/abs/{arxiv_id}"


def _get_clean_text(url: str) -> tuple[str, str, str]:
    """Returns (text, title, extractor). Raises on total failure."""
    # 1. cache (keyed on the user-visible URL — we don't rewrite the
    #    canonical URL even when we fetch from a different source below).
    cached = _read_cache(url)
    if cached is not None:
        text, extractor = cached
        _log(f"cache hit {url} ({extractor})")
        # Title is not cached separately; best-effort infer.
        return text, "", extractor

    # arxiv PDF → abs page rewrite for fetching. The user's URL stays the
    # cache key + index key; we just transparently fetch the abs page so
    # trafilatura can read the proper paper title from HTML metadata.
    # PDF bodies still go through the Jina fallback path if the abs page
    # extraction comes up short.
    fetch_url_target = url
    rewrite = _arxiv_abs_url_for_pdf(url)
    if rewrite is not None:
        _log(f"arxiv pdf detected → fetching abs page instead: {url} → {rewrite}")
        fetch_url_target = rewrite

    # 2. local extraction (from the rewritten URL when applicable)
    try:
        html = _fetch_html(fetch_url_target)
        text, title = _extract_trafilatura(html, fetch_url_target)
        if text and len(text.strip()) > 200:
            _write_cache(url, text, "trafilatura")
            world_write(url, text, extractor="trafilatura", title=title)
            _log(f"local extract {url} ({len(text)} chars)")
            return text, title, "trafilatura"
        _log(f"local extract empty for {fetch_url_target}, falling through to Jina")
    except Exception as exc:
        _log(f"local fetch/extract failed for {fetch_url_target}: {exc}")

    # 3. Jina fallback — fetch the ORIGINAL url here (not the rewrite).
    #    For arxiv PDFs, Jina's reader handles the PDF body directly and
    #    we want that text, not the abs-page snippet. Combined with the
    #    trafilatura-derived title above (when that succeeded), this gives
    #    us paper-title metadata + full PDF body in the same page.
    raw = _fetch_jina(url)
    import re as _re
    text = _re.sub(r"\n{3,}", "\n\n", raw).strip()
    _write_cache(url, text, "jina")
    world_write(url, text, extractor="jina")
    _log(f"jina extract {url} ({len(text)} chars)")
    # If we attempted an arxiv abs-page extract above and got a title out,
    # propagate it here even though jina was the body extractor. That
    # title comes from arxiv.org's authoritative metadata.
    arxiv_title = ""
    if rewrite is not None:
        try:
            html_abs = _fetch_html(rewrite)
            _t, arxiv_title = _extract_trafilatura(html_abs, rewrite)
        except Exception:
            pass
    return text, arxiv_title, "jina"


def fetch_url(url: str, start_char: int = 0, max_chars: int = 16000) -> str:
    """Fetch the FULL TEXT of a URL (paginated, cached, archived).

    Pipeline — local-first, self-sovereign:
        1. On-disk cache (`.ra_cache/fetch/`, 7-day TTL).
        2. Raw HTML fetch + `trafilatura` local extraction (OSS, no network
           intermediary beyond the page itself).
        3. If local extraction returns empty (SPAs, PDFs, paywalls), fall
           through to Jina Reader (`r.jina.ai`).
        4. On success, the cleaned text is ALSO written to
           `~/world_knowledge/web/<domain>/...md` so the knowledge base
           grows over time.

    Use for blog posts, workshop papers, READMEs, news articles, anything
    where the snippet isn't enough. For very long pages, paginate with
    `start_char=16000` — the response header tells you what remains.

    Args:
        url: Fully-qualified URL including scheme (https://...).
        start_char: Offset for pagination (default 0).
        max_chars: Characters to return this call (default 16000).

    Returns:
        Markdown slice with `[offset=N/total=T · extractor=X]` header.
    """
    if not url.startswith(("http://", "https://")):
        return f"Invalid URL (must start with http:// or https://): {url}"

    text, _title, extractor = _get_clean_text(url)

    total = len(text)
    start = max(0, int(start_char))
    end = min(total, start + max(1, int(max_chars)))
    body = text[start:end]

    header = f"[offset={start}/total={total} · extractor={extractor}]"
    if end < total:
        header += f" remaining={total - end} — call fetch_url(url, start_char={end}) for more"
    return f"{header}\n\n{body}"


def fetch_urls_parallel(urls: list[str], max_chars_each: int = 6000) -> str:
    """Fetch multiple URLs concurrently (shared cache + world_knowledge archive).

    Use when you have a shortlist of URLs and want all of them in one
    step — dramatically faster than serial `fetch_url` calls. Each URL
    gets the same local-first extraction pipeline.

    Args:
        urls: List of fully-qualified URLs (max 8).
        max_chars_each: Per-URL truncation (default 6000).

    Returns:
        Stitched text: each page prefixed with `=== URL ===` and a
        short status line.
    """
    urls = [u for u in (urls or []) if u and u.startswith(("http://", "https://"))][:8]
    if not urls:
        return "fetch_urls_parallel: no valid URLs provided"

    def _one(u: str):
        try:
            return u, fetch_url(u, start_char=0, max_chars=max_chars_each), None
        except Exception as exc:
            return u, "", f"{type(exc).__name__}: {exc}"

    results: list[tuple[str, str, str | None]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(urls))) as pool:
        futs = {pool.submit(_one, u): u for u in urls}
        for fut in as_completed(futs):
            results.append(fut.result())

    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda t: order.get(t[0], 99))

    blocks = []
    for u, body, err in results:
        if err:
            blocks.append(f"=== {u} ===\nERROR: {err}")
        else:
            blocks.append(f"=== {u} ===\n{body}")
    return "\n\n".join(blocks)
