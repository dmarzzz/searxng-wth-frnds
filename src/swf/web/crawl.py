"""Link-graph primitives.

Discovering the frontier = following hyperlinks from one good source.
This module exposes the low-level plumbing; the agent composes them:

    extract_links(url) → list of anchor→url
    fetch_urls_parallel([urls...]) → concatenated page bodies
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request

_UA = (
    "Mozilla/5.0 (research-agent web_search) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


def extract_links(url: str) -> str:
    """Extract all outbound links from a page (for one-hop follow-up).

    Use after `fetch_url` when the page is dense with pointers to further
    reading — blog posts, Wikipedia-style pages, paper reference sections.
    Prefer this over re-reading the full page if you just need the link
    map.

    Args:
        url: Fully-qualified URL to scrape links from.

    Returns:
        Deduplicated list of `anchor_text → url` pairs, up to 60, in
        document order. External vs. same-domain links are labeled.
    """
    if not url.startswith(("http://", "https://")):
        return f"Invalid URL (must start with http:// or https://): {url}"

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Accept": "text/html,application/xhtml+xml",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            html = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return f"extract_links error for {url}: {exc}"

    pairs = re.findall(
        r'<a\b[^>]*?href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        html,
        flags=re.IGNORECASE | re.DOTALL,
    )
    parsed = urllib.parse.urlparse(url)
    same_host = parsed.netloc.lower()

    seen: set[str] = set()
    out: list[str] = []
    for href, anchor in pairs:
        href = href.strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        abs_url = urllib.parse.urljoin(url, href)
        key = abs_url.split("#", 1)[0].rstrip("/")
        if not key or key in seen:
            continue
        seen.add(key)
        anchor_text = re.sub(r"<[^>]+>", "", anchor)
        anchor_text = re.sub(r"\s+", " ", anchor_text).strip()[:120] or "(no text)"
        host = urllib.parse.urlparse(abs_url).netloc.lower()
        marker = "·ext" if host and host != same_host else "·int"
        out.append(f"- [{marker}] {anchor_text}  →  {abs_url}")
        if len(out) >= 60:
            break

    if not out:
        return f"No links found on {url}"
    return f"[extract_links · {len(out)} links from {url}]\n" + "\n".join(out)
