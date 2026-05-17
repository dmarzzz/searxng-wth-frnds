"""#84: junk-title filter at swf-node index time + at peer ingest."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from swf import peer_scraper
from swf.search import migration
from swf.search.junk_titles import (
    JUNK_TITLE_EXACT,  # noqa: F401  (re-exported)
    is_junk_title,
    junk_title_reason,
)

# ── unit: matcher ─────────────────────────────────────────────────


@pytest.mark.parametrize("title", [
    "404", "404 Not Found", "Not Found", "Page not found",
    "Publications", "Welcome", "Untitled", "loading...",
    "Forbidden", "503 Service Unavailable",
    "  Publications  ",  # whitespace-trimmed
    "PAGE NOT FOUND",    # case-insensitive
])
def test_is_junk_title_catches_known_patterns(title):
    assert is_junk_title(title) is True


@pytest.mark.parametrize("title", [
    "Welcome to the Jungle (1991 film)",
    "Publications | The Bat Lab",   # rich enough to keep
    "An updated review of ketamine",
    "404: a documentary",
    "Active Inference and Intentional Behaviour",
])
def test_is_junk_title_keeps_legitimate_titles(title):
    assert is_junk_title(title) is False


def test_junk_title_reason_returns_diagnostic_string():
    assert junk_title_reason("404 Not Found") == "exact_match('404 not found')"
    assert junk_title_reason("Error 500") == "http_status('error 500')"
    assert junk_title_reason("legitimate page") is None


def test_empty_or_whitespace_title_is_junk():
    assert is_junk_title("") is True
    assert is_junk_title("   ") is True
    assert is_junk_title(None) is True  # type: ignore[arg-type]


def test_short_titles_are_kept():
    """We keep short legitimate titles (a single-letter song title,
    a short tag) — only the exact set + HTTP regex + empty case
    rejects."""
    assert is_junk_title("A") is False
    assert is_junk_title("ok") is False


# ── integration: swf.web.index_page skips junk ────────────────────


def test_index_page_skips_junk_titles(tmp_path, monkeypatch, capsys):
    """A user-fetched page whose <title> is `Publications` shouldn't
    land in `pages` and shouldn't be shipped to peers."""
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    from swf.web import index as web_index
    web_index.index_page(
        url="https://example.com/lab",
        title="Publications",
        content="navigation links and a list of papers",
        fetched_at="2026-05-04T00:00:00Z",
    )
    err = capsys.readouterr().err
    assert "skipped junk-title" in err
    # Verify nothing was actually written.
    db = tmp_path / "index.db"
    if db.exists():
        with sqlite3.connect(str(db)) as conn:
            n = conn.execute(
                "SELECT COUNT(*) FROM pages WHERE url=?",
                ("https://example.com/lab",),
            ).fetchone()[0]
            assert n == 0


def test_index_page_keeps_legitimate_titles(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path))
    from swf.web import index as web_index
    web_index.index_page(
        url="https://example.com/p",
        title="Active Inference and Intentional Behaviour",
        content="real content here",
        fetched_at="2026-05-04T00:00:00Z",
    )
    db = tmp_path / "index.db"
    assert db.exists()
    with sqlite3.connect(str(db)) as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM pages WHERE url=?",
            ("https://example.com/p",),
        ).fetchone()[0]
    assert n == 1


# ── integration: peer_scraper.ingest_bundle drops junk ────────────


def _seed(db: Path) -> None:
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE VIRTUAL TABLE pages USING fts5("
        "  url UNINDEXED, title, content, fetched_at UNINDEXED,"
        "  tokenize='porter unicode61');"
        "CREATE TABLE page_cids("
        "  url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,"
        "  computed_at TEXT NOT NULL);"
    )
    migration.ensure_schema(conn)
    conn.commit()
    conn.close()


@pytest.fixture
def indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    (tmp_path / "wk").mkdir(parents=True)
    db = tmp_path / "wk" / "index.db"
    _seed(db)
    return db


def test_ingest_bundle_drops_junk_titles_from_peer(indrex, monkeypatch):
    """A peer running old code might ship `404 Not Found` titles in
    its bundle. The consumer-side filter quietly skips them."""
    from swf.peer_scraper import VerifyResult
    monkeypatch.setattr(
        peer_scraper, "verify_bundle",
        lambda b, *, expected_pubkey: VerifyResult(
            ok=True, reason="ok",
            since=b.get("since", 0), until=b.get("until", 0),
            page_count=len(b.get("pages") or []),
            declared_root=b.get("merkle_root", ""),
            computed_root=b.get("merkle_root", ""),
        ),
    )
    pages = [
        {"url": "https://x.example/legit", "title": "Real Paper Title",
         "fetched_at": "2026-05-04T00:00:00Z"},
        {"url": "https://x.example/404", "title": "404 Not Found",
         "fetched_at": "2026-05-04T00:00:00Z"},
        {"url": "https://x.example/lab", "title": "Publications",
         "fetched_at": "2026-05-04T00:00:00Z"},
    ]
    bundle = {
        "schema": "swf.index_pages.v1",
        "pubkey": "PEER_A",
        "since": 0, "until": 3,
        "pages": pages,
        "merkle_root": peer_scraper.merkle_root(pages),
        "sig": "x" * 88,
        "epoch_id": "epoch-test",
        "page_count": len(pages),
    }
    stored = peer_scraper.ingest_bundle(indrex, bundle, source_label="alice")
    # Only the legit page survives.
    assert stored == 1
    conn = sqlite3.connect(str(indrex))
    try:
        urls = [r[0] for r in conn.execute("SELECT url FROM pages")]
    finally:
        conn.close()
    assert urls == ["https://x.example/legit"]
