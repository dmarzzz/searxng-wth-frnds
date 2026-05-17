"""Red-team pass 5 — regression tests for the post-#43 surface.

Pins the fixes for findings 1, 2, 3, 4, 6, 7, 9, 10. Each test names
the finding it guards in its docstring so a future refactor that
reverts the fix will fail with a clear pointer."""
from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from swf import identity, peer_scraper
from swf.peer_scraper import (
    MAX_BUNDLE_CURSOR_ADVANCE,
    MAX_BUNDLE_PAGES,
    MAX_NICKNAME_LEN,
    Peer,
    build_bundle,
    ingest_bundle,
    list_peers,
    upsert_peer,
    verify_bundle,
)
from swf.search import migration

# ── helpers (mirror tests/test_peer_scraper.py) ─────────────────────

def _seed_indrex(db: Path, rows: list[tuple[str, str, str, str]],
                 share_scopes: dict[str, str] | None = None,
                 source_types: dict[str, str] | None = None) -> None:
    """rows: (url, title, content, fetched_at). share_scopes/types
    let a test mark specific URLs as 'friends'/'public'/etc — the
    default 'private' is what migration.py defaults to."""
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE VIRTUAL TABLE pages USING fts5(
            url UNINDEXED, title, content, fetched_at UNINDEXED,
            tokenize='porter unicode61'
        );
        CREATE TABLE page_cids(
            url TEXT PRIMARY KEY, content_cid TEXT NOT NULL,
            computed_at TEXT NOT NULL
        );
        """
    )
    migration.ensure_schema(conn)
    share_scopes = share_scopes or {}
    source_types = source_types or {}
    for u, t, c, f in rows:
        conn.execute(
            "INSERT INTO pages(url, title, content, fetched_at) VALUES(?,?,?,?)",
            (u, t, c, f),
        )
        # Seed the meta row if the test cares about scope/source.
        if u in share_scopes or u in source_types:
            migration.set_meta(
                conn, u,
                share_scope=share_scopes.get(u),
                source_type=source_types.get(u),
            )
    conn.commit()
    conn.close()


@pytest.fixture
def peer_indrex(tmp_path, monkeypatch):
    monkeypatch.setenv("SWF_CONFIG_DIR", str(tmp_path / "cfg"))
    monkeypatch.setenv("RA_WORLD_KNOWLEDGE_DIR", str(tmp_path / "wk"))
    (tmp_path / "wk").mkdir(parents=True)
    return tmp_path / "wk" / "index.db"


# ── #7 (CRITICAL) build_bundle never serves private rows ────────────

def test_build_bundle_omits_private_pages_by_default(peer_indrex):
    """The §13.1 default share_scope is 'private'. build_bundle MUST
    never include those rows in the response — no auth gate on
    /index/pages, so a leak is unauthenticated full-archive disclosure.
    Pass-5 finding #7."""
    _seed_indrex(peer_indrex, [
        ("https://private/1", "Diary", "secret", "2026-04-01"),
        ("https://private/2", "Notes", "private", "2026-04-02"),
    ])  # all default → private
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    assert bundle["pages"] == []
    # Cursor still advances past the unshareable window so the puller
    # doesn't re-pull forever.
    assert bundle["until"] == 2


def test_build_bundle_serves_friends_and_public(peer_indrex):
    _seed_indrex(
        peer_indrex,
        [
            ("https://private/1", "P", "x", "2026-04-01"),
            ("https://friends/2", "F", "x", "2026-04-02"),
            ("https://public/3",  "U", "x", "2026-04-03"),
        ],
        share_scopes={
            "https://private/1": "private",
            "https://friends/2": "friends",
            "https://public/3":  "public",
        },
    )
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    urls = sorted(p["url"] for p in bundle["pages"])
    assert urls == ["https://friends/2", "https://public/3"]


def test_build_bundle_omits_peer_ingest_rows(peer_indrex):
    """Chained-provenance protection: pages we pulled from peers must
    NOT be reshared to other peers via /index/pages. Mirror of the
    friend-responder's TODO-8 rule. Pass-5 finding #7."""
    _seed_indrex(
        peer_indrex,
        [("https://reshare/1", "Re", "x", "2026-04-01")],
        share_scopes={"https://reshare/1": "friends"},
        source_types={"https://reshare/1": "peer_ingest"},
    )
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    assert bundle["pages"] == []


def test_build_bundle_omits_tombstoned_rows(peer_indrex):
    _seed_indrex(
        peer_indrex,
        [("https://t/1", "T", "x", "2026-04-01")],
        share_scopes={"https://t/1": "public"},
    )
    conn = sqlite3.connect(str(peer_indrex))
    migration.set_meta(conn, "https://t/1", deleted_at_ms=1)
    conn.commit()
    conn.close()
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    assert bundle["pages"] == []


def test_cursor_advances_past_unshareable_block(peer_indrex):
    """A long run of private rows must NOT cause the puller to
    re-pull the same window forever. The bundle's `until` reflects
    the full window we considered, even when none were shareable."""
    _seed_indrex(peer_indrex, [
        (f"https://private/{i}", f"P{i}", "x", "2026-04-01")
        for i in range(50)
    ])  # all private
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100)
    assert bundle["pages"] == []
    assert bundle["until"] == 50


# ── #1 forged `until` is rejected ─────────────────────────────────

def test_verify_bundle_rejects_huge_cursor_jump(peer_indrex):
    """A peer signing `until = 2**62` over `pages = []` would otherwise
    permanently lock the puller's cursor past every future row. The
    verifier rejects per pass-5 finding #1 — bounded cursor advance."""
    ident = identity.get_or_create_identity()
    huge = MAX_BUNDLE_CURSOR_ADVANCE + 1
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100,
                          ident=ident)
    bundle["since"] = 0
    bundle["until"] = huge
    # Re-sign so the merkle/sig still validate.
    payload = peer_scraper.signing_payload(
        merkle_root_hex=bundle["merkle_root"],
        since=0, until=huge, pubkey_b64=bundle["pubkey"],
    )
    import base64
    bundle["sig"] = base64.urlsafe_b64encode(
        ident.sign(payload),
    ).rstrip(b"=").decode("ascii")
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert not v.ok
    assert v.reason == "cursor_jump_too_large"


def test_verify_bundle_accepts_legit_cursor_advance(peer_indrex):
    """The bound is generous enough that a real peer with millions of
    pages can still catch up across many round-trips. Inverse of the
    above: at the boundary we still accept."""
    ident = identity.get_or_create_identity()
    bundle = build_bundle(db_path=peer_indrex, since=0, limit=100,
                          ident=ident)
    bundle["since"] = 0
    bundle["until"] = MAX_BUNDLE_CURSOR_ADVANCE
    payload = peer_scraper.signing_payload(
        merkle_root_hex=bundle["merkle_root"],
        since=0, until=MAX_BUNDLE_CURSOR_ADVANCE,
        pubkey_b64=bundle["pubkey"],
    )
    import base64
    bundle["sig"] = base64.urlsafe_b64encode(
        ident.sign(payload),
    ).rstrip(b"=").decode("ascii")
    v = verify_bundle(bundle, expected_pubkey=bundle["pubkey"])
    assert v.ok, v.reason


# ── #3 oversized bundles rejected ─────────────────────────────────

def test_verify_bundle_rejects_too_many_pages():
    """A peer that ships 10k+ pages would burn verifier CPU. The
    server-side build_bundle caps at 5000 already; the verifier
    enforces the same bound. Pass-5 finding #3."""
    pages = [
        {"url": f"https://x/{i}", "title": f"T{i}", "host": "x",
         "topic": "", "fetched_at": "", "content_cid": ""}
        for i in range(MAX_BUNDLE_PAGES + 1)
    ]
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 0,
        "pages": pages,
        "merkle_root": peer_scraper.merkle_root(pages),
        "sig": "AAAA",
    }
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert not v.ok
    assert v.reason == "too_many_pages"


# ── #6 duplicate URLs rejected ────────────────────────────────────

def test_verify_bundle_rejects_duplicate_urls():
    """A peer can't ship the same URL repeatedly to amplify ingest
    cost. Pass-5 finding #6."""
    pages = [
        {"url": "https://dup/1", "title": "A", "host": "dup",
         "topic": "", "fetched_at": "", "content_cid": ""},
        {"url": "https://dup/1", "title": "B", "host": "dup",
         "topic": "", "fetched_at": "", "content_cid": ""},
    ]
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 0,
        "pages": pages,
        "merkle_root": peer_scraper.merkle_root(pages),
        "sig": "AAAA",
    }
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert not v.ok
    assert v.reason == "duplicate_url"


def test_verify_bundle_rejects_non_dict_page_entry():
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 0,
        "pages": ["not-a-dict"],
        "merkle_root": "", "sig": "AAAA",
    }
    v = verify_bundle(bundle, expected_pubkey="pk")
    assert not v.ok
    assert v.reason == "page_not_a_dict"


# ── #2 SSRF: scheme + redirect guards ─────────────────────────────

def test_http_get_json_rejects_non_http_schemes():
    """`file://` and `ftp://` would otherwise let a malicious peers.yaml
    leak local files. Pass-5 finding #2."""
    assert peer_scraper._http_get_json("file:///etc/passwd") is None
    assert peer_scraper._http_get_json("ftp://example.com/x") is None


def test_no_redirect_handler_blocks_30x():
    """Custom HTTPRedirectHandler refuses 301/302/303/307/308.
    Confirms the SSRF guard short-circuits before the redirect target
    fires. Pass-5 finding #2."""
    import io
    import urllib.error
    import urllib.request
    handler = peer_scraper._NoRedirectHandler()
    req = urllib.request.Request("http://attacker.example/")
    headers = {"Location": "http://169.254.169.254/latest/"}
    fp = io.BytesIO(b"")
    for code in (301, 302, 303, 307, 308):
        with pytest.raises(urllib.error.HTTPError):
            getattr(handler, f"http_error_{code}")(
                req, fp, code, "moved", headers,
            )


# ── #4 peer-controlled string sanitization ────────────────────────

def test_upsert_peer_rejects_malformed_color(peer_indrex):
    """A color like `red; background:url(javascript:...)` would XSS
    the wall if rendered into an HTML style attribute. The `peers`
    table normalizes anything not matching `#RRGGBB` to empty.
    Pass-5 finding #4."""
    _seed_indrex(peer_indrex, [])
    upsert_peer(peer_indrex, pubkey="pk1",
                signature_color="red; background:url(javascript:alert(1))")
    # The color was rejected → stored empty (the consumer falls back
    # to a deterministic stable_hue).
    conn = sqlite3.connect(str(peer_indrex))
    color = conn.execute(
        "SELECT signature_color FROM peers WHERE pubkey=?", ("pk1",),
    ).fetchone()[0]
    conn.close()
    assert color == ""


def test_upsert_peer_caps_nickname_length(peer_indrex):
    _seed_indrex(peer_indrex, [])
    upsert_peer(peer_indrex, pubkey="pk1",
                nickname="A" * (MAX_NICKNAME_LEN + 100))
    rows = list_peers(peer_indrex)
    assert len(rows[0].nickname) == MAX_NICKNAME_LEN


def test_ingest_bundle_caps_source_label(peer_indrex):
    """A peer-supplied label that flows into pages_meta is bounded.
    Pass-5 finding #4."""
    _seed_indrex(peer_indrex, [])
    bundle = {
        "schema": peer_scraper.BUNDLE_SCHEMA,
        "pubkey": "pk", "since": 0, "until": 1,
        "pages": [{"url": "https://a/1", "title": "T", "host": "a",
                   "topic": "", "fetched_at": "", "content_cid": ""}],
        "merkle_root": "x", "sig": "y",
    }
    peer_scraper.ingest_bundle(
        peer_indrex, bundle, source_label="A" * 1000,
    )
    conn = sqlite3.connect(str(peer_indrex))
    label = conn.execute(
        "SELECT source_label FROM pages_meta WHERE url=?",
        ("https://a/1",),
    ).fetchone()[0]
    conn.close()
    assert len(label) <= peer_scraper.MAX_SOURCE_LABEL_LEN


# ── #9 peer-ingest cannot overwrite user_fetched attribution ──────

def test_set_meta_peer_ingest_does_not_overwrite_user_fetched(peer_indrex):
    """A scraper race must NEVER flip a self-fetched URL's source_type
    to peer_ingest — that would leak it through the friend-responder
    filter. Pass-5 finding #9."""
    _seed_indrex(peer_indrex, [])
    conn = sqlite3.connect(str(peer_indrex))
    migration.set_meta(
        conn, "https://x/1", source_type="user_fetched",
        share_scope="public",
    )
    conn.commit()
    # Now simulate ingest_bundle racing in with peer_ingest attribution.
    migration.set_meta(
        conn, "https://x/1", source_type="peer_ingest",
        source_pubkey="pk_attacker", source_label="attacker",
    )
    conn.commit()
    row = conn.execute(
        "SELECT source_type, source_pubkey, source_label "
        "FROM pages_meta WHERE url=?", ("https://x/1",),
    ).fetchone()
    conn.close()
    # Untouched: source_type stayed user_fetched, no attacker leak.
    assert row[0] == "user_fetched"
    assert row[1] is None
    assert row[2] is None


# ── #10 discovery cache concurrent access ─────────────────────────

def test_resolve_peer_url_concurrent_access(monkeypatch):
    """Concurrent threads calling _resolve_peer_url MUST never see a
    half-rebuilt cache. Pass-5 finding #10 (latent today; trivial to
    harden)."""
    # Force a cache miss so the rebuild path runs.
    peer_scraper._discovery_cache.clear()
    peer_scraper._discovery_cache_ts = 0.0

    class _DP:
        def __init__(self, pk, url):
            self.pubkey = pk
            self.url = url

    def _slow_discover():
        # Simulate a slow mDNS browse.
        import time as _t
        _t.sleep(0.05)
        return [_DP(f"pk{i}", f"http://h{i}:7777") for i in range(5)]

    import swf.discovery
    monkeypatch.setattr(swf.discovery, "discover_all_peers", _slow_discover)

    results = []
    barrier = threading.Barrier(8)

    def _worker(i):
        barrier.wait()
        url = peer_scraper._resolve_peer_url(
            Peer(pubkey=f"pk{i % 5}", nickname="", last_seen_at=None,
                 last_pull_cursor=0, trust_level="known"),
        )
        results.append(url)

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Every thread should get the EXPECTED URL or empty (if the
    # rebuild hadn't completed). Crucially: no thread sees a
    # half-rebuilt cache where pubkey lookup would return stale-mixed-
    # with-fresh data. With the lock, every successful lookup is
    # atomic w.r.t. the rebuild.
    assert len(results) == 8
    for r in results:
        assert r == "" or r.startswith("http://h")


# ── #5 PRAGMA journal_mode hoisted into ensure_schema ──────────────

def test_ensure_schema_sets_wal_once(tmp_path):
    """Pass-5 #5: WAL is set during the first ensure_schema call so
    event_bus._connect doesn't re-issue the PRAGMA per emit. Verify
    the migration actually flips the journal mode on a fresh DB."""
    db = tmp_path / "fresh.db"
    conn = sqlite3.connect(str(db))
    migration.ensure_schema(conn)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0].lower()
    conn.close()
    assert mode == "wal"


# ── #8 explicit _real_issuer_registered / _real_provider_registered ─

def test_ticket_flow_real_issuer_flag_tracks_registration(
    monkeypatch, tmp_path,
):
    """Pass-5 #8: the no-crypto guard now reads
    `_real_issuer_registered` (set by `set_issuer`) instead of
    `isinstance(_, _NullIssuer)`. The flag is True iff the registered
    issuer is NOT a `_NullIssuer` (or subclass) — a subclass of null
    is still null by contract. A genuinely separate real issuer
    flips the flag."""
    monkeypatch.setenv("SWF_ENABLE_TICKETS", "1")
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "t.db"))
    from swf.search import ticket_flow
    from swf.search.ticket_flow import (
        _NullIssuer,
        issue_query_tickets,
        reset_issuer,
        set_issuer,
    )

    reset_issuer()
    assert ticket_flow._real_issuer_registered is False

    class _SubclassNull(_NullIssuer):
        name = "subclass-of-null"

    set_issuer(_SubclassNull())
    # Subclass of null → still treated as null. The contract opt-out
    # is "don't inherit from _NullIssuer" — explicit, conservative.
    assert ticket_flow._real_issuer_registered is False

    class _RealIssuer:
        name = "real"
        def issuer_key(self, **kw):
            from swf.search.tickets import IssuerKey
            return IssuerKey(
                issuer_key_id="r", circle_id=kw["circle_id"],
                epoch_id=kw["epoch_id"], pubkey_bytes=b"R" * 32,
                valid_from_ms=0, valid_until_ms=10**14,
            )
        def issue(self, req):
            from swf.search.ticket_flow import IssueResponse
            return IssueResponse(
                issuer_key_id="r",
                signed_blinds=tuple(b + b"<sig>" for b in req.blinded_tokens),
            )
    set_issuer(_RealIssuer())
    assert ticket_flow._real_issuer_registered is True
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=3,
    )
    assert (n, status) == (3, "ok")

    reset_issuer()
    assert ticket_flow._real_issuer_registered is False
    n, status = issue_query_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=3,
    )
    assert (n, status) == (0, "no_crypto")


def test_receipts_isinstance_subclass_safe(monkeypatch, tmp_path):
    monkeypatch.setenv("SWF_ENABLE_RECEIPTS", "1")
    monkeypatch.setenv("SWF_TICKETS_DB", str(tmp_path / "t.db"))
    from swf.search import receipts
    from swf.search.receipts import (
        _NullReceiptProvider,
        mint_receipt_tickets,
        reset_provider,
        set_provider,
    )
    reset_provider()
    assert receipts._real_provider_registered is False

    class _SubclassProvider(_NullReceiptProvider):
        name = "subclass-of-null-receipt"

    set_provider(_SubclassProvider())
    # set_provider sees it's not a _NullReceiptProvider instance via
    # isinstance — wait, it IS via isinstance because of the
    # subclass. The flag therefore stays False. That's correct: a
    # subclass of _NullReceiptProvider is still a null provider by
    # contract. Going the other way (a real provider that doesn't
    # subclass null) the flag becomes True.
    assert receipts._real_provider_registered is False
    n, status = mint_receipt_tickets(
        peer_pubkey_b64="pk", circle_id="c", epoch_id="e", count=3,
    )
    assert status == "no_crypto"

    reset_provider()
    # A real provider that doesn't subclass null:
    class _RealProvider:
        name = "real"
        def issuer_key(self, **kw):
            from swf.search.tickets import IssuerKey
            return IssuerKey(
                issuer_key_id="r", circle_id=kw["circle_id"],
                epoch_id=kw["epoch_id"], pubkey_bytes=b"R" * 32,
                valid_from_ms=0, valid_until_ms=10**14,
            )
        def issue(self, **kw):
            from swf.search.receipts import IssueReceiptResponse
            return IssueReceiptResponse(
                issuer_key_id="r",
                signed_blinds=tuple(b + b"<sig>" for b in kw["blinded_tokens"]),
            )
    set_provider(_RealProvider())
    assert receipts._real_provider_registered is True
