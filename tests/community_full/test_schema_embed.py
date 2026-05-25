"""The embedded schema fallback in db.py must stay byte-for-byte in sync
with community_full/schema.sql. If you edit the .sql, update the
_EMBEDDED_SCHEMA string too (or vice-versa) — this test fails otherwise.

The fallback exists because PyInstaller onefile _MEI extraction
occasionally drops the bundled .sql, which used to crash-loop the daemon
at startup. The embedded copy lets the daemon boot regardless."""
import sqlite3

from swf.community_full import db


def test_embedded_schema_matches_file():
    assert db.SCHEMA_PATH.read_text() == db._EMBEDDED_SCHEMA


def test_loader_prefers_file():
    # When the file is present, the loader returns it verbatim.
    assert db._load_schema_sql() == db.SCHEMA_PATH.read_text()


def test_loader_falls_back_when_file_missing(tmp_path, monkeypatch):
    # Point SCHEMA_PATH at a nonexistent file → loader returns embedded.
    monkeypatch.setattr(db, "SCHEMA_PATH", tmp_path / "gone.sql")
    assert db._load_schema_sql() == db._EMBEDDED_SCHEMA


def test_init_works_without_schema_file(tmp_path, monkeypatch):
    # The daemon must initialize the metrics db even if the bundled .sql
    # is absent (incomplete _MEI extraction). This is the crash we fixed.
    monkeypatch.setattr(db, "SCHEMA_PATH", tmp_path / "gone.sql")
    dbfile = tmp_path / "community.db"
    db.init(dbfile)
    conn = sqlite3.connect(dbfile)
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    conn.close()
    assert "kv" in tables and "metrics_samples" in tables
