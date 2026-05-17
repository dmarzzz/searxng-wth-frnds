"""Storage tests for the bundles SQLite table."""
from __future__ import annotations

import sqlite3

import pytest

from swf.bundles import (
    cid_for,
    ensure_schema,
    get_by_cid,
    insert,
    latest_version,
    list_,
)


@pytest.fixture
def isolated_indrex(tmp_path, monkeypatch):
    """Point swf.indrex.db_path() at a tmp dir for the duration of
    the test. Lets `insert(envelope)` open its own connection without
    leaking state across tests.

    Returns the path to the indrex DB."""
    monkeypatch.setenv("SWF_KNOWLEDGE_DIR", str(tmp_path))
    # SWF_KNOWLEDGE_DIR -> <dir>/index.db per swf.indrex.db_path
    return tmp_path / "index.db"


@pytest.fixture
def conn(isolated_indrex):
    c = sqlite3.connect(str(isolated_indrex))
    c.row_factory = sqlite3.Row
    ensure_schema(c)
    yield c
    c.close()


class TestEnsureSchema:
    def test_idempotent(self, conn):
        # Calling twice must not error.
        ensure_schema(conn)
        ensure_schema(conn)

    def test_creates_table_and_indexes(self, conn):
        rows = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','index') AND name LIKE 'bundles%' "
            "OR name LIKE 'idx_bundles%'"
        ).fetchall()
        names = {r["name"] for r in rows}
        assert "bundles" in names
        assert "idx_bundles_kind_record_version" in names
        assert "idx_bundles_kind_signed_at" in names


class TestInsert:
    def test_insert_returns_was_new_first_time(
        self, isolated_indrex, make_envelope,
    ):
        env = make_envelope()
        cid, was_new = insert(env)
        assert was_new
        assert cid == cid_for(env)

    def test_insert_idempotent_on_same_envelope(
        self, isolated_indrex, make_envelope,
    ):
        env = make_envelope()
        cid1, new1 = insert(env)
        cid2, new2 = insert(env)
        assert cid1 == cid2
        assert new1 is True
        assert new2 is False

    def test_insert_with_caller_supplied_conn(self, conn, make_envelope):
        env = make_envelope()
        cid, was_new = insert(env, conn=conn)
        # Caller owns the commit when conn is passed in — make sure
        # the row is visible after we commit explicitly.
        conn.commit()
        assert was_new
        row = conn.execute(
            "SELECT cid, kind, record_id, version FROM bundles WHERE cid=?",
            (cid,),
        ).fetchone()
        assert row is not None
        assert row["kind"] == "cohort.surface"
        assert row["record_id"] == "alice"
        assert row["version"] == 0


class TestGetByCid:
    def test_round_trip(self, conn, make_envelope):
        env = make_envelope(record_id="bob", version=3)
        cid, _ = insert(env, conn=conn)
        conn.commit()
        loaded = get_by_cid(conn, cid)
        assert loaded is not None
        # Round-trip preserves every field. (We stored the canonical
        # form, so key order may differ from the original — compare
        # by content not by serialized text.)
        assert loaded["kind"] == env["kind"]
        assert loaded["record_id"] == env["record_id"]
        assert loaded["version"] == env["version"]
        assert loaded["author"]["pubkey"] == env["author"]["pubkey"]
        assert loaded["payload"] == env["payload"]
        assert loaded["signature"] == env["signature"]

    def test_unknown_cid_returns_none(self, conn):
        assert get_by_cid(conn, "f" * 64) is None

    def test_empty_cid_returns_none(self, conn):
        assert get_by_cid(conn, "") is None


class TestList:
    def _seed(self, conn, make_envelope, n: int = 3, *, kind="cohort.surface",
              record_id="alice"):
        for i in range(n):
            env = make_envelope(kind=kind, record_id=record_id, version=i)
            insert(env, conn=conn)
        conn.commit()

    def test_filter_by_kind(self, conn, make_envelope):
        self._seed(conn, make_envelope, n=2, kind="cohort.surface",
                   record_id="alice")
        self._seed(conn, make_envelope, n=2, kind="cohort.depth",
                   record_id="alice-depth")
        all_kinds = list_(conn)
        assert len(all_kinds) == 4
        only_surface = list_(conn, kind="cohort.surface")
        assert len(only_surface) == 2
        assert all(b["kind"] == "cohort.surface" for b in only_surface)

    def test_filter_by_record_id(self, conn, make_envelope):
        self._seed(conn, make_envelope, n=3, record_id="alice")
        self._seed(conn, make_envelope, n=2, record_id="bob")
        alices = list_(conn, kind="cohort.surface", record_id="alice")
        assert len(alices) == 3
        assert all(b["record_id"] == "alice" for b in alices)

    def test_record_id_results_are_version_desc(self, conn, make_envelope):
        self._seed(conn, make_envelope, n=4, record_id="alice")
        rows = list_(conn, kind="cohort.surface", record_id="alice")
        versions = [r["version"] for r in rows]
        assert versions == sorted(versions, reverse=True)

    def test_since_version_filter(self, conn, make_envelope):
        self._seed(conn, make_envelope, n=5, record_id="alice")
        rows = list_(conn, kind="cohort.surface", record_id="alice",
                     since_version=2)
        # Strict greater-than per docstring, so we get versions 3 & 4.
        versions = sorted(r["version"] for r in rows)
        assert versions == [3, 4]

    def test_limit(self, conn, make_envelope):
        self._seed(conn, make_envelope, n=10, record_id="alice")
        rows = list_(conn, kind="cohort.surface", record_id="alice", limit=3)
        assert len(rows) == 3

    def test_empty_db_returns_empty_list(self, conn):
        assert list_(conn) == []


class TestLatestVersion:
    def test_unknown_record_returns_none(self, conn):
        assert latest_version(conn, kind="cohort.surface", record_id="ghost") is None

    def test_returns_max_version(self, conn, make_envelope):
        for v in (0, 5, 2, 7, 3):
            insert(make_envelope(version=v, record_id="alice"), conn=conn)
        conn.commit()
        assert latest_version(conn, kind="cohort.surface", record_id="alice") == 7

    def test_scoped_per_record_id(self, conn, make_envelope):
        insert(make_envelope(version=10, record_id="alice"), conn=conn)
        insert(make_envelope(version=2, record_id="bob"), conn=conn)
        conn.commit()
        assert latest_version(conn, kind="cohort.surface", record_id="alice") == 10
        assert latest_version(conn, kind="cohort.surface", record_id="bob") == 2
