"""Encryption-key-reservoir loader tests (#93 phase 7)."""
from __future__ import annotations

import textwrap

import pytest

from swf.bundles import Reservoir, ReservoirEntry, load_reservoir


@pytest.fixture
def make_yaml(tmp_path):
    """Write a YAML file under tmp_path and return the resulting path."""

    def _write(name: str, body: str):
        p = tmp_path / name
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    return _write


# A small but realistic stand-in for the 20-key reservoir. We don't
# need real X25519 bech32 keys here — the loader only checks the
# `age1` prefix and string-shape.
_K1 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0001"
_K2 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0002"
_K3 = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0003"


class TestLoadReservoir:
    def test_parses_well_formed_file(self, make_yaml):
        path = make_yaml(
            ".reservoir.yml",
            f"""
            schema_version: 1
            generated_at: "2026-05-07T10:00:00Z"
            keys:
              - id: alc-001
                pubkey: "{_K1}"
                distributed_to: "Andrew"
              - id: alc-002
                pubkey: "{_K2}"
                distributed_to: "Tina"
              - id: alc-003
                pubkey: "{_K3}"
                distributed_to: null
            """,
        )
        res = load_reservoir(path)
        assert isinstance(res, Reservoir)
        assert len(res) == 3
        assert res.path == path
        assert res.schema_version == 1
        assert res.generated_at == "2026-05-07T10:00:00Z"
        assert res.pubkeys() == [_K1, _K2, _K3]
        # Distributed metadata is parsed but does NOT affect membership.
        assert res.is_recipient(_K1)
        assert res.is_recipient(_K3)
        assert not res.is_recipient("age1notinreservoir")
        # Entry shape.
        first = res.keys[0]
        assert isinstance(first, ReservoirEntry)
        assert first.id == "alc-001"
        assert first.distributed_to == "Andrew"
        assert res.keys[2].distributed_to is None
        # Truthiness mirrors emptiness.
        assert bool(res)

    def test_missing_file_returns_empty_with_warning(
        self, tmp_path, capsys, monkeypatch,
    ):
        monkeypatch.delenv("SWF_RESERVOIR_FILE", raising=False)
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        ghost = tmp_path / "does-not-exist.yml"
        res = load_reservoir(ghost)
        captured = capsys.readouterr()
        assert len(res) == 0
        assert res.path is None
        assert res.pubkeys() == []
        assert "no reservoir.yml found" in captured.err
        assert "encrypted bundles cannot be produced" in captured.err
        assert not bool(res)

    def test_env_override(self, make_yaml, monkeypatch):
        path = make_yaml(
            "from-env.yml",
            f"""
            schema_version: 1
            keys:
              - id: env-key
                pubkey: "{_K1}"
                distributed_to: "Env"
            """,
        )
        monkeypatch.setenv("SWF_RESERVOIR_FILE", str(path))
        res = load_reservoir()
        assert res.path == path
        assert res.is_recipient(_K1)

    def test_swf_config_dir_lookup(self, tmp_path, monkeypatch):
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        (cfg / ".reservoir.yml").write_text(
            'schema_version: 1\n'
            'keys:\n'
            f'  - id: cfg-key\n    pubkey: "{_K1}"\n'
            '    distributed_to: null\n',
            encoding="utf-8",
        )
        monkeypatch.delenv("SWF_RESERVOIR_FILE", raising=False)
        monkeypatch.setenv("SWF_CONFIG_DIR", str(cfg))
        res = load_reservoir()
        assert res.is_recipient(_K1)

    def test_malformed_yaml_returns_empty(
        self, make_yaml, capsys, monkeypatch,
    ):
        monkeypatch.delenv("SWF_RESERVOIR_FILE", raising=False)
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        path = make_yaml("bad.yml", "this: is: not: valid: yaml: [\n")
        res = load_reservoir(path)
        captured = capsys.readouterr()
        assert len(res) == 0
        assert res.path == path
        assert "failed to read" in captured.err

    def test_non_dict_top_level(self, make_yaml, capsys):
        path = make_yaml("bad-top.yml", "- just\n- a\n- list\n")
        res = load_reservoir(path)
        captured = capsys.readouterr()
        assert len(res) == 0
        assert "expected top-level mapping" in captured.err

    def test_malformed_entries_skipped_with_warning(self, make_yaml, capsys):
        path = make_yaml(
            "messy.yml",
            f"""
            schema_version: 1
            keys:
              - id: ok
                pubkey: "{_K1}"
                distributed_to: "Andrew"
              - id: nopubkey
              - "not a mapping"
              - id: badprefix
                pubkey: "ed25519:notanage"
              - id: dup
                pubkey: "{_K1}"
            """,
        )
        res = load_reservoir(path)
        captured = capsys.readouterr()
        # Only the first valid entry survives — the 'dup' one is
        # skipped because its pubkey is already registered.
        assert len(res) == 1
        assert res.is_recipient(_K1)
        # Warnings emitted for the broken entries.
        assert "skipped" in captured.err

    def test_schema_version_mismatch_logs_warning_but_keeps_keys(
        self, make_yaml, capsys,
    ):
        path = make_yaml(
            "future.yml",
            f"""
            schema_version: 999
            keys:
              - id: alc-001
                pubkey: "{_K1}"
                distributed_to: "Andrew"
            """,
        )
        res = load_reservoir(path)
        captured = capsys.readouterr()
        # Forward-compat: warning logged, but the keys we can parse
        # are kept.
        assert len(res) == 1
        assert "schema_version" in captured.err
        # The Reservoir reflects what we read, not what we expected.
        assert res.schema_version == 999

    def test_missing_keys_field_returns_empty(self, make_yaml, capsys):
        path = make_yaml(
            "no-keys.yml",
            """
            schema_version: 1
            generated_at: "2026-05-07T..."
            """,
        )
        res = load_reservoir(path)
        captured = capsys.readouterr()
        assert len(res) == 0
        assert "missing or non-list 'keys'" in captured.err

    def test_pubkeys_is_in_file_order(self, make_yaml):
        """pubkeys() must preserve file order so encrypt-to-all is
        deterministic across reloads (matters for cid stability when
        a producer re-emits the same bundle)."""
        path = make_yaml(
            ".reservoir.yml",
            f"""
            schema_version: 1
            keys:
              - id: alc-002
                pubkey: "{_K2}"
                distributed_to: "Tina"
              - id: alc-001
                pubkey: "{_K1}"
                distributed_to: "Andrew"
              - id: alc-003
                pubkey: "{_K3}"
                distributed_to: null
            """,
        )
        res = load_reservoir(path)
        assert res.pubkeys() == [_K2, _K1, _K3]


# ── #109: lazy-restat hot-reload (mirror of alchemists hot-reload) ────


import os as _os  # noqa: E402

from swf.bundles.reservoir import (  # noqa: E402
    load_reservoir_cached,
    reset_reservoir_cache_for_tests,
)


def _bump_mtime(path) -> None:
    """Advance `path`'s `st_mtime` past the loader's cached value, so
    same-second-resolution filesystems don't mask reload bugs."""
    st = path.stat()
    new = st.st_mtime + 5.0
    _os.utime(path, (new, new))


class TestReservoirHotReload:
    """#109: `load_reservoir_cached()` re-stats the captured file path
    on every call and re-parses if `st_mtime_ns` advanced.

    Same lazy approach as the alchemist cache — operators hit the
    same problem with `.reservoir.yml` (regenerate the 20-key
    reservoir, the daemon serves the stale cache until restart),
    so we apply the identical fix on the reservoir side.
    """

    def test_advancing_mtime_triggers_reload(
        self, tmp_path, monkeypatch, capsys,
    ):
        path = tmp_path / ".reservoir.yml"
        path.write_text(
            'schema_version: 1\n'
            'keys:\n'
            f'  - id: alc-001\n    pubkey: "{_K1}"\n'
            '    distributed_to: null\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_RESERVOIR_FILE", str(path))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_reservoir_cache_for_tests()

        first = load_reservoir_cached()
        assert len(first) == 1

        # No edit -> same object.
        assert load_reservoir_cached() is first

        # Add a second key + bump mtime.
        path.write_text(
            'schema_version: 1\n'
            'keys:\n'
            f'  - id: alc-001\n    pubkey: "{_K1}"\n'
            '    distributed_to: null\n'
            f'  - id: alc-002\n    pubkey: "{_K2}"\n'
            '    distributed_to: null\n',
            encoding="utf-8",
        )
        _bump_mtime(path)
        capsys.readouterr()

        fresh = load_reservoir_cached()
        captured = capsys.readouterr()
        assert fresh is not first
        assert len(fresh) == 2
        assert fresh.is_recipient(_K2)
        assert "reservoir.yml reloaded" in captured.err
        assert "1 -> 2 keys" in captured.err

    def test_disappeared_file_serves_cached_with_warning(
        self, tmp_path, monkeypatch, capsys,
    ):
        path = tmp_path / ".reservoir.yml"
        path.write_text(
            'schema_version: 1\n'
            'keys:\n'
            f'  - id: alc-001\n    pubkey: "{_K1}"\n'
            '    distributed_to: null\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_RESERVOIR_FILE", str(path))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_reservoir_cache_for_tests()

        first = load_reservoir_cached()
        assert len(first) == 1

        path.unlink()
        capsys.readouterr()

        served = load_reservoir_cached()
        captured = capsys.readouterr()
        # Same object — we kept the previous parse.
        assert served is first
        assert "reservoir.yml stat failed" in captured.err
        assert "serving cached reservoir" in captured.err

    def test_load_stamps_mtime(self, tmp_path, monkeypatch):
        """`load_reservoir` populates `mtime_ns` so the cache
        hot-reload check has a baseline to compare against."""
        path = tmp_path / ".reservoir.yml"
        path.write_text(
            'schema_version: 1\n'
            'keys:\n'
            f'  - id: alc-001\n    pubkey: "{_K1}"\n'
            '    distributed_to: null\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_RESERVOIR_FILE", str(path))
        res = load_reservoir(path)
        assert res.mtime_ns > 0
        assert res.mtime_ns == path.stat().st_mtime_ns
