"""Alchemist-list loader tests."""
from __future__ import annotations

import os
import textwrap

import pytest

from swf.bundles import is_alchemist_pubkey, load_alchemists
from swf.bundles.alchemists import (
    AlchemistList,
    load_alchemists_cached,
    reset_alchemists_cache_for_tests,
)


@pytest.fixture
def make_yaml(tmp_path):
    """Write a YAML file under tmp_path and return the resulting path."""

    def _write(name: str, body: str):
        p = tmp_path / name
        p.write_text(textwrap.dedent(body), encoding="utf-8")
        return p

    return _write


class TestLoadAlchemists:
    def test_parses_well_formed_file(self, make_yaml):
        path = make_yaml(
            ".alchemists.yml",
            """
            schema_version: 1
            alchemists:
              - id: andrew
                pubkey: "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              - id: tina
                pubkey: "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            """,
        )
        al = load_alchemists(path)
        assert len(al) == 2
        assert al.is_alchemist_pubkey(
            "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        assert al.is_alchemist_pubkey(
            "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        )
        assert al.path == path

    def test_unknown_pubkey_not_listed(self, make_yaml):
        path = make_yaml(
            "a.yml",
            """
            schema_version: 1
            alchemists:
              - id: andrew
                pubkey: "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            """,
        )
        al = load_alchemists(path)
        assert not al.is_alchemist_pubkey(
            "ed25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        )

    def test_missing_file_returns_empty_with_warning(
        self, tmp_path, capsys, monkeypatch,
    ):
        # Steer the loader at an explicit path that doesn't exist.
        # Also clear env vars so default lookup doesn't surprise us.
        monkeypatch.delenv("SWF_ALCHEMISTS_FILE", raising=False)
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        ghost = tmp_path / "does-not-exist.yml"
        al = load_alchemists(ghost)
        captured = capsys.readouterr()
        assert len(al) == 0
        assert al.path is None
        assert "no alchemists.yml found" in captured.err
        assert "all signed bundles will be rejected" in captured.err
        # AlchemistList truthiness mirrors emptiness.
        assert not bool(al)

    def test_env_override(self, make_yaml, monkeypatch):
        path = make_yaml(
            "from-env.yml",
            """
            schema_version: 1
            alchemists:
              - id: env-alc
                pubkey: "ed25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            """,
        )
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(path))
        al = load_alchemists()
        assert al.path == path
        assert al.is_alchemist_pubkey(
            "ed25519:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        )

    def test_swf_config_dir_lookup(self, tmp_path, make_yaml, monkeypatch):
        # Simulate SWF_CONFIG_DIR pointing at a directory containing
        # `.alchemists.yml`. The loader should pick it up without an
        # explicit path.
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        (cfg / ".alchemists.yml").write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: cfg-alc\n'
            '    pubkey: "ed25519:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"\n',
            encoding="utf-8",
        )
        monkeypatch.delenv("SWF_ALCHEMISTS_FILE", raising=False)
        monkeypatch.setenv("SWF_CONFIG_DIR", str(cfg))
        al = load_alchemists()
        assert al.is_alchemist_pubkey(
            "ed25519:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        )

    def test_malformed_entries_skipped_with_warning(self, make_yaml, capsys):
        path = make_yaml(
            "bad.yml",
            """
            schema_version: 1
            alchemists:
              - id: ok
                pubkey: "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
              - id: nopubkey
              - "not a mapping"
              - id: badprefix
                pubkey: "x25519:1234"
            """,
        )
        al = load_alchemists(path)
        captured = capsys.readouterr()
        # Only the valid entry survives.
        assert len(al) == 1
        assert al.is_alchemist_pubkey(
            "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        # Warnings emitted for the broken entries.
        assert "skipped" in captured.err

    def test_module_level_helper(self):
        al = AlchemistList(members={"ed25519:aa": "andrew"}, path=None)
        assert is_alchemist_pubkey("ed25519:aa", al)
        assert not is_alchemist_pubkey("ed25519:bb", al)

    def test_non_dict_top_level(self, make_yaml, capsys):
        path = make_yaml("bad-top.yml", "- just\n- a\n- list\n")
        al = load_alchemists(path)
        captured = capsys.readouterr()
        assert len(al) == 0
        assert "expected top-level mapping" in captured.err


def test_alchemist_cache_is_shared_across_subsystems(make_yaml, monkeypatch):
    """Regression: every bundle ingest channel reads from a single
    process-wide `AlchemistList` cache.

    This pins the lift performed in the alchemist-cache unify pass
    (mirror of #105's reservoir lift). Before the lift, peer_server,
    the puller, and the hivemind route each kept their own
    `_ALCHEMISTS_CACHE` dict — three caches, three reset hooks, three
    chances for an operator's `.alchemists.yml` to read inconsistently
    across subsystems. After the lift, all three call sites delegate
    to `swf.bundles.alchemists`, and this test asserts:

      1. The first load via `load_alchemists_cached()` parses the file.
      2. After `reset_alchemists_cache_for_tests()` drops the cache,
         the next load re-parses (proving the reset hook works).
      3. The puller's wrapper, the peer_server's wrapper, and the
         hivemind route all return the SAME object instance — i.e.
         they share the cache, not just the file path.
    """
    # Stage one alchemist and point the loader at it.
    yaml_path = make_yaml(
        ".alchemists.yml",
        """
        schema_version: 1
        alchemists:
          - id: shared-cache-test
            pubkey: "ed25519:1111111111111111111111111111111111111111111111111111111111111111"
        """,
    )
    monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(yaml_path))
    monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)

    # Start clean.
    reset_alchemists_cache_for_tests()

    # 1. First load via the canonical cache: should see N=1 entries.
    first = load_alchemists_cached()
    assert len(first) == 1
    assert first.is_alchemist_pubkey(
        "ed25519:1111111111111111111111111111111111111111111111111111111111111111",
    )

    # Subsequent calls return the same object (cache hit, not a re-parse).
    again = load_alchemists_cached()
    assert again is first

    # 2. Reset drops the cache; the next load re-parses (fresh object,
    #    same N entries).
    reset_alchemists_cache_for_tests()
    second = load_alchemists_cached()
    assert len(second) == 1
    assert second is not first  # fresh parse after reset

    # 3. All three call sites read from the same cache object. We grab
    #    the AlchemistList through each wrapper and assert pointer
    #    equality — anything else (a re-parse, a stale separate cache)
    #    would create a different object. The route module imports the
    #    shared `load_alchemists_cached` lazily inside its handler
    #    (`_build_sink_config_lazy`), so we exercise that exact import
    #    path here rather than reaching into a private global.
    from swf.bundles import (
        load_alchemists_cached as _bundles_pkg_export,
    )
    from swf.bundles import puller as _puller
    from swf.peer_server import _load_alchemists_cached as _peer_server_wrapper

    via_module = _bundles_pkg_export()
    via_puller = _puller._load_alchemists_cached()
    via_peer_server = _peer_server_wrapper()
    # Mirror the lazy-import the hivemind route uses inside
    # `_build_sink_config_lazy`. Same import shape, same cache.
    from swf.bundles import load_alchemists_cached as _route_lazy_import
    via_route = _route_lazy_import()

    # All four call sites return the same in-process AlchemistList.
    # If any wrapper kept its own cache, this would fail with
    # `assert <obj-A> is <obj-B>` mismatching identities.
    assert via_module is second
    assert via_puller is second
    assert via_peer_server is second
    assert via_route is second


# ── #109: lazy-restat hot-reload ─────────────────────────────────────


def _bump_mtime(path) -> None:
    """Advance `path`'s `st_mtime_ns` past the loader's cached value.

    Filesystems with second-grained mtime (some HFS+, some FUSE
    mounts) can collapse a same-second rewrite into the same
    `st_mtime_ns`, which would mask hot-reload bugs. We `os.utime`
    to a deterministic future time to make the assertion sharp
    regardless of FS resolution.
    """
    st = path.stat()
    new = st.st_mtime + 5.0
    os.utime(path, (new, new))


class TestAlchemistsHotReload:
    """#109: `load_alchemists_cached()` re-stats the captured file
    path on every call and re-parses if `st_mtime_ns` advanced.

    The lazy approach (no inotify, no extra thread) is the user's
    "cheaper, simpler" preference from the issue — see the docstring
    on `load_alchemists_cached`.
    """

    def test_advancing_mtime_triggers_reload(
        self, tmp_path, monkeypatch, capsys,
    ):
        """Write yaml; load; bump mtime + add a key; load again;
        assert new content."""
        path = tmp_path / ".alchemists.yml"
        path.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: alc-0\n'
            '    pubkey: "ed25519:' + "0" * 64 + '"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(path))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_alchemists_cache_for_tests()

        first = load_alchemists_cached()
        assert len(first) == 1

        # Same call, no edit -> same cache object (no re-parse).
        same = load_alchemists_cached()
        assert same is first

        # Add a second key + bump mtime.
        path.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: alc-0\n'
            '    pubkey: "ed25519:' + "0" * 64 + '"\n'
            '  - id: alc-1\n'
            '    pubkey: "ed25519:' + "1" * 64 + '"\n',
            encoding="utf-8",
        )
        _bump_mtime(path)

        # Drain captured stderr up to here so we can assert on the
        # reload log line specifically.
        capsys.readouterr()

        fresh = load_alchemists_cached()
        captured = capsys.readouterr()

        # New AlchemistList object; new key visible.
        assert fresh is not first
        assert len(fresh) == 2
        assert fresh.is_alchemist_pubkey("ed25519:" + "1" * 64)
        # Operator log: roster reload counted.
        assert "alchemists.yml reloaded" in captured.err
        assert "1 -> 2 entries" in captured.err

        # And subsequent calls return the new fresh object until the
        # next mtime bump.
        assert load_alchemists_cached() is fresh

    def test_same_mtime_returns_cached_no_reparse(
        self, tmp_path, monkeypatch,
    ):
        """If mtime hasn't advanced, the cache returns the same object
        (the stat is cheap, but a re-parse would be wasteful)."""
        path = tmp_path / ".alchemists.yml"
        path.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: alc-0\n'
            '    pubkey: "ed25519:' + "0" * 64 + '"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(path))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_alchemists_cache_for_tests()

        a = load_alchemists_cached()
        b = load_alchemists_cached()
        c = load_alchemists_cached()
        # No edit -> same object, no re-parse cost.
        assert a is b is c

    def test_disappeared_file_serves_cached_with_warning(
        self, tmp_path, monkeypatch, capsys,
    ):
        """If the file vanishes between calls (deleted, broken
        symlink), we keep serving the previous cache instead of
        crashing — and log a one-line stderr warning so the operator
        notices."""
        path = tmp_path / ".alchemists.yml"
        path.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: alc-0\n'
            '    pubkey: "ed25519:' + "0" * 64 + '"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(path))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_alchemists_cache_for_tests()

        first = load_alchemists_cached()
        assert len(first) == 1

        # Yank the file out from under the cache.
        path.unlink()
        capsys.readouterr()

        served = load_alchemists_cached()
        captured = capsys.readouterr()

        # Same object — we kept the previous parse.
        assert served is first
        # But the stderr warning fired.
        assert "alchemists.yml stat failed" in captured.err
        assert "serving cached roster" in captured.err

    def test_symlink_target_swap_picked_up_via_default_stat(
        self, tmp_path, monkeypatch, capsys,
    ):
        """The user's #109 workflow uses a symlink at
        `~/.config/swf/.alchemists.yml` whose target gets rewritten
        in place. `os.stat` follows symlinks by default, so the cache
        observes the target's mtime change without us tracking the
        link explicitly."""
        target = tmp_path / "real.yml"
        target.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: target-v1\n'
            '    pubkey: "ed25519:' + "a" * 64 + '"\n',
            encoding="utf-8",
        )
        link = tmp_path / "link.yml"
        link.symlink_to(target)

        # Loader reads via the SYMLINK path (the user's workflow).
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(link))
        monkeypatch.delenv("SWF_CONFIG_DIR", raising=False)
        reset_alchemists_cache_for_tests()

        first = load_alchemists_cached()
        assert len(first) == 1
        assert first.is_alchemist_pubkey("ed25519:" + "a" * 64)

        # Rewrite the TARGET (not the link). With `os.stat` following
        # symlinks, the cached mtime now lags the target's mtime, so
        # the next call re-parses.
        target.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: target-v2-a\n'
            '    pubkey: "ed25519:' + "a" * 64 + '"\n'
            '  - id: target-v2-b\n'
            '    pubkey: "ed25519:' + "b" * 64 + '"\n',
            encoding="utf-8",
        )
        _bump_mtime(target)
        capsys.readouterr()

        fresh = load_alchemists_cached()
        captured = capsys.readouterr()
        assert fresh is not first
        assert len(fresh) == 2
        assert fresh.is_alchemist_pubkey("ed25519:" + "b" * 64)
        assert "alchemists.yml reloaded" in captured.err

    def test_load_stamps_loaded_at_and_mtime(
        self, tmp_path, monkeypatch,
    ):
        """`load_alchemists` populates `loaded_at` (ISO-8601 UTC, `Z`
        suffix) and `mtime_ns` (file's `st_mtime_ns`). Both are
        consumed downstream — `loaded_at` by `GET /alchemists`,
        `mtime_ns` by the cache hot-reload check."""
        path = tmp_path / ".alchemists.yml"
        path.write_text(
            'schema_version: 1\n'
            'alchemists:\n'
            '  - id: alc-0\n'
            '    pubkey: "ed25519:' + "0" * 64 + '"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("SWF_ALCHEMISTS_FILE", str(path))
        al = load_alchemists()
        assert al.loaded_at.endswith("Z")
        # Format: 2026-05-04T12:00:00Z (no fractional seconds, no
        # +00:00). Sanity check the broad shape.
        assert "T" in al.loaded_at
        assert al.mtime_ns > 0
        # `mtime_ns` matches the actual file's mtime at load time.
        assert al.mtime_ns == path.stat().st_mtime_ns
