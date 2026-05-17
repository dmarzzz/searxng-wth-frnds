"""E2E tests for `swf-node --check` against the bundle-config validators.

Sister file to `test_node_check.py` — that one is search-focused (legacy
runtime DBs); this one exercises the bundle-config validators added in
the operator-UX pass (alchemists.yml, reservoir.yml, convent signing
key cross-check).

Why a separate file:
  * `test_node_check.py` already has its own `_bootstrap_runtime_dbs`
    fixture that we don't need here, and our scenarios touch
    orthogonal config (env vars + YAML files, no DB writes). Mixing
    would force every test in the file to share both setups.
  * The bundle-config validators FAIL with `[FAIL]` lines in their own
    namespace, so a test failure here points cleanly at bundle-config
    code without sieving through search-related output.

Pattern matches `test_node_check.py`:
  * subprocess `python -m swf.peer_server --check`
  * fresh tmp HOME so we don't poison the developer's real ~/.config
  * env strip-downs to clear any leaked overrides from the parent shell
  * stdout parsing on the `[ok] / [skip] / [warn] / [FAIL]` markers
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src"


def _run_check(
    home: Path, *, extra_env: dict | None = None,
) -> subprocess.CompletedProcess:
    """Run `swf-node --check` against `home` as HOME with a clean
    environment. Mirrors `test_node_check._run_check` but lifted here
    so the bundle-config tests don't depend on that file's internals."""
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["PYTHONPATH"] = str(SRC)
    # Strip any leftover overrides from the parent shell that would
    # redirect bundle-config or DB paths outside `home`.
    for k in (
        "SWF_CONFIG_DIR", "SWF_CACHE_DB", "SWF_CACHE_SECRET_FILE",
        "SWF_REPUTATION_DB", "SWF_TICKETS_DB",
        "SWF_ALCHEMISTS_FILE", "SWF_RESERVOIR_FILE",
        "SWF_CONVENT_SIGNING_KEY",
        "RA_WORLD_KNOWLEDGE_DIR",
    ):
        env.pop(k, None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "swf.peer_server", "--check"],
        capture_output=True, text=True, env=env, timeout=60,
    )


# ── helpers for forging YAMLs + Ed25519 seeds ─────────────────────────


def _gen_ed25519_seed() -> tuple[bytes, str]:
    """Generate a fresh Ed25519 keypair. Returns `(seed_bytes,
    pubkey_str)` where pubkey_str is the canonical `ed25519:<hex>`."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed, f"ed25519:{raw.hex()}"


def _write_alchemists(path: Path, *pubkey_strings: str) -> None:
    lines = ["schema_version: 1", "alchemists:"]
    for i, pk in enumerate(pubkey_strings):
        lines.append(f"  - id: alc-{i}")
        lines.append(f'    pubkey: "{pk}"')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_reservoir(path: Path, *recipients: str) -> None:
    lines = [
        "schema_version: 1",
        'generated_at: "2026-05-04T00:00:00Z"',
        "keys:",
    ]
    for i, r in enumerate(recipients):
        lines.append(f"  - id: alc-{i:03d}")
        lines.append(f'    pubkey: "{r}"')
        lines.append("    distributed_to: null")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# A single representative age recipient (bech32 X25519) we can hard-code.
# The `--check` validators only enforce the `age1` prefix, so we don't
# need a real X25519 pubkey here — the encryption-time path is what
# pyrage validates the bech32 body against. (Tests that need REAL
# X25519 keys live in test_two_peer_bundle_propagation.py.)
_AGE_RECIPIENT = "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx0001"


# ── tests ──────────────────────────────────────────────────────────────


def test_check_passes_with_full_bundle_config(tmp_path):
    """All three bundle-config checks PASS when configured correctly:

      * alchemists.yml parses + has at least one well-formed entry
      * reservoir.yml parses + has at least one age recipient
      * convent signing key seed file matches an alchemists.yml entry

    The convent-signing-key check is the cross-validating one — a
    common operator misconfig is "key file is fine, alchemists.yml is
    fine, but the pubkey isn't in the alchemist list" (the
    `--hivemind-sink` boot would refuse). PASS here means the cross-
    check found the pubkey in the list.
    """
    seed, pubkey_str = _gen_ed25519_seed()
    config_dir = tmp_path / ".config" / "swf"
    config_dir.mkdir(parents=True)
    seed_path = config_dir / "convent-signing.key"
    seed_path.write_bytes(seed)
    _write_alchemists(config_dir / ".alchemists.yml", pubkey_str)
    _write_reservoir(config_dir / ".reservoir.yml", _AGE_RECIPIENT)

    # Point the convent-signing-key check at the seed file via env;
    # the alchemists/reservoir checks fall through to the
    # `~/.config/swf/<name>` defaults inside `home`.
    res = _run_check(
        tmp_path,
        extra_env={"SWF_CONVENT_SIGNING_KEY": str(seed_path)},
    )
    out = res.stdout
    assert res.returncode == 0, (
        f"expected exit 0; got {res.returncode}\n"
        f"stdout={out}\nstderr={res.stderr}"
    )
    assert "[FAIL]" not in out, out
    # All three bundle-config checks must show [ok].
    assert "[ok] alchemists.yml" in out, out
    assert "[ok] reservoir.yml" in out, out
    assert "[ok] convent signing key" in out, out
    # The convent-key OK line names the matched alchemist by id.
    assert "matches alchemist alc-0" in out, out


def test_check_fails_on_malformed_alchemists_yml(tmp_path):
    """A YAML parse error in `.alchemists.yml` triggers `[FAIL]
    alchemists.yml: YAML parse failed`. The check returns non-zero so
    operator init scripts can react. Other bundle-config checks should
    still run (we don't short-circuit on a failure)."""
    config_dir = tmp_path / ".config" / "swf"
    config_dir.mkdir(parents=True)
    # Intentionally malformed YAML — unclosed quote, dangling colon.
    bad_yaml = textwrap.dedent("""
        schema_version: 1
        alchemists:
          - id: alc-0
            pubkey: "ed25519:not-a-valid-hex
        broken: : :
    """)
    (config_dir / ".alchemists.yml").write_text(bad_yaml, encoding="utf-8")

    res = _run_check(tmp_path)
    out = res.stdout
    assert "[FAIL] alchemists.yml" in out, out
    assert res.returncode >= 1, (res.returncode, out)


def test_check_warns_on_convent_key_not_in_alchemists(tmp_path):
    """The cross-check between SWF_CONVENT_SIGNING_KEY and
    `.alchemists.yml` emits `[warn]` (not `[FAIL]`) when the signing
    key's pubkey isn't listed in alchemists.yml — operator misconfig
    that would refuse `--hivemind-sink` boot but doesn't gate the
    daemon's other surfaces. WARN keeps the signal visible without
    incrementing the exit-code failure count, so init scripts that
    treat non-zero as fatal don't trip on a state the daemon can
    still partially serve from."""
    # Two distinct keypairs: alchemists.yml lists key #1; the env var
    # points at key #2's seed file. The cross-check finds the loaded
    # pubkey is NOT in alchemists.yml and warns.
    _seed1, pubkey1 = _gen_ed25519_seed()
    seed2, pubkey2 = _gen_ed25519_seed()
    assert pubkey1 != pubkey2

    config_dir = tmp_path / ".config" / "swf"
    config_dir.mkdir(parents=True)
    seed_path = config_dir / "convent-signing.key"
    seed_path.write_bytes(seed2)
    _write_alchemists(config_dir / ".alchemists.yml", pubkey1)
    # No reservoir — that check independently SKIPs.

    res = _run_check(
        tmp_path,
        extra_env={"SWF_CONVENT_SIGNING_KEY": str(seed_path)},
    )
    out = res.stdout
    # WARN does NOT count toward the exit code.
    assert res.returncode == 0, (
        f"expected 0 (warn ≠ failure); got {res.returncode}\n{out}"
    )
    assert "[warn] convent signing key" in out, out
    # The warning text identifies the missing pubkey -> alchemists.yml mismatch.
    assert "NOT in" in out and ".alchemists.yml" in out, out
    # The alchemists.yml itself parsed cleanly so its check is OK.
    assert "[ok] alchemists.yml" in out, out


def test_check_skips_when_no_bundle_config(tmp_path):
    """A fresh tmp HOME with NO bundle-config files and NO env vars
    set: every bundle-config check SKIPs (operator hasn't opted in).
    SKIP must NOT count as a failure — a fresh swf-node install
    must exit 0 even with no optional config so init scripts that
    treat non-zero as fatal don't misfire.

    This is the exact contract `test_node_check.test_check_on_fresh_home_reports_missing_dbs`
    asserts at the suite level; we double-down here on the bundle
    surface specifically so a regression in `_check_alchemists_yml`'s
    skip-vs-fail logic doesn't sneak through.
    """
    res = _run_check(tmp_path)
    out = res.stdout
    assert res.returncode == 0, (
        f"expected 0 on fresh HOME; got {res.returncode}\n"
        f"stdout={out}\nstderr={res.stderr}"
    )
    # Each bundle-config check has its own skip line.
    assert "[skip] alchemists.yml" in out, out
    assert "[skip] reservoir.yml" in out, out
    assert "[skip] convent signing key" in out, out
    # And no FAILs from these checks (other DB checks may also skip
    # on a fresh HOME, which is fine — the contract is "skip != fail").
    bundle_fail_markers = [
        "[FAIL] alchemists.yml",
        "[FAIL] reservoir.yml",
        "[FAIL] convent signing key",
    ]
    for marker in bundle_fail_markers:
        assert marker not in out, (marker, out)
