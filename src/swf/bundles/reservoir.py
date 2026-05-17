"""Encryption-key reservoir loader.

Phase 7 of #93. Per spec §3.6, every `cohort.depth` and (when encrypted)
`transcript.batch` bundle is age-encrypted to ALL the public keys in
`cohort-data/.reservoir.yml`:

    schema_version: 1
    generated_at: "2026-05-07T..."
    keys:
      - id: alc-001
        pubkey: "age1xxxx..."
        distributed_to: "Andrew"
      - id: alc-002
        pubkey: "age1yyyy..."
        distributed_to: "Tina"
      - id: alc-005
        pubkey: "age1eeee..."
        distributed_to: null     # unallocated, stays in cold storage

This module loads the file, exposes a small dataclass for membership
checks, and is the sole place the producer-side encryption path looks
up reservoir pubkeys.

Lookup order for the file (first that exists wins):
    1. `$SWF_RESERVOIR_FILE`     — explicit override
    2. `$SWF_CONFIG_DIR/.reservoir.yml`
    3. `~/.config/swf/.reservoir.yml`

A missing file is NOT an error: we return a `Reservoir` with an empty
`keys` list and emit a one-line stderr warning so a fresh swf-node
still boots. Callers that depend on the reservoir (the hivemind sink's
`?encrypt=true` path) check `Reservoir.pubkeys()` and fail with a 503
when it's empty — see `swf.hivemind.sink`. Callers that don't need
encryption (the default unencrypted hivemind path, the `POST /bundles`
verifier) ignore the reservoir entirely.

Mirror the conventions of `swf.bundles.alchemists`: lenient parsing
(skip malformed entries with a warning rather than aborting the
load), schema-version warning rather than rejection, and a
single-pass YAML load so the file format stays operator-friendly.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

#: Current `.reservoir.yml` schema version. Spec §3.6 examples carry
#: `schema_version: 1`; mismatches log a warning but do not reject the
#: load (forward compat: a future loader extension might add fields).
_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ReservoirEntry:
    """One row in `.reservoir.yml`.

    `id` is a short slug — `"alc-001"` etc. — used purely for
    operator readability; the encryption code keys on `pubkey`.

    `pubkey` is the age recipient string (`age1...`, the bech32-encoded
    X25519 pubkey). Stored verbatim so it round-trips into pyrage's
    `Recipient.from_str` without re-encoding.

    `distributed_to` is the human name the privkey was handed to, or
    None for unallocated keys. Informational only; the encryption path
    does NOT consult it (spec §3.6 says "encrypted to all 20 reservoir
    pubkeys" — distribution status doesn't gate inclusion).
    """

    id: str
    pubkey: str
    distributed_to: str | None


@dataclass(frozen=True)
class Reservoir:
    """The loaded reservoir.

    `keys` is the in-order list of entries; downstream callers who need
    the pubkey set call `pubkeys()` to drop ids/distribution metadata.

    `path` records where the list came from for log/diagnostics; None
    means "no file found".

    `mtime_ns` is the resolved file's `st_mtime_ns` at parse time —
    used by `load_reservoir_cached` for #109's lazy-reload check.
    Zero when the file was missing or stat failed.
    """

    schema_version: int = _SCHEMA_VERSION
    generated_at: str = ""
    keys: list[ReservoirEntry] = field(default_factory=list)
    path: Path | None = None
    mtime_ns: int = 0

    def pubkeys(self) -> list[str]:
        """Recipient strings, in file order. Used as the input to
        `swf.bundles.encryption.encrypt_payload` and as the
        `encryption.recipients` envelope field."""
        return [e.pubkey for e in self.keys]

    def is_recipient(self, pk: str) -> bool:
        """True iff `pk` (an age recipient string) is in the reservoir.
        Used by the verifier's recipients-subset-of-reservoir check."""
        return any(e.pubkey == pk for e in self.keys)

    def __len__(self) -> int:
        return len(self.keys)

    def __bool__(self) -> bool:
        return bool(self.keys)


def _candidate_paths(explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    out: list[Path] = []
    env = os.environ.get("SWF_RESERVOIR_FILE")
    if env:
        out.append(Path(env))
    cfg_env = os.environ.get("SWF_CONFIG_DIR")
    if cfg_env:
        out.append(Path(cfg_env) / ".reservoir.yml")
    out.append(Path.home() / ".config" / "swf" / ".reservoir.yml")
    return out


def _stat_mtime_ns(p: Path) -> int:
    """Return `st_mtime_ns` for `p`, following symlinks. Returns 0 if
    the stat fails (file missing, broken symlink, permission). Used
    by `load_reservoir_cached`'s lazy-reload check (#109)."""
    try:
        return p.stat().st_mtime_ns
    except OSError:
        return 0


def load_reservoir(path: Path | None = None) -> Reservoir:
    """Load `.reservoir.yml` and return a `Reservoir`.

    Behavior:
      - Missing file -> empty reservoir, stderr warning, no exception.
      - Malformed file (not a dict, missing `keys` key, entries without
        `pubkey`) -> stderr warning per problem; valid entries still
        survive.
      - `schema_version` mismatch -> warning, but the load proceeds —
        we don't know what a future schema would change, so we treat
        the keys we can parse as authoritative.
      - Pubkeys are stored verbatim (must start with `age1` per spec
        §3.6 — `age-v1` X25519 recipient bech32 form). Entries with
        malformed pubkeys are skipped with a warning rather than
        aborting the load.
      - Stamps `mtime_ns` (the resolved file's `st_mtime_ns`) at parse
        time so the cache layer (`load_reservoir_cached`) can detect
        operator edits and trigger a re-parse without a daemon restart.
    """
    candidates = _candidate_paths(path)
    found: Path | None = None
    for p in candidates:
        try:
            if p.is_file():
                found = p
                break
        except OSError:
            continue

    if found is None:
        target = candidates[0] if candidates else Path("<unknown>")
        print(
            f"[bundles] no reservoir.yml found at {target}; "
            "encrypted bundles cannot be produced",
            file=sys.stderr,
        )
        return Reservoir(keys=[], path=None, mtime_ns=0)

    mtime_ns = _stat_mtime_ns(found)

    try:
        raw = yaml.safe_load(found.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(
            f"[bundles] failed to read {found}: {exc}; treating as empty",
            file=sys.stderr,
        )
        return Reservoir(keys=[], path=found, mtime_ns=mtime_ns)

    if not isinstance(raw, dict):
        print(
            f"[bundles] {found}: expected top-level mapping, got {type(raw).__name__}",
            file=sys.stderr,
        )
        return Reservoir(keys=[], path=found, mtime_ns=mtime_ns)

    schema_version = raw.get("schema_version", _SCHEMA_VERSION)
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        print(
            f"[bundles] {found}: schema_version must be int; got "
            f"{type(schema_version).__name__}, ignoring",
            file=sys.stderr,
        )
        schema_version = _SCHEMA_VERSION
    elif schema_version != _SCHEMA_VERSION:
        print(
            f"[bundles] {found}: schema_version {schema_version} "
            f"!= expected {_SCHEMA_VERSION}; proceeding anyway",
            file=sys.stderr,
        )

    generated_at = raw.get("generated_at", "")
    if not isinstance(generated_at, str):
        generated_at = ""

    entries = raw.get("keys")
    if not isinstance(entries, list):
        print(
            f"[bundles] {found}: missing or non-list 'keys' key",
            file=sys.stderr,
        )
        return Reservoir(
            schema_version=schema_version,
            generated_at=generated_at,
            keys=[], path=found, mtime_ns=mtime_ns,
        )

    parsed: list[ReservoirEntry] = []
    seen_pubkeys: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            print(
                f"[bundles] {found}: entry #{idx} is not a mapping; skipped",
                file=sys.stderr,
            )
            continue
        pub = entry.get("pubkey")
        ident = entry.get("id") or ""
        dist = entry.get("distributed_to")
        if not isinstance(pub, str) or not pub.startswith("age1"):
            print(
                f"[bundles] {found}: entry #{idx} has malformed pubkey; "
                "expected 'age1...' (bech32 X25519 recipient); skipped",
                file=sys.stderr,
            )
            continue
        if pub in seen_pubkeys:
            print(
                f"[bundles] {found}: duplicate pubkey for entry #{idx}; "
                "earlier entry kept, later skipped",
                file=sys.stderr,
            )
            continue
        if dist is not None and not isinstance(dist, str):
            print(
                f"[bundles] {found}: entry #{idx} has non-string "
                "distributed_to; coerced to None",
                file=sys.stderr,
            )
            dist = None
        seen_pubkeys.add(pub)
        parsed.append(ReservoirEntry(
            id=str(ident), pubkey=pub, distributed_to=dist,
        ))

    return Reservoir(
        schema_version=schema_version,
        generated_at=generated_at,
        keys=parsed,
        path=found,
        mtime_ns=mtime_ns,
    )


# ── process-wide cache ────────────────────────────────────────────────
#
# The reservoir is loaded once and reused across every bundle ingest
# channel (the hivemind sink, the bundle puller, the `POST /bundles`
# verifier). Lifting the cache out of the individual call sites
# ensures a single `.reservoir.yml` is parsed at most once per process.
#
# Hot-reload (added per #109's "do the same for reservoir" note):
# operators hit the same problem with `.reservoir.yml` as with
# `.alchemists.yml` — regenerating the file requires a daemon restart
# unless we re-stat. We do exactly the alchemist trick: on every
# `load_reservoir_cached()` call, stat the captured file path
# (following symlinks), compare `st_mtime_ns`, and re-parse on
# advance. Stat failures keep the previous cache so an in-flight
# encrypted POST doesn't 503 mid-rotation.
#
# Tests reset via `reset_reservoir_cache_for_tests`.

_RESERVOIR_CACHE: Reservoir | None = None


def load_reservoir_cached() -> Reservoir:
    """Lazy-load + cache the reservoir, with mtime-based hot-reload.

    On each call:
      1. If the cache is empty, load + cache (cold start).
      2. Otherwise, `stat()` the captured file path (following
         symlinks). Compare `st_mtime_ns` against the value stamped at
         last load.
      3. If mtime advanced, re-load and atomically swap the cache.
         Emit a stderr line `[bundles] reservoir.yml reloaded
         (N -> M keys)`.
      4. If the stat fails (file vanished, symlink broke), keep
         serving the previous cache and log
         `[bundles] reservoir.yml stat failed: <reason>; serving
         cached reservoir` so the operator notices but the relay
         doesn't start 503'ing every encrypted POST.

    Used by every bundle ingest channel (hivemind sink, pull puller,
    `POST /bundles` verifier) so all three paths agree on which set
    of recipients a producer is allowed to encrypt to — and all three
    pick up operator edits to `.reservoir.yml` without a daemon
    restart.
    """
    global _RESERVOIR_CACHE
    cached = _RESERVOIR_CACHE
    if cached is None:
        _RESERVOIR_CACHE = load_reservoir()
        return _RESERVOIR_CACHE

    if cached.path is None:
        # No file at first load. Re-walk the candidate list to see if
        # one appeared. Same shape as the alchemist cache.
        for p in _candidate_paths(None):
            try:
                if p.is_file():
                    fresh = load_reservoir()
                    print(
                        f"[bundles] reservoir.yml reloaded "
                        f"({len(cached)} -> {len(fresh)} keys)",
                        file=sys.stderr,
                    )
                    _RESERVOIR_CACHE = fresh
                    return fresh
            except OSError:
                continue
        return cached

    try:
        new_mtime = cached.path.stat().st_mtime_ns
    except OSError as exc:
        print(
            f"[bundles] reservoir.yml stat failed: {exc}; "
            "serving cached reservoir",
            file=sys.stderr,
        )
        return cached

    if new_mtime == cached.mtime_ns:
        return cached

    fresh = load_reservoir()
    print(
        f"[bundles] reservoir.yml reloaded "
        f"({len(cached)} -> {len(fresh)} keys)",
        file=sys.stderr,
    )
    _RESERVOIR_CACHE = fresh
    return fresh


def reset_reservoir_cache_for_tests() -> None:
    """Drop the cached reservoir. Tests call this between cases that
    point at different tmp `.reservoir.yml` files."""
    global _RESERVOIR_CACHE
    _RESERVOIR_CACHE = None
