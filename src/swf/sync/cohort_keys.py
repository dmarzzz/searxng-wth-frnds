"""Cohort-keys file loader (spec §8.2).

The cohort-keys file is the trust root: a static JSON file distributed
out of band (typically shipped with the Electron app) that maps
cohort-member handles to Ed25519 pubkeys. Sync verifies every incoming
envelope's `author_pubkey` against this list.

File shape (spec §8.2):

    {
      "schema": "swf.cohort_keys.v1",
      "cohort_id": "shape-rotator-2025-cohort-3",
      "generated_at_ms": 1716000000000,
      "members": [
        {"handle": "amiller",
         "pubkey": "ed25519:<hex>",
         "added_at_ms": 1715000000000}
      ]
    }

Resolution order (spec §8.2):
  1. `$SWF_COHORT_KEYS_FILE`            — explicit override
  2. `$SWF_CONFIG_DIR/cohort-keys.json`
  3. `~/.config/swf/cohort-keys.json`

A missing file is NOT a daemon failure — it just means "no cohort
known", and the HTTP layer returns 503 `no_cohort_keys` to incoming
sync attempts. Validators reject duplicate handles (spec §9.6) and
malformed pubkeys; the file MAY contain other entries that are
silently skipped.

Hot-reload mirrors `swf.bundles.alchemists.load_alchemists_cached`:
one `stat()` per call on the captured path, cache swap on mtime
advance. No background thread, no inotify.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Reuse the same canonicalization rule for hashing the loaded file's
# pubkey set when we want a stable identity for diagnostics. Not
# required by the spec but keeps log lines deterministic.
_PUBKEY_PREFIX = "ed25519:"


@dataclass(frozen=True)
class CohortKeys:
    """Resolved cohort-keys file.

    `members` is the handle → pubkey map (spec §8.2). Both fields are
    informational on the wire — the sync verifier consults `pubkeys`
    (a frozenset of every legal author pubkey) for the whitelist
    check, and the local-write path consults `members` to look up the
    expected author of a `record_id`.

    `path` is `None` when no file was found; in that case the loader
    emits a single stderr warning at load time and `bool(self)` is
    False so the HTTP layer can refuse incoming sync with a clean 503.
    """

    members: dict[str, str] = field(default_factory=dict)  # handle → pubkey
    cohort_id: str = ""
    path: Path | None = None
    mtime_ns: int = 0

    @property
    def pubkeys(self) -> frozenset[str]:
        """All pubkeys in canonical `ed25519:<hex>` form."""
        return frozenset(self.members.values())

    def is_known_pubkey(self, pubkey: str) -> bool:
        """True iff `pubkey` (canonical `ed25519:<hex>` form) is in the
        cohort. Exact-match; the loader rejects malformed entries up
        front so callers can pass the envelope's `author_pubkey`
        verbatim."""
        return pubkey in self.pubkeys

    def pubkey_for_handle(self, handle: str) -> str | None:
        """Return the pubkey for `handle`, or None if not in cohort.

        Used by the local-write path (`POST /sync/local_record`) to
        cross-check that the local node's identity matches the
        expected author of the `record_id` (spec §7.4 / §9.5).
        """
        return self.members.get(handle)

    def handle_for_pubkey(self, pubkey: str) -> str | None:
        """Inverse of `pubkey_for_handle`. Linear scan, but the cohort
        is O(50) entries — not worth a second dict."""
        for h, pk in self.members.items():
            if pk == pubkey:
                return h
        return None

    def __len__(self) -> int:
        return len(self.members)

    def __bool__(self) -> bool:
        return bool(self.members)


def _candidate_paths(explicit: Path | None) -> list[Path]:
    """Resolve the candidate file paths in the order spec §8.2 mandates."""
    if explicit is not None:
        return [explicit]
    out: list[Path] = []
    env_file = os.environ.get("SWF_COHORT_KEYS_FILE")
    if env_file:
        out.append(Path(env_file))
    cfg_env = os.environ.get("SWF_CONFIG_DIR")
    if cfg_env:
        out.append(Path(cfg_env) / "cohort-keys.json")
    out.append(Path.home() / ".config" / "swf" / "cohort-keys.json")
    return out


def _stat_mtime_ns(p: Path) -> int:
    try:
        return p.stat().st_mtime_ns
    except OSError:
        return 0


def load_cohort_keys(path: Path | None = None) -> CohortKeys:
    """Load + validate a cohort-keys file.

    Validation rules (spec §9.6):
      * The top-level value MUST be a dict.
      * `members` MUST be a list of dicts.
      * Each entry MUST have `handle: str` and `pubkey: str` matching
        the `ed25519:<64 hex>` form.
      * Duplicate handles are rejected — the second entry is dropped
        with a stderr warning. (The spec calls duplicate handles a
        cohort-curator bug worth surfacing loudly.)
      * Duplicate pubkeys are also dropped with a warning.
      * Malformed entries are skipped individually rather than failing
        the whole load — lenient parsing matches the alchemist loader.

    Missing file → empty `CohortKeys` with `path=None`. Idempotent and
    never raises.
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
            f"[sync] no cohort-keys.json found at {target}; "
            "sync will refuse all incoming envelopes",
            file=sys.stderr,
        )
        return CohortKeys()

    mtime_ns = _stat_mtime_ns(found)
    try:
        raw = json.loads(found.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(
            f"[sync] failed to read {found}: {exc}; treating as empty",
            file=sys.stderr,
        )
        return CohortKeys(path=found, mtime_ns=mtime_ns)

    if not isinstance(raw, dict):
        print(
            f"[sync] {found}: expected top-level mapping, got {type(raw).__name__}",
            file=sys.stderr,
        )
        return CohortKeys(path=found, mtime_ns=mtime_ns)

    cohort_id_raw = raw.get("cohort_id", "")
    cohort_id = cohort_id_raw if isinstance(cohort_id_raw, str) else ""

    entries = raw.get("members")
    if not isinstance(entries, list):
        print(
            f"[sync] {found}: missing or non-list 'members' key",
            file=sys.stderr,
        )
        return CohortKeys(
            cohort_id=cohort_id, path=found, mtime_ns=mtime_ns,
        )

    members: dict[str, str] = {}
    seen_pubkeys: set[str] = set()
    import re as _re
    _pubkey_re = _re.compile(r"^ed25519:[0-9a-f]{64}$")

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            print(
                f"[sync] {found}: entry #{idx} is not a mapping; skipped",
                file=sys.stderr,
            )
            continue
        handle = entry.get("handle")
        pubkey = entry.get("pubkey")
        if not isinstance(handle, str) or not handle:
            print(
                f"[sync] {found}: entry #{idx} missing handle; skipped",
                file=sys.stderr,
            )
            continue
        if not isinstance(pubkey, str) or not _pubkey_re.match(pubkey):
            print(
                f"[sync] {found}: entry #{idx} ({handle}) has malformed pubkey; skipped",
                file=sys.stderr,
            )
            continue
        if handle in members:
            # Duplicate handle. Spec §9.6: reject — surface the
            # validator failure and keep the first entry rather than
            # silently overwriting.
            print(
                f"[sync] {found}: duplicate handle {handle!r} at entry #{idx}; skipped",
                file=sys.stderr,
            )
            continue
        if pubkey in seen_pubkeys:
            print(
                f"[sync] {found}: duplicate pubkey for {handle!r} at entry #{idx}; skipped",
                file=sys.stderr,
            )
            continue
        members[handle] = pubkey
        seen_pubkeys.add(pubkey)

    return CohortKeys(
        members=members,
        cohort_id=cohort_id,
        path=found,
        mtime_ns=mtime_ns,
    )


# ── process-wide cache with mtime hot-reload ──────────────────────────

_CACHE: CohortKeys | None = None


def load_cohort_keys_cached() -> CohortKeys:
    """Lazy-load + cache the cohort-keys file, with mtime hot-reload.

    Behavior mirrors `swf.bundles.alchemists.load_alchemists_cached`:

      1. Cold start → load, cache, return.
      2. Cached.path is None (no file at first load) → re-walk the
         candidate list each call so a freshly-dropped file is picked
         up. Cheap.
      3. Cached.path set → one `stat()` per call. If `st_mtime_ns`
         advanced since last load, re-parse and atomically swap the
         cache.
      4. Stat fails (file vanished) → keep serving the previous cache,
         emit a stderr warning. The daemon stays up; the operator
         sees the message.
    """
    global _CACHE
    cached = _CACHE
    if cached is None:
        _CACHE = load_cohort_keys()
        return _CACHE

    if cached.path is None:
        # No file at first load — re-walk candidates each call so a
        # freshly-dropped file gets picked up without a daemon restart.
        for p in _candidate_paths(None):
            try:
                if p.is_file():
                    fresh = load_cohort_keys()
                    print(
                        f"[sync] cohort-keys.json reloaded "
                        f"({len(cached)} -> {len(fresh)} entries)",
                        file=sys.stderr,
                    )
                    _CACHE = fresh
                    return fresh
            except OSError:
                continue
        return cached

    try:
        new_mtime = cached.path.stat().st_mtime_ns
    except OSError as exc:
        print(
            f"[sync] cohort-keys.json stat failed: {exc}; "
            "serving cached roster",
            file=sys.stderr,
        )
        return cached

    if new_mtime == cached.mtime_ns:
        return cached

    fresh = load_cohort_keys()
    print(
        f"[sync] cohort-keys.json reloaded "
        f"({len(cached)} -> {len(fresh)} entries)",
        file=sys.stderr,
    )
    _CACHE = fresh
    return fresh


def reset_cohort_keys_cache_for_tests() -> None:
    """Drop the cached `CohortKeys`. Tests call this between cases that
    point at different tmp cohort-keys files."""
    global _CACHE
    _CACHE = None
