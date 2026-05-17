"""Alchemist signing-list loader.

Phase 1 of #93. Per spec §3.7, every cohort/transcript bundle must
be signed by an Ed25519 key whose pubkey is listed in
`.alchemists.yml`:

    schema_version: 1
    alchemists:
      - id: andrew
        pubkey: "ed25519:<hex>"
      - id: tina
        pubkey: "ed25519:<hex>"

This module loads the file, normalizes pubkeys to the lookup key
expected by the verifier (the full `ed25519:<hex>` string), and exposes
a small dataclass for membership checks.

Lookup order for the file (first that exists wins):
    1. `$SWF_ALCHEMISTS_FILE`     — explicit override
    2. `$SWF_CONFIG_DIR/.alchemists.yml`
    3. `~/.config/swf/.alchemists.yml`

A missing file is NOT an error: we return an empty `AlchemistList` and
emit a one-line stderr warning so a fresh swf-node still boots. The
verifier will reject every cohort/transcript bundle it sees, which is
the right safe-by-default behavior. `search.result` bundles bypass the
alchemist check entirely (see `swf.bundles.verify`) so the legacy
search path keeps working.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml


@dataclass(frozen=True)
class AlchemistList:
    """Membership predicate over alchemist pubkeys.

    `members` maps the canonical pubkey string (as it appears in YAML —
    `"ed25519:<hex>"`) to the alchemist's id (`"andrew"`, ...). The id
    is informational; only membership is consulted by the verifier.

    `path` records where the list came from so callers can surface it
    in logs / diagnostics. None means "no file found".
    """

    members: dict[str, str] = field(default_factory=dict)
    path: Path | None = None
    #: ISO-8601 UTC timestamp captured at the moment the YAML was
    #: parsed. Surfaced by `GET /alchemists` (#108 ask 2) so operators
    #: can tell at a glance when the in-memory roster last refreshed
    #: relative to the file on disk.
    loaded_at: str = ""
    #: `st_mtime_ns` of the resolved file at last load. Used by
    #: `load_alchemists_cached` to detect external edits and trigger a
    #: re-parse without a daemon restart (#109). Zero when the file
    #: was missing or stat failed.
    mtime_ns: int = 0

    def is_alchemist_pubkey(self, pubkey: str) -> bool:
        """True iff `pubkey` (canonical `ed25519:<hex>` form) is listed.

        We only consult exact-string matches. Callers should pass the
        envelope's `author.pubkey` verbatim — the verifier guarantees
        the prefix at the shape-check stage, so canonicalization is a
        non-issue here.
        """
        return pubkey in self.members

    def __len__(self) -> int:
        return len(self.members)

    def __bool__(self) -> bool:
        return bool(self.members)


def is_alchemist_pubkey(pubkey: str, alchemists: AlchemistList) -> bool:
    """Module-level convenience for the public surface.

    Equivalent to `alchemists.is_alchemist_pubkey(pubkey)`; exposed
    separately so the import surface in `swf.bundles.__init__` matches
    the issue spec.
    """
    return alchemists.is_alchemist_pubkey(pubkey)


def _candidate_paths(explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    out: list[Path] = []
    env = os.environ.get("SWF_ALCHEMISTS_FILE")
    if env:
        out.append(Path(env))
    cfg_env = os.environ.get("SWF_CONFIG_DIR")
    if cfg_env:
        out.append(Path(cfg_env) / ".alchemists.yml")
    out.append(Path.home() / ".config" / "swf" / ".alchemists.yml")
    return out


def _utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with second precision and a literal `Z`
    suffix. Matches the wire format the rest of the bundle subsystem
    uses for timestamps (`signed_at`, `generated_at`, etc.) so a
    `loaded_at` value round-trips through clients without bespoke
    parsing."""
    return datetime.now(timezone.utc).replace(
        microsecond=0,
    ).isoformat().replace("+00:00", "Z")


def _stat_mtime_ns(p: Path) -> int:
    """Return `st_mtime_ns` for `p`, following symlinks. Returns 0 if
    the stat fails (file missing, broken symlink, permission). Callers
    treat 0 as "couldn't stat" — used by the lazy-reload path to keep
    serving the previous cache instead of crashing."""
    try:
        # `os.stat` follows symlinks by default. Per #109 the user's
        # workflow is "the symlink stays put; the target file gets
        # rewritten" — so we capture the symlinked path verbatim and
        # let `os.stat` resolve it on each call. If the user later
        # flips the symlink to a different target, the next stat
        # observes that target's mtime (and we re-load). This is
        # Option A from the issue: simpler than re-resolving the
        # symlink chain ourselves.
        return p.stat().st_mtime_ns
    except OSError:
        return 0


def load_alchemists(path: Path | None = None) -> AlchemistList:
    """Load `.alchemists.yml` and return an `AlchemistList`.

    Behavior:
      - Missing file -> empty list, stderr warning, no exception.
      - Malformed file (not a dict, missing `alchemists` key, entries
        without `pubkey`) -> stderr warning per problem; valid entries
        still survive. We choose lenient parsing because a fresh repo
        may have a partially-edited file during program-bring-up.
      - Pubkeys are stored verbatim (must include the `ed25519:` prefix
        per §3.7). Entries with malformed pubkeys are skipped with a
        warning rather than aborting the load.
      - Stamps `loaded_at` (ISO-8601 UTC, second precision) and
        `mtime_ns` (the resolved file's `st_mtime_ns`) at parse time.
        The cache layer (`load_alchemists_cached`) uses `mtime_ns` to
        detect operator edits and trigger a re-parse without a daemon
        restart; `loaded_at` is surfaced by `GET /alchemists`.
    """
    loaded_at = _utcnow_iso()
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
            f"[bundles] no alchemists.yml found at {target}; "
            "all signed bundles will be rejected",
            file=sys.stderr,
        )
        return AlchemistList(
            members={}, path=None, loaded_at=loaded_at, mtime_ns=0,
        )

    mtime_ns = _stat_mtime_ns(found)

    try:
        raw = yaml.safe_load(found.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        print(
            f"[bundles] failed to read {found}: {exc}; treating as empty",
            file=sys.stderr,
        )
        return AlchemistList(
            members={}, path=found, loaded_at=loaded_at, mtime_ns=mtime_ns,
        )

    members: dict[str, str] = {}
    if not isinstance(raw, dict):
        print(
            f"[bundles] {found}: expected top-level mapping, got {type(raw).__name__}",
            file=sys.stderr,
        )
        return AlchemistList(
            members={}, path=found, loaded_at=loaded_at, mtime_ns=mtime_ns,
        )

    entries = raw.get("alchemists")
    if not isinstance(entries, list):
        print(
            f"[bundles] {found}: missing or non-list 'alchemists' key",
            file=sys.stderr,
        )
        return AlchemistList(
            members={}, path=found, loaded_at=loaded_at, mtime_ns=mtime_ns,
        )

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            print(
                f"[bundles] {found}: entry #{idx} is not a mapping; skipped",
                file=sys.stderr,
            )
            continue
        pub = entry.get("pubkey")
        ident = entry.get("id") or ""
        if not isinstance(pub, str) or not pub.startswith("ed25519:"):
            print(
                f"[bundles] {found}: entry #{idx} has malformed pubkey; skipped",
                file=sys.stderr,
            )
            continue
        # Last-write-wins on duplicate pubkeys; warn so the operator
        # notices the inconsistency.
        if pub in members:
            print(
                f"[bundles] {found}: duplicate pubkey for entry #{idx}; "
                "earlier entry overwritten",
                file=sys.stderr,
            )
        members[pub] = str(ident)

    return AlchemistList(
        members=members, path=found, loaded_at=loaded_at, mtime_ns=mtime_ns,
    )


# ── process-wide cache ────────────────────────────────────────────────
#
# The alchemist list is loaded once and reused across every bundle
# ingest channel (peer_server's `POST /bundles` verifier, the bundle
# puller, the hivemind route). Lifting the cache out of the individual
# call sites ensures a single `.alchemists.yml` is parsed at most once
# per process — no matter how many channels are wired in.
#
# Hot-reload (added per #109): on every `load_alchemists_cached()` call
# we cheap-stat the captured file path. If the resolved file's
# `st_mtime_ns` advanced since last load, we re-parse and atomically
# swap the cache. The check is microseconds (one `stat()`) so it runs
# unconditionally — no debounce, no filesystem watch, no extra thread.
#
# Symlink note: Python's `os.stat` follows symlinks by default. The
# user's workflow keeps the symlink at `~/.config/swf/.alchemists.yml`
# fixed and rewrites the target file in place; capturing the original
# (symlinked) path and re-stat'ing it on each call catches every edit
# without us having to track symlink targets ourselves. If the symlink
# is later flipped to a different target, the next stat observes the
# new target's mtime and we re-load. (`inotify` would NOT see this —
# it watches the inode, not the link.)
#
# Tests reset via `reset_alchemists_cache_for_tests`. Wrappers in
# `peer_server.py`, `swf.bundles.puller`, and `swf.hivemind.route`
# delegate here so existing test surface
# (`peer_server._reset_alchemists_cache_for_tests`,
# `puller.reset_alchemists_cache_for_tests`) keeps working.

_ALCHEMISTS_CACHE: AlchemistList | None = None


def load_alchemists_cached() -> AlchemistList:
    """Lazy-load + cache the alchemist list, with mtime-based hot-reload.

    On each call:
      1. If the cache is empty, load + cache (cold start).
      2. Otherwise, `stat()` the captured file path (following
         symlinks). Compare `st_mtime_ns` against the value stamped at
         last load.
      3. If mtime advanced, re-load and atomically swap the cache.
         Emit a stderr line `[bundles] alchemists.yml reloaded
         (N -> M entries)`.
      4. If the stat fails (file vanished, symlink broke), keep
         serving the previous cache and log
         `[bundles] alchemists.yml stat failed: <reason>; serving
         cached roster` so the operator notices but the relay doesn't
         start 403'ing every POST.

    Used by every bundle ingest channel (peer_server's `POST /bundles`
    verifier, the pull puller, the hivemind route) so all three paths
    agree on which authors are blessed to sign — and all three pick up
    operator edits to `.alchemists.yml` without a daemon restart.
    """
    global _ALCHEMISTS_CACHE
    cached = _ALCHEMISTS_CACHE
    if cached is None:
        _ALCHEMISTS_CACHE = load_alchemists()
        return _ALCHEMISTS_CACHE

    # Cache exists. If the original load found no file (cached.path is
    # None), there's no path to stat — so we re-walk the candidate
    # list each call to detect a file appearing. Cheap (one is_file
    # per primary candidate) and only hit in the rare cached-empty
    # case; the common path (cached.path set) is one stat() per call.
    if cached.path is None:
        for p in _candidate_paths(None):
            try:
                if p.is_file():
                    fresh = load_alchemists()
                    print(
                        f"[bundles] alchemists.yml reloaded "
                        f"({len(cached)} -> {len(fresh)} entries)",
                        file=sys.stderr,
                    )
                    _ALCHEMISTS_CACHE = fresh
                    return fresh
            except OSError:
                continue
        return cached

    # Common path: cached has a known file. Stat it (following the
    # symlink) and compare to the cached mtime.
    try:
        new_mtime = cached.path.stat().st_mtime_ns
    except OSError as exc:
        # File disappeared (deleted, symlink broken). Keep serving the
        # previous cache so in-flight POSTs don't start 403'ing while
        # the operator regenerates the file.
        print(
            f"[bundles] alchemists.yml stat failed: {exc}; "
            "serving cached roster",
            file=sys.stderr,
        )
        return cached

    if new_mtime == cached.mtime_ns:
        return cached

    # mtime advanced — re-parse. The new load captures the new mtime
    # itself, so subsequent calls will be no-ops until the next edit.
    fresh = load_alchemists()
    print(
        f"[bundles] alchemists.yml reloaded "
        f"({len(cached)} -> {len(fresh)} entries)",
        file=sys.stderr,
    )
    _ALCHEMISTS_CACHE = fresh
    return fresh


def reset_alchemists_cache_for_tests() -> None:
    """Drop the cached AlchemistList. Tests call this between cases that
    point at different tmp `.alchemists.yml` files."""
    global _ALCHEMISTS_CACHE
    _ALCHEMISTS_CACHE = None
