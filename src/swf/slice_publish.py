"""Slice publisher: turn new search_results rows into signed slices.

The second half of the architectural inversion. Instead of friends
serving query-time HTTP fan-outs, each peer periodically publishes an
append-only chain of signed slices. Each slice carries entries (URL +
title + snippet + content_hash + extractor) added to this peer's
indrex since the previous slice. Peers pull each other's slices and
merge entries into their OWN local search_results table. Queries then
never leave the local process.

Spec: INDREX.md section B (v0 authenticity composition) + the 0.8
roadmap bullet.

Responsibilities:
  - Track the last published seq + cursor (timestamp) per node in
    `~/.config/swf/publisher-state.json`.
  - Snapshot new rows from the local `search_results` table (rows that
    arrived after the last cursor).
  - Build a slice via `swf.slice.build_slice`, sign with the node's
    Ed25519 identity, write to `~/.config/swf/slices/<seq>.json`.
  - Return the slice so a daemon / CLI can log what changed.

State format (JSON):
  {
    "last_seq": 3,
    "last_cursor": "2026-04-19T04:12:05+00:00",
    "last_hash": "<b64url content hash of slice seq=3>"
  }
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from swf.identity import get_or_create_identity
from swf.indrex import db_path
from swf.slice import Slice, build_slice


def _state_dir(cfg_dir: Path | str | None = None) -> Path:
    if cfg_dir is not None:
        d = Path(cfg_dir)
    else:
        d = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def slices_dir(cfg_dir: Path | str | None = None) -> Path:
    d = _state_dir(cfg_dir) / "slices"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _publisher_state_path(cfg_dir: Path | str | None = None) -> Path:
    return _state_dir(cfg_dir) / "publisher-state.json"


def load_publisher_state(cfg_dir: Path | str | None = None) -> dict:
    p = _publisher_state_path(cfg_dir)
    if not p.exists():
        return {"last_seq": -1, "last_cursor": "", "last_hash": ""}
    try:
        return json.loads(p.read_text())
    except Exception:
        return {"last_seq": -1, "last_cursor": "", "last_hash": ""}


def save_publisher_state(state: dict, cfg_dir: Path | str | None = None) -> None:
    _publisher_state_path(cfg_dir).write_text(json.dumps(state, indent=2))


@dataclass
class PublishOutcome:
    seq: int
    entries: int
    path: Path | None
    skipped: bool
    reason: str = ""


def _read_new_rows(cursor_ts: str, db: Path | None = None) -> list[dict]:
    """Return rows from search_results with seen_at > cursor_ts, ordered
    ascending by seen_at so slice entries have a natural sequence."""
    path = db_path(db) if db else db_path()
    if not path.exists():
        return []
    uri = f"file:{path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=0.5)
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute(
                "SELECT url, title, snippet, seen_at, engines "
                "  FROM search_results "
                " WHERE seen_at > :cursor "
                " ORDER BY seen_at ASC",
                {"cursor": cursor_ts or ""},
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    finally:
        conn.close()

    out: list[dict] = []
    for r in rows:
        url = r["url"] or ""
        if not url:
            continue
        # Use sha256 of the snippet as the "content_hash" approximation,
        # since we don't have the full page body here. For v0.8 this
        # marks the entry's content shape at publish time. When the 0.6
        # full-page sigchain ships in a follow-up, content_hash will use
        # the raw-HTML hash already stored in world_knowledge/web/.
        import hashlib as _h

        body = ((r["title"] or "") + "\n" + (r["snippet"] or "")).encode("utf-8")
        content_hash = "sha256:" + _h.sha256(body).hexdigest()
        out.append(
            {
                "url": url,
                "content_hash": content_hash,
                "extractor": "search_results_snippet",
                "fetched_at": r["seen_at"] or "",
                "final_url": url,
                # Non-canonical-signing fields carried for the receiver
                # to materialize. Not included in leaf hash so they can
                # evolve without breaking merkle verification.
                "_title": r["title"] or "",
                "_snippet": r["snippet"] or "",
                "_engines": r["engines"] or "",
            }
        )
    return out


def publish(
    db: Path | None = None,
    cfg_dir: Path | str | None = None,
) -> PublishOutcome:
    """Build the next slice from new search_results rows; sign and write.

    Returns `PublishOutcome` indicating what happened. Skipped publishes
    (no new rows) return `skipped=True` with a reason and do not advance
    state.
    """
    state = load_publisher_state(cfg_dir)
    cursor = state.get("last_cursor", "")
    new_rows = _read_new_rows(cursor, db=db)
    if not new_rows:
        return PublishOutcome(
            seq=state.get("last_seq", -1),
            entries=0,
            path=None,
            skipped=True,
            reason="no new rows since last publish",
        )

    ident = get_or_create_identity()
    next_seq = state.get("last_seq", -1) + 1

    slice_obj: Slice = build_slice(
        author_pubkey_b64=ident.pub_b64,
        seq=next_seq,
        prev_hash=state.get("last_hash", ""),
        entries=new_rows,
        identity=ident,
    )

    ts_tail = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = slices_dir(cfg_dir) / f"{next_seq:06d}-{ts_tail}.json"
    path.write_text(
        json.dumps(slice_obj.to_dict(include_sig=True), indent=2)
    )

    # Advance state to the highest seen_at we just packed.
    new_cursor = max((r["fetched_at"] for r in new_rows), default=cursor)
    save_publisher_state(
        {
            "last_seq": next_seq,
            "last_cursor": new_cursor,
            "last_hash": slice_obj.content_hash(),
            "last_path": str(path),
        },
        cfg_dir=cfg_dir,
    )

    return PublishOutcome(
        seq=next_seq, entries=len(new_rows), path=path, skipped=False
    )


def latest_head(cfg_dir: Path | str | None = None) -> dict | None:
    """Return the HEAD metadata (seq, hash, path, ts) or None if no
    slices published yet."""
    state = load_publisher_state(cfg_dir)
    if state.get("last_seq", -1) < 0:
        return None
    path = state.get("last_path")
    return {
        "seq": state["last_seq"],
        "hash": state["last_hash"],
        "cursor": state["last_cursor"],
        "path": path,
    }


def slice_path_for(seq: int, cfg_dir: Path | str | None = None) -> Path | None:
    """Find the on-disk slice file for the given seq, or None."""
    prefix = f"{seq:06d}-"
    for p in slices_dir(cfg_dir).glob(f"{prefix}*.json"):
        return p
    return None
