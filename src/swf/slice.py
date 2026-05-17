"""Signed slices + RFC 6962 binary merkle root.

A *slice* is a batch of IndexEntry commitments that a peer publishes in
a signed, hash-chained sequence. Any receiver can:

  1. Verify the slice was published by the pinned peer (Ed25519 sig).
  2. Verify the slice's merkle root over its entries (RFC 6962 binary).
  3. Verify any single entry against the root with an O(log n) proof.
  4. Chain the current slice to the previous one via `prev_hash`, so a
     peer cannot rewrite history without the break being detectable.

Spec ref: INDREX.md section B (v0 authenticity composition). Escalation
from here goes Sigstore-style transparency log (v1 → 0.7+) and Noise KK
transport (v2 → 0.7).

Wire format for a slice JSON object (canonical when signed):

    {
      "author":    "<ed25519 pubkey, b64url>",
      "seq":       <monotonic integer, starts at 0>,
      "ts":        "<ISO 8601 UTC, seconds precision>",
      "prev_hash": "<sha256 b64url of prior slice's canonical JSON, '' for seq=0>",
      "entries":   [{"url": ..., "content_hash": "...", "extractor": "...",
                     "fetched_at": "...", "final_url": "..."}, ...],
      "merkle_root": "<sha256 b64url of RFC-6962 binary merkle over entry hashes>",
      "sig":       "<Ed25519 signature, b64url>"
    }

The signature covers everything EXCEPT `sig` itself. Canonical JSON is
`json.dumps(..., sort_keys=True, separators=(",", ":"))`.

RFC 6962 binary merkle (leaf = sha256(0x00 || bytes);
internal = sha256(0x01 || L || R)) is the same scheme as Certificate
Transparency and Rekor. Odd-last-leaf: promote as-is at each level.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# ── Helpers ──────────────────────────────────────────────────────────────


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_b64(b: bytes) -> str:
    return _b64url_encode(hashlib.sha256(b).digest())


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


# ── Entry serialization ──────────────────────────────────────────────────


def entry_leaf_bytes(entry: dict) -> bytes:
    """Stable leaf bytes for a single IndexEntry.

    The canonical-JSON-of-the-entry gets hashed with the RFC 6962 leaf
    prefix (0x00). Keeping the hash function out of this helper keeps
    the two-step (serialize → hash) auditable.
    """
    return canonical_json(
        {
            "url": entry.get("url") or "",
            "content_hash": entry.get("content_hash") or "",
            "extractor": entry.get("extractor") or "",
            "fetched_at": entry.get("fetched_at") or "",
            "final_url": entry.get("final_url") or "",
        }
    )


# ── RFC 6962 binary merkle ──────────────────────────────────────────────


def _leaf_hash(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x00")
    h.update(data)
    return h.digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(b"\x01")
    h.update(left)
    h.update(right)
    return h.digest()


def _largest_pow2_lt(n: int) -> int:
    """Largest k = 2^a such that k < n, for n > 1."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """MTH(D[n]) per RFC 6962 section 2.1. `leaves` are already
    leaf-hashed (via `_leaf_hash`). Returns the merkle tree hash."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_pow2_lt(n)
    left = _mth(leaves[:k])
    right = _mth(leaves[k:])
    return _node_hash(left, right)


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 merkle root over a list of already-hashed leaves.

    Empty list → sha256("") per RFC 6962 section 2.1.
    """
    return _mth(leaves)


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]) per RFC 6962 section 2.1.1. Audit path for
    leaf at index `m` in `leaves`. Returns sibling hashes from leaf
    to root.
    """
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_pow2_lt(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    """Audit path per RFC 6962 section 2.1.1. `leaves` already hashed."""
    if not leaves:
        raise ValueError("cannot build inclusion proof over empty leaves")
    if not (0 <= index < len(leaves)):
        raise IndexError(f"index {index} out of range for {len(leaves)} leaves")
    return _path(index, leaves)


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes
) -> bool:
    """Verify an RFC 6962 inclusion proof. Algorithm per RFC 6962
    section 2.1.1 "PATH", inverted for verification.
    """
    if not (0 <= index < tree_size):
        return False
    fn = index
    sn = tree_size - 1
    r = leaf
    p_iter = iter(proof)
    while sn > 0:
        if fn % 2 == 1 or fn == sn:
            try:
                sibling = next(p_iter)
            except StopIteration:
                return False
            if fn == sn:
                # Walk up to the parent level without branching; the sibling
                # at this step came from the left of the subtree split.
                r = _node_hash(sibling, r)
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
            else:
                r = _node_hash(sibling, r)
        else:
            try:
                sibling = next(p_iter)
            except StopIteration:
                return False
            r = _node_hash(r, sibling)
        fn //= 2
        sn //= 2
    # All proof elements must have been consumed
    if any(True for _ in p_iter):
        return False
    return r == root


# ── Slice construction + verification ────────────────────────────────────


@dataclass
class Slice:
    author: str
    seq: int
    ts: str
    prev_hash: str
    entries: list[dict]
    merkle_root: str
    sig: str = ""

    def to_dict(self, *, include_sig: bool) -> dict:
        out = {
            "author": self.author,
            "seq": self.seq,
            "ts": self.ts,
            "prev_hash": self.prev_hash,
            "entries": self.entries,
            "merkle_root": self.merkle_root,
        }
        if include_sig:
            out["sig"] = self.sig
        return out

    def canonical(self) -> bytes:
        """Canonical bytes for signing (sig excluded)."""
        return canonical_json(self.to_dict(include_sig=False))

    def content_hash(self) -> str:
        """Hash of the FULL slice including sig. Used as `prev_hash` input
        for the next slice in the chain."""
        return sha256_b64(canonical_json(self.to_dict(include_sig=True)))


def build_slice(
    author_pubkey_b64: str,
    seq: int,
    prev_hash: str,
    entries: list[dict],
    identity,  # swf.identity.Identity, passed in to avoid circular import
    ts: str | None = None,
) -> Slice:
    """Build a signed slice. `entries` should be dicts with url,
    content_hash, extractor, fetched_at, final_url. Extra keys are
    ignored (only the canonical fields participate in the merkle root).
    """
    ts = ts or _now_iso()
    leaves = [_leaf_hash(entry_leaf_bytes(e)) for e in entries]
    root = _b64url_encode(merkle_root(leaves))
    s = Slice(
        author=author_pubkey_b64,
        seq=seq,
        ts=ts,
        prev_hash=prev_hash or "",
        entries=list(entries),
        merkle_root=root,
        sig="",
    )
    s.sig = identity.sign_b64(s.canonical())
    return s


def verify_slice(
    slice_obj: Slice | dict,
    expected_author_pubkey: str | None = None,
    expected_prev_hash: str | None = None,
) -> tuple[bool, str]:
    """Verify a slice's signature, merkle root, and optionally chain link.

    Returns (ok, reason). `reason` is non-empty on failure.
    """
    if isinstance(slice_obj, dict):
        try:
            s = Slice(
                author=slice_obj["author"],
                seq=int(slice_obj["seq"]),
                ts=slice_obj["ts"],
                prev_hash=slice_obj.get("prev_hash", ""),
                entries=list(slice_obj.get("entries", [])),
                merkle_root=slice_obj["merkle_root"],
                sig=slice_obj.get("sig", ""),
            )
        except Exception as exc:
            return False, f"slice missing required fields: {exc}"
    else:
        s = slice_obj

    if expected_author_pubkey and s.author != expected_author_pubkey:
        return False, f"author mismatch: expected {expected_author_pubkey[:16]}… got {s.author[:16]}…"

    if expected_prev_hash is not None and s.prev_hash != expected_prev_hash:
        return False, f"prev_hash mismatch (chain break): expected {expected_prev_hash} got {s.prev_hash}"

    # Recompute merkle root
    leaves = [_leaf_hash(entry_leaf_bytes(e)) for e in s.entries]
    got_root = _b64url_encode(merkle_root(leaves))
    if got_root != s.merkle_root:
        return False, f"merkle root mismatch: computed {got_root}, claimed {s.merkle_root}"

    # Verify signature
    from swf.identity import verify

    if not s.sig:
        return False, "slice has no signature"
    if not verify(s.author, s.canonical(), s.sig):
        return False, "signature verification failed"

    return True, ""
