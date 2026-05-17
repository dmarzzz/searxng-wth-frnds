"""URL-membership bloom filter with per-recipient salting.

Used for: "does friend X have URL Y already?" probes. Lets us skip
a round-trip to a friend when their filter says no, and lets a friend
skip shipping a URL we already have when their receiver's filter says
yes.

Per-recipient salting is mandatory per INDREX section A (Naor-Yogev 2015:
unsalted filters are adversarially enumerable). Each recipient gets a
different filter keyed on `blake2b(url, recipient_pubkey, circle_secret)`.

v0.5 ships a classic Bloom filter (zero-dep, easy to verify). The spec
targets Binary Fuse8 as the long-term choice for size/FP efficiency; swap
is a localized change inside `build_filter` / `test_filter` when we ship
a pure-Python fuse implementation. See INDREX.md section A.

Public surface:
    - build_filter(urls, recipient_pubkey_b64, circle_secret=None,
                   target_fp=0.01) -> bytes
    - contains(blob, url, recipient_pubkey_b64, circle_secret=None) -> bool
    - filter_stats(blob) -> dict
"""

from __future__ import annotations

import contextlib
import hashlib
import math
import os
import struct
from collections.abc import Iterable

# Header layout:
#   magic (4B)  = b"SWF1"
#   version (1B) = 1
#   k_hashes (1B)
#   m_bits (4B, big-endian)
#   n_items (4B, big-endian)
#   salt (32B, the per-recipient salt; kept with the filter so a
#        recipient's cache can reject a filter built for someone else)
#   bitarray (m_bits/8 bytes, rounded up)
_HEADER_LEN = 4 + 1 + 1 + 4 + 4 + 32
_MAGIC = b"SWF1"


def _size_and_k(n: int, fp: float) -> tuple[int, int]:
    """Standard bloom sizing: m = -n*ln(p) / (ln2)^2, k = (m/n)*ln2."""
    n = max(1, n)
    fp = max(1e-9, min(0.5, fp))
    m = -n * math.log(fp) / (math.log(2) ** 2)
    m = max(64, int(math.ceil(m)))
    # Round up to byte boundary.
    m = ((m + 7) // 8) * 8
    k = max(1, int(round((m / n) * math.log(2))))
    # Clamp k to 1 byte (we only have 1 byte in the header for it).
    k = min(k, 255)
    return m, k


def _derive_salt(recipient_pubkey_b64: str, circle_secret: bytes | None) -> bytes:
    """Per-recipient salt. Using blake2b with the pubkey as the personalizer
    keeps the salt deterministic (so sender+receiver derive the same one)
    without storing it anywhere. `circle_secret`, if set, is an extra
    secret only members of the trust circle know."""
    h = hashlib.blake2b(digest_size=32, salt=b"swf-digest-salt"[:16])
    h.update((recipient_pubkey_b64 or "").encode("utf-8"))
    if circle_secret:
        h.update(b"\xff")
        h.update(circle_secret)
    return h.digest()


def _hash_indices(url: str, k: int, m_bits: int, salt: bytes) -> list[int]:
    """k independent hashes over `url` in [0, m_bits). Uses double-hashing
    (Kirsch-Mitzenmacher 2008) to get k indices from two blake2b calls."""
    h1 = hashlib.blake2b(digest_size=16, key=salt[:16])
    h1.update(b"1|")
    h1.update(url.encode("utf-8"))
    h1_int = int.from_bytes(h1.digest(), "big")

    h2 = hashlib.blake2b(digest_size=16, key=salt[16:32])
    h2.update(b"2|")
    h2.update(url.encode("utf-8"))
    h2_int = int.from_bytes(h2.digest(), "big")

    return [((h1_int + i * h2_int) % m_bits) for i in range(k)]


def build_filter(
    urls: Iterable[str],
    recipient_pubkey_b64: str,
    circle_secret: bytes | None = None,
    target_fp: float = 0.01,
) -> bytes:
    """Build a bloom filter over the given URLs, salted for a specific
    recipient. Returns opaque bytes with the header `test_filter` expects.

    Empty url set is valid (returns a header-only filter with m=64 bits,
    n=0). Duplicates are counted only once.
    """
    urls = list({u for u in urls if isinstance(u, str) and u})
    n = len(urls)
    m_bits, k = _size_and_k(n, target_fp)
    salt = _derive_salt(recipient_pubkey_b64, circle_secret)

    nbytes = m_bits // 8
    bitarray = bytearray(nbytes)
    for u in urls:
        for idx in _hash_indices(u, k, m_bits, salt):
            byte = idx >> 3
            bit = idx & 7
            bitarray[byte] |= 1 << bit

    header = (
        _MAGIC
        + bytes([1, k])
        + struct.pack(">II", m_bits, n)
        + salt
    )
    assert len(header) == _HEADER_LEN
    return bytes(header + bitarray)


def _unpack_header(blob: bytes) -> tuple[int, int, int, bytes]:
    if len(blob) < _HEADER_LEN:
        raise ValueError("filter too short")
    if blob[:4] != _MAGIC:
        raise ValueError(f"bad magic {blob[:4]!r}")
    version = blob[4]
    if version != 1:
        raise ValueError(f"unknown digest version {version}")
    k = blob[5]
    m_bits, n_items = struct.unpack(">II", blob[6:14])
    salt = blob[14:46]
    return k, m_bits, n_items, salt


def contains(
    blob: bytes,
    url: str,
    recipient_pubkey_b64: str,
    circle_secret: bytes | None = None,
) -> bool:
    """Return True if `url` might be in the set (FP possible), False if
    definitely not.

    Will raise `ValueError` if this filter wasn't built for this
    (recipient, circle_secret) pair — the salt check catches filter
    misuse rather than silently returning garbage results.
    """
    k, m_bits, _n, salt = _unpack_header(blob)
    expected_salt = _derive_salt(recipient_pubkey_b64, circle_secret)
    if salt != expected_salt:
        raise ValueError(
            "filter salt mismatch: this filter was built for a different "
            "recipient or circle_secret"
        )
    bitarray = blob[_HEADER_LEN:]
    nbytes_expected = m_bits // 8
    if len(bitarray) != nbytes_expected:
        raise ValueError(
            f"filter truncated: header says {nbytes_expected} bytes, got {len(bitarray)}"
        )

    for idx in _hash_indices(url, k, m_bits, salt):
        byte = idx >> 3
        bit = idx & 7
        if not (bitarray[byte] & (1 << bit)):
            return False
    return True


def filter_stats(blob: bytes) -> dict:
    """Introspection for logs + diagnostics."""
    k, m_bits, n_items, salt = _unpack_header(blob)
    # Estimate actual FP from current fill.
    if len(blob) > _HEADER_LEN:
        filled = sum(bin(b).count("1") for b in blob[_HEADER_LEN:])
    else:
        filled = 0
    fill_ratio = filled / m_bits if m_bits else 0.0
    est_fp = fill_ratio ** k if k > 0 else 1.0
    return {
        "version": 1,
        "k": k,
        "m_bits": m_bits,
        "n_items": n_items,
        "fill_ratio": round(fill_ratio, 4),
        "estimated_fp": round(est_fp, 6),
        "salt_prefix": salt[:4].hex(),
        "total_bytes": len(blob),
    }


# ── Circle secret loading ──────────────────────────────────────────────────


def load_circle_secret() -> bytes | None:
    """Read `~/.config/swf/circle.secret` (32 bytes random). Returns None
    if absent; callers treat that as "no circle, omit from digest salt."

    Use `swf-peer secret init` to generate one per trust zone.
    """
    from pathlib import Path

    base = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    path = base / "circle.secret"
    if not path.exists():
        return None
    raw = path.read_bytes()
    if len(raw) == 32:
        return raw
    if len(raw) == 64:
        # hex encoded
        try:
            return bytes.fromhex(raw.decode().strip())
        except Exception:
            return None
    return None


def generate_circle_secret() -> bytes:
    """Generate a fresh 32-byte circle secret and write it to
    ~/.config/swf/circle.secret with mode 0600."""
    from pathlib import Path

    base = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    base.mkdir(parents=True, exist_ok=True)
    path = base / "circle.secret"
    secret = os.urandom(32)
    path.write_bytes(secret)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    return secret
