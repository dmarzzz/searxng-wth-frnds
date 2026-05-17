"""IPFS-compatible CIDv1 over cleaned content.

Produces the same CID that ``ipfs add --raw-leaves --cid-version=1`` produces
for a single chunk under 256 KiB. Implementation is stdlib-only — no
multiformats / multihash dependency.

Format (decoded):
    0x01     CID version (CIDv1)
    0x55     codec: raw
    0x12     multihash code: sha2-256
    0x20     digest length: 32 bytes
    <32 bytes of sha256(content)>

Encoded as multibase 'b' (base32 lowercase, no padding) → strings like
"bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy".

For content larger than ~256 KiB, real IPFS would build a UnixFS DAG; we
don't need that here. Single-chunk raw is fine for cleaned-text articles
(typically a few KB to ~50 KB).
"""

from __future__ import annotations

import hashlib

_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def _b32_lower(data: bytes) -> str:
    """RFC 4648 base32 lowercase, no padding (multibase 'b')."""
    out: list[str] = []
    bit_buf = 0
    bits = 0
    for byte in data:
        bit_buf = (bit_buf << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_BASE32_ALPHABET[(bit_buf >> bits) & 0x1F])
    if bits > 0:
        out.append(_BASE32_ALPHABET[(bit_buf << (5 - bits)) & 0x1F])
    return "".join(out)


def cid_for_content(content: str | bytes) -> str:
    """Compute the CIDv1 (raw, sha256) of the given content.

    Strings are encoded as UTF-8 first. Returns a multibase-b string
    starting with "bafkrei…".
    """
    if isinstance(content, str):
        data = content.encode("utf-8")
    else:
        data = content
    digest = hashlib.sha256(data).digest()
    # CIDv1 prefix + sha256 multihash
    cid_bytes = b"\x01\x55\x12\x20" + digest
    return "b" + _b32_lower(cid_bytes)


def looks_like_cid(s: str | None) -> bool:
    """Cheap shape check. Real validation isn't needed in v0; the column is
    informational and not used to fetch anything yet."""
    return bool(s) and isinstance(s, str) and s.startswith("bafkrei") and len(s) >= 50


# ── self-test ─────────────────────────────────────────────────────────────────
# Verified against `ipfs add --cid-version=1 --raw-leaves`:
#   echo -n "" | ipfs add --raw-leaves --cid-version=1 -Q
#     → bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku
#   echo -n "hello world" | ipfs add --raw-leaves --cid-version=1 -Q
#     → bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e

if __name__ == "__main__":
    cases = [
        ("",            "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"),
        ("hello world", "bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e"),
    ]
    for content, expected in cases:
        got = cid_for_content(content)
        ok = "✓" if got == expected else "✗"
        print(f"  {ok}  {content!r:20}  → {got}  (expected {expected})")
        assert got == expected, f"CID mismatch for {content!r}: got {got}, want {expected}"
    print("OK — CIDs match `ipfs add --raw-leaves --cid-version=1`.")
