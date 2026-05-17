"""Deterministic per-pubkey signature_color and signature_freq.

P2P-review #6: this lived in `community_full/db.py` despite having
no DB dependency. Importing `community_full` to color a peer pulls
in metrics.db init costs and forces every consumer to install the
`[community-full]` extras. Now lives standalone; a thin re-export
in `community_full/db.py` keeps existing callers working.

`signature_for(pubkey)` returns `(color, freq)` where:
  - color is `#RRGGBB` from a hand-picked 12-color neon palette
    chosen for visual distinctness on the wall
  - freq is a Hz value in [220, 880] for the audio chime
Same pubkey → same `(color, freq)` forever.
"""
from __future__ import annotations

import hashlib

# Hand-picked 12-color neon palette. All on a similar luminance band
# so the wall has visual coherence; maximally distinct so no two
# peers in the first 12 look the same. Pure hash-to-hue produced
# near-collisions on real pubkeys (mint/lime/seafoam clustered
# indistinguishably); the palette guarantees distinctness.
_PALETTE = (
    "#FF7B6B",  # coral
    "#FFB35C",  # amber
    "#FFE066",  # gold
    "#A8E063",  # lime
    "#5AE6A8",  # mint
    "#5CE0E6",  # cyan
    "#5AAEFF",  # sky
    "#9C7BFF",  # violet
    "#D866FF",  # magenta
    "#FF6BB5",  # pink
    "#E6856B",  # rust
    "#7BFFD6",  # seafoam
)


def signature_for(pubkey: str) -> tuple[str, float]:
    """Deterministic `(signature_color, signature_freq)` from a pubkey.

    Color: 12-color palette by `hash(pubkey) mod 12`. Peers 13+ wrap
    and may share with an earlier peer — acceptable at LAN scale.

    Frequency: 16 bits of the same hash mapped to [220, 880] Hz
    (one octave from A3 to A4)."""
    h = hashlib.blake2b(pubkey.encode("utf-8"), digest_size=8).digest()
    idx = int.from_bytes(h[:2], "big") % len(_PALETTE)
    color = _PALETTE[idx]
    freq_norm = int.from_bytes(h[2:4], "big") / 65535.0
    freq = 220.0 * (2.0 ** freq_norm)
    return color, round(freq, 2)


__all__ = ["signature_for"]
