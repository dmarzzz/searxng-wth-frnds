"""`swf-peer` CLI: manage the peers list SearXNG's local_friends engine reads.

    swf-peer add alice http://alice.local:7777
    swf-peer add bob  swf://<pubkey>@host:port       # URI shorthand, 0.4+
    swf-peer list
    swf-peer remove alice
    swf-peer health
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from swf.peers import Peer, config_path, load_peers, save_peers


def _cmd_add(args: argparse.Namespace) -> int:
    cfg = load_peers()
    url = args.url.strip()

    # Accept `swf://<pubkey>@host:port` URI. Extracted pubkey is used as
    # the trust anchor (TOFU bypass: user already knows what to expect).
    pubkey = None
    if url.startswith("swf://"):
        parsed = urlparse(url)
        if parsed.username:
            pubkey = parsed.username
        host = parsed.hostname or ""
        port = parsed.port or 7777
        scheme = "http"  # 0.7 upgrades to Noise KK / swfs://
        url = f"{scheme}://{host}:{port}"

    if not url.startswith(("http://", "https://")):
        print(f"error: peer URL must start with http:// or https:// (got {url!r})", file=sys.stderr)
        return 2

    # TOFU: unless the user already handed us a pubkey via swf://, probe
    # the peer and record whatever they advertise. Later verification
    # against this pinned key catches key rotation or imposter attempts.
    probed_pk, fingerprint = _probe_pubkey(url)
    if pubkey is None and probed_pk:
        pubkey = probed_pk
        print(f"TOFU pinned pubkey from {url}: {fingerprint}")
    elif pubkey is not None and probed_pk and pubkey != probed_pk:
        print(
            f"warning: pubkey from URI disagrees with peer's advertisement.\n"
            f"  URI says:  {pubkey[:16]}…\n"
            f"  peer says: {probed_pk[:16]}…\n"
            f"keeping URI-supplied key. If this is unexpected, investigate.",
            file=sys.stderr,
        )

    others = [p for p in cfg.peers if p.name != args.name]
    others.append(Peer(name=args.name, url=url, pubkey=pubkey))
    cfg.peers = others
    path = save_peers(cfg)
    print(f"added/updated peer {args.name!r} → {url}")
    print(f"wrote {path}")
    if pubkey:
        print(f"  pubkey: {pubkey}")
    else:
        print("  (no pubkey captured; peer may not be running, or is pre-0.4)")
    return 0


def _probe_pubkey(url: str) -> tuple[str | None, str | None]:
    """Fetch /.well-known/indrex and return (pubkey_b64, fingerprint_hex).
    Verifies signature if present. Returns (None, None) on any failure."""
    import json
    import urllib.request

    try:
        req = urllib.request.Request(
            url.rstrip("/") + "/.well-known/indrex",
            headers={"User-Agent": "swf-peer/tofu", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            payload = json.loads(resp.read())
    except Exception:
        return None, None

    pk = payload.get("pubkey")
    if not pk:
        return None, None

    # Verify the peer actually holds the private key for the pubkey it
    # advertises. Without this, TOFU pins whatever a MITM put on the wire.
    sig = payload.get("sig")
    ts = payload.get("ts")
    body_hash = payload.get("body_hash")
    if sig and ts and body_hash:
        from swf.identity import canonical_indrex_response, verify

        canonical = canonical_indrex_response(
            pubkey_b64=pk,
            node=payload.get("name") or "",
            ts=ts,
            body_hash=body_hash,
        )
        if not verify(pk, canonical, sig):
            print(
                f"warning: peer at {url} failed signature verification "
                "(advertised pubkey does not match signature). NOT pinning.",
                file=sys.stderr,
            )
            return None, None

    from swf.identity import pubkey_fingerprint

    try:
        fp = pubkey_fingerprint(pk)
    except Exception:
        fp = None
    return pk, fp


def _cmd_remove(args: argparse.Namespace) -> int:
    cfg = load_peers()
    before = len(cfg.peers)
    cfg.peers = [p for p in cfg.peers if p.name != args.name]
    if len(cfg.peers) == before:
        print(f"peer {args.name!r} not found", file=sys.stderr)
        return 1
    path = save_peers(cfg)
    print(f"removed peer {args.name!r} ({path})")
    return 0


def _cmd_list(_args: argparse.Namespace) -> int:
    cfg = load_peers()
    if not cfg.peers:
        print(f"no peers configured (file: {config_path()})")
        return 0
    print(f"peers in {config_path()}:")
    for p in cfg.peers:
        pk = f"  pubkey={p.pubkey[:16]}…" if p.pubkey else ""
        print(f"  {p.name:<24}  {p.url}{pk}")
    return 0


def _cmd_health(_args: argparse.Namespace) -> int:
    import json
    import urllib.error
    import urllib.request

    cfg = load_peers()
    if not cfg.peers:
        print("no peers configured")
        return 0

    any_fail = False
    for p in cfg.peers:
        url = p.canonical() + "/.well-known/indrex"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "swf-peer-cli",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read())
            stats = data.get("stats") or {}
            print(
                f"  ✓ {p.name:<24} {p.url}  "
                f"v{data.get('version','?')}  "
                f"pages={stats.get('pages','?')} "
                f"cache={stats.get('cached_urls','?')}"
            )
        except Exception as exc:
            any_fail = True
            print(f"  ✗ {p.name:<24} {p.url}  {type(exc).__name__}: {exc}")
    return 1 if any_fail else 0


def main() -> int:
    # #79: bootstrap stdlib logging so any swf.* modules called from
    # the peer-CLI subcommands (peers / discovery / digest helpers)
    # surface log output through the configured handler. Idempotent.
    from swf._logging import bootstrap as _log_bootstrap
    _log_bootstrap()

    parser = argparse.ArgumentParser(
        prog="swf-peer",
        description="Manage the peers.yaml the local_friends engine reads.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Add or update a peer")
    p_add.add_argument("name")
    p_add.add_argument("url", help="Peer URL (http://... or swf://pubkey@host:port)")
    p_add.set_defaults(func=_cmd_add)

    p_rm = sub.add_parser("remove", help="Remove a peer by name")
    p_rm.add_argument("name")
    p_rm.set_defaults(func=_cmd_remove)

    p_ls = sub.add_parser("list", help="List configured peers")
    p_ls.set_defaults(func=_cmd_list)

    p_health = sub.add_parser(
        "health", help="Probe each peer's /.well-known/indrex endpoint"
    )
    p_health.set_defaults(func=_cmd_health)

    p_discover = sub.add_parser(
        "discover",
        help="Find peers via mDNS + Tailscale without adding them to peers.yaml",
    )
    p_discover.set_defaults(func=_cmd_discover)

    p_sync = sub.add_parser(
        "sync",
        help="Discover + append new peers to peers.yaml (hand-added entries preserved).",
    )
    p_sync.set_defaults(func=_cmd_sync)

    p_secret = sub.add_parser(
        "secret",
        help="Manage the circle secret (shared symmetric key for the trust zone).",
    )
    p_secret_sub = p_secret.add_subparsers(dest="secret_cmd", required=True)
    p_secret_init = p_secret_sub.add_parser(
        "init", help="Generate a new circle secret (warns before overwriting)."
    )
    p_secret_init.add_argument("--force", action="store_true", help="Overwrite existing secret.")
    p_secret_init.set_defaults(func=_cmd_secret_init)
    p_secret_show = p_secret_sub.add_parser(
        "show", help="Print the circle secret as base64 (for sharing via a secure channel)."
    )
    p_secret_show.set_defaults(func=_cmd_secret_show)
    p_secret_import = p_secret_sub.add_parser(
        "import", help="Install a circle secret from stdin (base64). Use when a friend sends you one."
    )
    p_secret_import.set_defaults(func=_cmd_secret_import)

    p_identity = sub.add_parser(
        "identity",
        help="Show this node's Ed25519 pubkey and fingerprint.",
    )
    p_identity.set_defaults(func=_cmd_identity)

    p_publish = sub.add_parser(
        "publish",
        help="Build a signed slice from new search_results, publish to ~/.config/swf/slices/.",
    )
    p_publish.set_defaults(func=_cmd_publish)

    p_sync_content = sub.add_parser(
        "sync-content",
        help="Pull signed slices from peers, verify, merge entries into local indrex.",
    )
    p_sync_content.set_defaults(func=_cmd_sync_content)

    args = parser.parse_args()
    return args.func(args)


def _cmd_publish(_args: argparse.Namespace) -> int:
    from swf.slice_publish import publish

    outcome = publish()
    if outcome.skipped:
        print(f"no slice published: {outcome.reason}")
        return 0
    print(
        f"published slice seq={outcome.seq} · {outcome.entries} entries → {outcome.path}"
    )
    return 0


def _cmd_sync_content(_args: argparse.Namespace) -> int:
    from swf.slice_consume import sync_all_peers

    outcomes = sync_all_peers()
    if not outcomes:
        print("no peers configured; nothing to sync")
        return 0
    any_fail = False
    for o in outcomes:
        if o.error:
            any_fail = True
            print(f"  ✗ {o.peer:<24} {o.error}")
        elif o.pulled == 0:
            print(f"  ✓ {o.peer:<24} up-to-date at seq={o.head_seq}")
        else:
            print(
                f"  ✓ {o.peer:<24} pulled={o.pulled} verified={o.verified} "
                f"merged={o.merged} → head_seq={o.head_seq}"
            )
    return 1 if any_fail else 0


def _cmd_secret_init(args: argparse.Namespace) -> int:
    from swf.digest import generate_circle_secret, load_circle_secret

    if load_circle_secret() is not None and not args.force:
        print(
            "error: circle secret already exists at ~/.config/swf/circle.secret\n"
            "  use `--force` to overwrite (DANGEROUS: invalidates digests with all peers)",
            file=sys.stderr,
        )
        return 1
    secret = generate_circle_secret()
    import base64

    print("generated 32-byte circle secret")
    print("share this with trust-zone members via a secure channel:")
    print()
    print(f"  {base64.urlsafe_b64encode(secret).rstrip(b'=').decode()}")
    print()
    print("on each friend's machine: `swf-peer secret import` and paste the above.")
    return 0


def _cmd_secret_show(_args: argparse.Namespace) -> int:
    import base64

    from swf.digest import load_circle_secret

    secret = load_circle_secret()
    if secret is None:
        print("no circle secret set (run `swf-peer secret init`)", file=sys.stderr)
        return 1
    print(base64.urlsafe_b64encode(secret).rstrip(b"=").decode())
    return 0


def _cmd_secret_import(_args: argparse.Namespace) -> int:
    import base64
    import contextlib
    import os
    import sys as _sys
    from pathlib import Path

    b64 = _sys.stdin.read().strip()
    if not b64:
        print("error: expected base64 circle secret on stdin", file=_sys.stderr)
        return 2
    try:
        padding = "=" * (-len(b64) % 4)
        raw = base64.urlsafe_b64decode(b64 + padding)
    except Exception as exc:
        print(f"error: not valid base64 ({exc})", file=_sys.stderr)
        return 2
    if len(raw) != 32:
        print(f"error: secret must be 32 bytes (got {len(raw)})", file=_sys.stderr)
        return 2
    base = Path(os.environ.get("SWF_CONFIG_DIR", Path.home() / ".config" / "swf"))
    base.mkdir(parents=True, exist_ok=True)
    path = base / "circle.secret"
    path.write_bytes(raw)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)
    print(f"wrote {path} (mode 0600)")
    return 0


def _cmd_identity(_args: argparse.Namespace) -> int:
    from swf.identity import get_or_create_identity

    ident = get_or_create_identity()
    print(f"pubkey:      {ident.pub_b64}")
    print(f"fingerprint: {ident.fingerprint()}")
    return 0


def _cmd_discover(_args: argparse.Namespace) -> int:
    from swf.discovery import discover_all_peers

    peers = discover_all_peers()
    if not peers:
        print("no peers discovered (mDNS returned nothing, Tailscale not running or empty)")
        return 0
    print(f"discovered {len(peers)} peer(s):")
    for p in peers:
        pk = f"  pubkey={p.pubkey[:16]}…" if p.pubkey else ""
        print(f"  [{p.source:<9}] {p.name:<24} {p.url}{pk}")
    print()
    print("use `swf-peer add <name> <url>` to pin any of these in peers.yaml")
    return 0


def _cmd_sync(args: argparse.Namespace) -> int:
    """Discover via mDNS + Tailscale and merge findings into peers.yaml.

    Does NOT overwrite hand-added peers (matched by URL). New discoveries
    are added with `auto-<source>-<name>` naming so you can see which
    are automatic and prune them at will.
    """
    from swf.discovery import discover_all_peers

    cfg = load_peers()
    known_urls = {p.canonical() for p in cfg.peers}
    discovered = discover_all_peers()

    added = 0
    for dp in discovered:
        if dp.source == "config":
            continue
        if dp.url.rstrip("/") in known_urls:
            continue
        auto_name = f"auto-{dp.source}-{dp.name}"
        # Avoid name collisions
        base_name = auto_name
        n = 2
        while any(p.name == auto_name for p in cfg.peers):
            auto_name = f"{base_name}-{n}"
            n += 1
        cfg.peers.append(Peer(name=auto_name, url=dp.url, pubkey=dp.pubkey))
        added += 1
        print(f"  + [{dp.source}] {auto_name} → {dp.url}")

    if added == 0:
        print("no new peers to add")
        return 0
    path = save_peers(cfg)
    print(f"\nwrote {path} ({added} new peer(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
