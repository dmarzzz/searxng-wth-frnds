# Operating swf-node

Running on a NAS, a server, behind NAT, behind a reverse proxy, on
Tailscale. The README covers the laptop-quickstart path; this doc is
for the rest.

## State on disk

| Path | Owner | What lives there |
|---|---|---|
| `~/.config/swf/identity.key` | mode 0600 | Ed25519 private key. The daemon enforces 0600 on creation; rotating breaks every TOFU peer trust until they re-add. |
| `~/.config/swf/identity.pub` | mode 0644 | Ed25519 public key (mirror of `identity.key`'s public part). |
| `~/.config/swf/cache_secret.bin` | mode 0600 | HMAC secret for the search-results cache. |
| `~/.config/swf/peers.yaml` | mode 0644 | Hand-pinned peers, written by `swf-peer add`. |
| `~/.config/swf/community.yaml` | mode 0644 | Aggregator-mode push config (`--full`). |
| `~/.config/swf/config.toml` | mode 0644 | Reference skeleton written by `swf-node init`; not read by the daemon. |
| `~/.local/share/swf/search_cache.db` | sqlite | LOCAL_CACHE FTS5 + per-row HMAC. |
| `~/.local/share/swf/reputation.db` | sqlite | Per-provider reputation scores. |
| `~/.local/share/swf/tickets.sqlite` | sqlite | Anonymous-ticket nullifiers (only with `SWF_ENABLE_TICKETS=1`). |
| `~/world_knowledge/index.db` | sqlite | FTS5 indrex (pages + pages_meta + page_cids + search_results + events + peers + swf_kv). |
| `~/world_knowledge/web/<host>/<date>-<slug>.md` | markdown | Markdown archive (one file per fetched page). |

All paths overridable via `SWF_CONFIG_DIR`, `SWF_STATE_DIR`,
`SWF_KNOWLEDGE_DIR`. The daemon creates them lazily; nothing requires
pre-creation.

## Running on a NAS / homeserver

Persistent process, foreground or background:

```bash
SWF_BIND=0.0.0.0 swf-node                 # foreground
nohup swf-node > /var/log/swf-node.log 2>&1 &   # detached, simple
```

Or use the systemd unit (`examples/systemd/swf-node.service`):

```bash
mkdir -p ~/.config/systemd/user
cp examples/systemd/swf-node.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now swf-node.service
loginctl enable-linger $USER              # survive logout
journalctl --user -u swf-node -f          # tail logs
```

## Behind NAT / off-LAN peering

mDNS only crosses one broadcast domain — guest Wi-Fi, AP client
isolation, and VLANs all stop it. Two supported escape hatches:

**Tailscale (recommended).** swf-node calls `tailscale status --json`
on every discovery cycle. Peers in the same tailnet get auto-detected
without any peers.yaml entry. No env var; just have `tailscale` on
PATH and be logged in.

**Manual hand-pinning.** When you can reach a peer over a known
hostname or IP (Wireguard, ZeroTier, SSH tunnel), use:

```bash
swf-peer add alice http://alice.tail-scale-net.ts.net:7777
swf-peer health
```

This writes to `peers.yaml`. The pubkey is TOFU-pinned on first
contact; rotation invalidates trust.

## Reverse proxy

For public exposure (TLS termination, rate limiting, ACL), put
something in front. The daemon has no built-in TLS.

**Caddy** (`examples/caddy/Caddyfile`):

```bash
SWF_AGENT_TOKEN=<your-token> caddy run --config examples/caddy/Caddyfile
```

The Caddyfile splits peer routes (Ed25519-signed; pass through) from
agent routes (`/web_search`, `/fetch_url`, `/fetch_urls`,
`/local_search` — require `Authorization: Bearer <token>`).
Unmatched paths return 404 (default-deny for `/admin/*` etc.).

**nginx** (`examples/nginx/swf-node.conf`): same posture, but the
bearer has to be templated in at deploy time via envsubst because
nginx doesn't read env vars at request time.

Set the same `SWF_AGENT_TOKEN` on both swf-node and the proxy. The
daemon checks the bearer in constant time when bind is non-loopback.

## Network requirements

- TCP 7777 (or `SWF_PORT`) inbound from the LAN.
- UDP 5353 (mDNS) inbound + outbound on the LAN broadcast domain. If
  you have a Linux firewall, `iptables` or `nftables` rules are needed:
  ```
  iptables -A INPUT  -p udp --dport 5353 -j ACCEPT
  iptables -A OUTPUT -p udp --dport 5353 -j ACCEPT
  ```
  macOS allows mDNS by default; no action needed. On **Windows**, the
  first time swf-node binds with a non-loopback bind (LAN-peer shape),
  Windows Defender Firewall will prompt for an inbound rule on the
  swf-node binary — pick **Allow** for *Private* networks (the home/work
  LAN profile); declining or allowing only *Public* leaves the daemon
  reachable to nobody. Embedding hosts (e.g. the Shape Rotator OS
  Electron app) that want to skip the prompt can pre-create the rule
  via `New-NetFirewallRule` (TCP `SWF_PORT` + UDP 5353, profile
  `Private`); see the Windows-specific firewall snippet in
  [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md#windows-firewall).
- Optional: outbound HTTP to `SEARXNG_URL`, outbound DNS, outbound
  HTTPS to whatever URLs `/fetch_url` is called on.

## Identity rotation

```bash
swf-node init --force
```

This deletes `identity.key` and generates a new one. Consequences:

- Every peer that has you in their `peers.yaml` will see the next
  `/.well-known/indrex` doc come back with a different `pubkey`. Their
  `swf-peer health` will report the mismatch.
- Bundles you ship under the new key won't verify against the old TOFU
  pin. Peers must `swf-peer remove <oldname> && swf-peer add <newname>`.
- `peers.yaml` and `world_knowledge/index.db` are unaffected.

Rotate when:

- The `identity.key` file leaked (any unauthorized read).
- You're moving to a new physical machine and want a clean break.

Don't rotate "to be safe" — peer-trust churn is a real cost.

## State backup / restore

`world_knowledge/` is plain markdown + SQLite. Everything else is
recoverable.

```bash
# back up
tar czf swf-state.tar.gz \
    ~/.config/swf \
    ~/.local/share/swf \
    ~/world_knowledge

# restore
tar xzf swf-state.tar.gz -C /
```

The migration system is additive-only (`swf-node migrate` after a
restore is harmless and verifies the schema is current).

## Upgrading

```bash
pipx upgrade swf-node                      # operators
git pull && pip install -e .               # from-source
swf-node migrate                           # verify schema is current
swf-node --check                           # smoke
```

If you upgrade across a major version, expect peers running the older
version to be unable to verify your bundles. The protocol version is
encoded in the mDNS TXT record's `proto` field; a mismatch shows up
in `swf-peer discover` output.

## Multi-peer demo on one machine

```bash
make demo-2-peers
# or directly:
bash scripts/demo-2-peers.sh
```

Each peer gets its own `SWF_CONFIG_DIR`, `SWF_KNOWLEDGE_DIR`, port,
and `SWF_NODE_NAME`. They're hand-pinned via `swf-peer add` because
mDNS on loopback is flaky (two registrations on the same hostname
confuse the browser).

## Common signals to watch

- **`peer_pull_completed` events** in the SSE stream — each peer pull
  fires one. `stored=0` means the peer has nothing new (or nothing
  shareable); `stored>0` means real ingest.
- **`/metrics/snapshot` `peers.count_active`** — peers seen within the
  liveness window.
- **`/metrics/snapshot` `process.num_fds`** — slow upward drift here is
  an FD leak; sudden spike usually means a misbehaving local client
  (RST flood from a tooling probe).
- **`/.well-known/indrex` `stats.pages`** — your local indrex size. If
  this is ticking up but `peers.count_active` stays at 0, you're
  generating content but no one is pulling it.

See `docs/TROUBLESHOOTING.md` for symptom → likely cause → command
mappings.
