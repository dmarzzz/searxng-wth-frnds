# Security policy

## Supported versions

`swf-node` is in an alpha (0.x) phase — the latest minor release is
the only version that receives security fixes. Pin to `>=0.8` if you
need anything resembling a stability promise.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-relevant
findings. Instead, email **dmarz** at the address listed on the GitHub
profile (`github.com/dmarzzz`), with subject prefix `swf-node SECURITY:`.

Expected response timeline:

- **Within 72 hours** — acknowledgement that the report was received.
- **Within 14 days** — initial assessment + planned mitigation path.
- **Within 90 days** — fix released or, if the issue is out-of-scope,
  a written explanation. Coordinated disclosure preferred.

If you do not hear back within 72 hours, you are welcome to escalate
publicly — the silence itself is a defect we want fixed.

## Threat model

The full threat model lives at [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
Summary of what is and is not in scope:

**In scope:**
- Silent public-egress downgrade — a private query routed to a public
  search engine without explicit user consent.
- Provenance confusion — a peer's bundle being mis-attributed to the
  local user, or vice versa.
- DC-net requester unmasking — recovery of the original requester
  inside an anonymous-ticket peer search.
- Identity-key leakage from `~/.config/swf/identity.key`.
- Peer-bundle signature forgery / replay.

**Out of scope:**
- Host compromise (local code execution, root access). If the host is
  rooted, swf-node's identity and DB are gone — that's the OS's job to
  protect, not ours.
- Malicious LAN-majority attacks. The peer-trust model is TOFU per
  pubkey; if a majority of your LAN peers are hostile, you have a
  bigger problem than swf-node.
- Traffic analysis from a network observer. swf-node does not (yet)
  defend against an adversary watching packet sizes or timings.
- Denial-of-service from a single LAN peer. PR #62 added scoring +
  pruning, but a peer that can saturate your link will saturate your
  link.

## Hardening guidance

- Keep `~/.config/swf/identity.key` at mode `0600`. The daemon enforces
  this on creation; `swf-node doctor` (PR #69) verifies it.
- Set `SWF_BIND=127.0.0.1` (the default) unless you intend to expose
  the daemon to other hosts. When binding non-loopback, also set
  `SWF_AGENT_TOKEN` for the privileged routes.
- Run a reverse proxy (`examples/caddy/`, `examples/nginx/` — PR #70)
  if you expose the node beyond your trusted LAN. swf-node has no
  built-in TLS, no rate limiting, and no per-peer ACL.
- Use Tailscale or another overlay network for off-LAN peering. The
  built-in `detect_tailscale_peers` integration is the supported path.
