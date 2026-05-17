# TODO — searxng-wth-frnds

Pending work, sorted by urgency. Items below the line are explicitly *not* shipping soon — recorded so we don't re-debate them.

## next ship

### transport hardening (incremental)
- [ ] **adopt Noise handshake on TCP for peer-to-peer transport.** Replaces plaintext HTTP with encrypted+authenticated transport. Use `noiseprotocol` (Python, mature). Already in `INDREX.md` section B v2 escalation ladder.
  - ~80 lines
  - peer-server keeps its existing route surface; only the framing changes
  - same primitive voxterm uses (they get there via AES-GCM + HKDF; we'd use the standard Noise handshake)
  - leaves searxng's `local_friends` engine path on plain HTTP for the LAN-trust case; Noise kicks in when peers explicitly opt into it via a config flag

### content addressing
- [ ] **`GET /content/<cid>` on `swf-peer-server`.** When/if we want body sync, each peer answers "yes I have it / no I don't" by looking up `pages.content_cid` in their local indrex. No DHT needed at our N.
  - bodies come from `~/world_knowledge/web/<host>/...md` (we already write them)
  - ~30 lines on the peer-server side
  - paired client lookup goes in `swf-community-full` scraper or in the renderer

### scraper resilience
- [ ] **persist scraper cursors to disk.** Today the full node's `last_pulled_p` per peer is in-memory; on restart it re-pulls from `since_p=0` (idempotent thanks to `INSERT OR IGNORE`, but wastes a round-trip per peer). Persist to `community.db.kv` keyed by peer pubkey.
- [ ] **detect peer DB reset.** If a peer wipes their `~/world_knowledge/index.db` and starts fresh, their rowids reset to 1 but our cursor is at e.g. 500. We'd silently miss new pages until rowid catches up. Fix: include the peer's `(min_rowid, max_rowid)` in slice metadata; if the cursor is out of range, reset to 0.

### release

- [ ] **re-enable PyPI publish** — deferred for v0.8.0 (the `pypi` job was removed from `.github/workflows/release.yml`); re-add when there's actual third-party-package demand.

### naming / packaging — collapse to one binary

After this lands, the **agent-server vs peer-server distinction disappears as a primary axis of the architecture.** One binary, one port, one route surface; audience separation moves into the `source` arg on `/search` (see the route-surface item below). The remaining axis is `--client | --full`, which is a flag on the same binary.

- [ ] **`swf-peer-server` → `swf-node`** plus aliases for `swf-peer-server` / `swf-agent-server` that just forward (one deprecation cycle). One process, one mental model: "I run `swf-node`."
- [ ] **fold agent-server routes into the unified node.** Routes are uniform; auth is per-`source`-permission. Drops the dual-port surface and the agent-server module entirely.
- [ ] **fold `community-full` aggregator routes onto the same port.** Currently uvicorn on 7790 alongside ThreadingHTTPServer on 7777. Merge into one ThreadingHTTPServer (hand-roll SSE for `/events`).
- [ ] **collapse the route surface around `source`-as-argument.** Today the same word "search" is used for three different operations and the dual-server (peer-server + agent-server) split forces three URLs for what's really one operation. New shape:

    ```
    POST /search          { q, source: <str | list[str]>, limit? }
                          - source = "local"            → this node's indrex (no auth needed)
                          - source = "<peer_alias>"     → that peer's /search { source: "local" } (no auth)
                          - source = "google" | "ddg" | "nitter" | "<engine>"
                                                         → public engine (auth required)
                          - source = [list]             → fan out + merge across the list
                                                          (auth required if any item is non-local)
                          - source = "*"                → equivalent to /metasearch
    POST /metasearch      { q, limit? }
                          - convenience over source = "*"
                          - uses operator's configured source list
                          - auth required (some sources cost CPU / API quota)
    POST /fetch           { url, ... }                  → retrieve + persist + index (auth required)
    POST /fetch/batch     { urls, ... }                 → batch retrieve (auth required)
    ```

  This **eliminates the agent-server vs peer-server distinction.** Both audiences hit the same routes; what they're allowed to do depends on the `source` argument. A LAN peer's searxng asks `POST /search { q, source: "local" }` — no auth. The local agent asks `POST /metasearch { q }` — auth required because it costs me network/quota.

  Auth model: **per-source-class, not per-route.**
    - `source ∈ {"local", "<known peer alias>"}`            → no token required
    - any other source                                       → bearer-token required when bound non-loopback

  Source aliases for peers come from `peers.yaml` (operator-set via `swf-peer add alice http://…`) plus mDNS-discovered peers (auto-named from instance name or pubkey prefix).

  Searxng's `local_friends` engine adapter changes from `GET /search?q=X` to `POST /search { q: X, source: "local" }`. The old `GET /search?q=X` path is kept as a deprecated alias for one cycle with a `Deprecation` header.

  Old paths kept as aliases for one cycle:
    - `GET  /search?q=…`                  → equivalent to `POST /search { source: "local" }`
    - `POST /local_search`                → `POST /search { source: "local" }`
    - `POST /web_search`                  → `POST /metasearch`
    - `POST /fetch_url`                   → `POST /fetch`
    - `POST /fetch_urls`                  → `POST /fetch/batch`

  Validation rules for `source`:
    - dedup list values
    - reject unknown peer aliases / engine names with 400 + listing valid sources in the body
    - `"*"` is only valid as the sole value (not inside a list)
    - empty list = error
- [ ] **`backfill-cids` is not community-specific** — move it out of `swf-community` into a more general indrex-maintenance command (or expose as a flag on `swf-node` startup).

### MCP support (additive, not blocking)
- [ ] **`swf-node --mcp`** flag that exposes the route surface as a Model Context Protocol server (JSON-RPC over stdio or SSE).
  - same routes underneath, MCP framing on top
  - tools/list returns: `search`, `metasearch`, `fetch`, `fetch_batch` with proper schemas + descriptions of each source the operator has configured
  - lets any MCP-capable LLM client (Claude, agent runtimes, IDE plugins) drop into the swf node as a tool source
  - additive: doesn't change anything existing

### Nix flake (additive, not blocking)
- [ ] **`flake.nix`** alongside the existing `Dockerfile`. Docker stays the primary distribution path because it's the lower-friction on-ramp for the casual "just run it" operator; Nix is the elegant power-user path for the audience that already runs NixOS / nix-darwin and overlaps heavily with the LAN-first / self-sovereign crowd.
  - `packages.default` — `swf-node` derivation built from `pyproject.toml`
  - `apps.default` — `nix run github:dmarzzz/searxng-wth-frnds#swf-node` works without install
  - `devShells.default` — `.[dev,community-full]` deps + ruff + pytest, drop-in for contributors who want a hermetic env
  - Optional: a `nixosModule` for systemd integration (`services.swf-node.enable = true`)
  - Maintenance cost: small if locked carefully via `flake.lock`. Not on the v0.8.0 release path; defer until a Nix user files an issue or the maintenance burden of Docker becomes painful.

## future networking (deferred — see `INDREX.md` section E)

Recorded so we don't re-evaluate from scratch when the question comes up again.

| trigger | what we'd reach for |
|---|---|
| transport encryption needed (peers off the trusted LAN) | Noise handshake — see "transport hardening" above. **NOT libp2p; just one primitive.** |
| body sync at small N (≤20 peers) | `GET /content/<cid>` on peer-server — see "content addressing" above |
| body sync at large N + asymmetric availability | bitswap + Kademlia provider records — at this point libp2p is justified |
| federate hives across the public internet | libp2p (DCUtR, AutoNAT, circuit-relay v2) — DHT for peer routing |
| multiple full nodes federating ("multi-wall") | GossipSub for "new contribution" event distribution |
| third-party clients (phone app, browser, polyglot) | libp2p — pick a mature impl (go-libp2p or js-libp2p), expose as a sidecar |

**Default disposition:** mDNS + HTTP + Ed25519 is the right level of complexity for a friends-on-a-LAN deployment. We escalate to Noise when peers go off-LAN. We escalate to libp2p only when one of the last three rows above has actually arrived. Adopting libp2p prematurely is a net-negative (alpha py-libp2p, ~10× the dependency surface, harder debugging) at our current scale.

## explicitly NOT doing

- **Replacing HTTP with libp2p today.** See `INDREX.md` section E for the full evaluation. The wins are real but ~all future-looking; the costs are immediate.
- **DHT-based peer discovery.** mDNS covers the LAN case; URL list / Tailscale covers cross-LAN cases that we have. DHT is only worth it when peers can't be reliably found by either of those.
- **GossipSub for events.** SSE is fine for "one full node → one renderer." We'd revisit if multiple full nodes ever federate.
- **`zkTLS` for slice content.** Already on the v3 ladder in `INDREX.md` section B; not pulling forward.

## housekeeping

- [ ] one-line CHANGELOG entry per release (currently version bumps in `pyproject.toml` are the only signal)
- [ ] `swf-community-seed` is currently in `community_full/` — fine, but worth renaming to `swf-community-bootstrap` to avoid confusing it with the slice cursor `since=` semantics
