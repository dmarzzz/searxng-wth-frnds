# INDREX spec

Forward-looking spec for the local-index + friend-sharing layer of `searxng-wth-frnds`. This document is the north star; code ships against it.

Status as of 2026-04-18: research phase closed on four sub-topics (set digests, content authenticity, searxng adapter, LAN discovery). Spec below reflects chosen mechanisms. `v0` section at the bottom is what we ship this cycle. Sections marked **[v1]** or **[v2]** are scoped future work, not guesses.

## Terminology

| term | meaning |
|---|---|
| `searxng` | the upstream project (https://github.com/searxng/searxng). We extend it, we do not fork it. |
| `local index` | your FTS5 index over content you have fetched. Single-user data structure. |
| `indrex` | your view of what the whole trust network has. Composes your local index with signed digests of friends' slices. Named after Indra's Net. |
| `slice` | a portion of a friend's local index, scoped by topic/domain/time/authorization. What actually gets exchanged over the wire. |
| `digest` | compact representation of what a peer holds. Used for membership probes and topical routing. |
| `trust zone` | a small pre-agreed set of peers. TZ#1 is just you. TZ#2 is you plus friends, bound by a shared **circle secret**. |
| `circle secret` | a 32-byte random shared at invite time. Used to fingerprint mDNS service names, encrypt mDNS TXT payloads, and salt per-recipient digests. First-class config artifact. |

## Architecture (reads off the whiteboard)

```
                      ┌─────────────────┐   ┌───────────┐
                      │ TOR / DCNET     │──►│ google    │
                      │ (egress anon,   │──►│ brave     │
                      │  separate plane)│──►│ tavily    │
                      └──────▲──────────┘   │ exa       │
                             │              └───────────┘
   user ─► searxng ──────────┤
                             │
                             └─► local index  ◄──► (other searxng engines)
                                     │
                                     │ p2p (mDNS on LAN / Tailscale overlay)
                                     ▼
                                 friend's local index
                                     (Trust Zone #2)
```

Key invariants:

- Searxng is the front door. The user always talks to searxng. We do not proxy searxng.
- The local index is a searxng upstream engine, peer to Google / Brave / Tavily / Exa. Searxng's native merger orders it above the public engines when it has hits (via a weight boost). Details in section **C**.
- The p2p plane does not touch searxng. It flows between `local index` instances directly, discovered by mDNS on LAN and Tailscale-MagicDNS across NATs.
- TOR/DCNET is independent of this spec.

## A. Digest structures and gossip (resolved)

**URL-membership digest: Binary Fuse8 filter.**
~205 KB for 180k URLs at ~0.4% FP. Immutable (rebuild rather than insert); fine because build is sub-second at our scale and we only republish once daily. Compared to Bloom (~216 KB at 1% FP) and Cuckoo (~10 bits/key with delete support), Binary Fuse8 wins on size x FP x simplicity. Reference: https://arxiv.org/abs/2201.01174, https://github.com/FastFilter/xorfilter.

**Per-recipient salting is mandatory.** Unsalted filters are adversarially enumerable (Naor-Yogev 2015, https://eprint.iacr.org/2015/543.pdf). Filter keys are computed as `blake3(url, recipient_pubkey, circle_secret)`. Each friend receives a different filter.

**Update protocol: Rateless IBLT** (Yang/Gilad/Alizadeh SIGCOMM 2024, https://arxiv.org/abs/2402.02668, reference impl https://github.com/yangl1996/riblt). Sync bytes scale with `|delta|`, not `|set|`. For 1k daily changes that is ~30–50 KB regardless of corpus size. Full filter refetched once on cold bootstrap; thereafter RIBLT for deltas.

**Topical-coverage digest: two layers.**
- MinHash/LSH over document shingled tokens for "do you have documents similar to this one?" (~1 KB/doc sketch, few MB per corpus).
- Topic-centroid vectors from k-means over embeddings for "do you cover topic Y broadly?" (64 x 384-dim float32 = ~100 KB). Privacy dial: fewer clusters leak less.

**Gossip transport: libp2p gossipsub** for the tiny signed `DigestManifest` (`{peer_id, snapshot_id, root_hash, fuse_filter_url, log_head_seq}`). Direct streams for the filter blob and RIBLT delta stream.

**Prior-art finding worth internalizing**: no F2F system we looked at ships a compact set-digest of its whole corpus. SSB uses vector clocks, IPFS wantlists, YaCy moves shards. We are genuinely inventing this primitive for our F2F invite-only-long-lived regime.

## B. Content authenticity (resolved)

**v0 composition**: three mechanisms that compose, all use existing standards:

1. **SSB-style sigchain.** Each friend has an Ed25519 feed keypair. Slice messages carry `{previous, author, sequence, timestamp, payload_hash, signature}`. Schema per https://spec.scuttlebutt.nz/feed/messages. Gives unforgeable provenance and tamper-evident history (prev-hash break is detectable).
2. **Per-document fetch attestation in a DSSE envelope, in-toto v1 Statement shape.** Predicate type: `searxng-frnds/FetchAttestation/v1`, carrying `{fetched_at, http_status, final_url, extractor, extractor_version, extractor_config_hash}`. Reuses https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md, gets tooling for free. This one structure does the work of per-doc attestation AND extractor-version tag.
3. **Binary Merkle root over the slice**, RFC 6962 style (same shape as CT and Rekor). Plain binary, not Sparse Merkle (no sparse keyspace lookups), not Patricia. O(log n) inclusion proofs with mature tooling.

**Escalation ladder**:

| stage | adds | stakes |
|---|---|---|
| v0 | the three above | bugs, rot, silent extractor failures, redirect drift |
| v1 | Sigstore/Rekor-style transparency log of slice roots + gossip between friends | retroactive rewrites, equivocation (friend showing different slices to different peers) |
| v2 | **Noise KK** handshake for transport between friends; per-session keys; feed-key delegation records for rotation | bounded blast radius on host compromise, transport forward secrecy |
| v3 | Per-URL opt-in **zkTLS** (TLSNotary); receiver-side re-fetch sampling; canonical-ID short-circuits (Wikipedia `oldid`, arXiv versioned, signed git) | motivated adversarial friend |

**zkTLS reality check (April 2026):** TLSNotary is `alpha.14` as of Jan 2026, ~5s native / 10s browser for a 10 KB response, ~40 comm rounds. Response-size cost is the killer. Shippable as v3 opt-in per URL, never as default.

**Attack matrix summary:**
- v0 catches: stale content (via timestamp), extractor bug (via extractor_version tag), redirect drift (via `final_url`), history rewrite (prev-hash break), in-transit corruption (hash mismatch), silent friend rewrite (root mismatch).
- v0 does NOT catch: friend MITM'd by ISP at fetch time, friend's host compromised with key exfil, adversarial friend fabricating content, equivocation.
- v1 adds equivocation detection.
- v2 adds host-compromise blast-radius control.
- v3 adds adversarial-friend bar (zkTLS is the only thing that meaningfully raises this).

**The explicit honesty:** the v0 trust model is "friends are curated humans, we catch accidents not malice." User docs need to say this plainly.

## C. SearXNG engine adapter (resolved)

**Option A: native Python offline engine.** Single `.py` file (~60 lines, written below in the v0 section). Registered in `settings.yml` as `engine_type: offline`. No HTTP sidecar, no JSON-engine wrapper, no fork.

**Why A over B (json_engine wrapping a sidecar):** searxng's `engine_type: "offline"` processor is first-class and used in-tree by `sqlite`, `postgresql`, `mongodb`, `valkey_server`, `command`. Prior art: `searx/engines/sqlite.py` is the closest template; we port it to FTS5 with `bm25()` ranking and `snippet()` highlighting. No HTTP/serialization tax, no second process to supervise, native access to searxng's `EngineResults` + `MainResult` dedup machinery.

**Deployment constraint (important):** `searx/engines/__init__.py` hardcodes the engines directory in `load_module`. There is no dotted-path plugin discovery. The `.py` file **must physically live in `searx/engines/`**. For Docker, this means bind-mounting our file into `/usr/local/searxng/searx/engines/local_index.py`. We are not forking searxng; we are injecting one file at deploy time.

**Merger mechanics:** searxng's `calculate_score` does `weight = product(engine.weight for each contributing engine)`. Setting our engine to `weight: 4.0` gives a 4x boost when the same URL also comes back from Google. Weights above ~5 distort single-engine-hit ordering; in-tree values range 0.5–2.0, so 4.0 is aggressive but in-distribution.

**Dedup is URL-string-exact** on `netloc|path|params|query|fragment`. This forces URL canonicalization on ingest (see section on derivative decisions).

**Hot-reload story:** new FTS5 rows visible to searxng readers immediately via SQLite WAL mode. Engine code changes need a searxng restart. Data updates do not.

**Gotchas:**
- Engine `name:` in YAML cannot contain underscore. Use `"local index"` (with space) or `"indrex"`. Module filename is fine as `local_index.py`.
- `MainResult.__hash__` requires `parsed_url`. Auto-populated by `normalize_result_fields`; don't strip it.
- Offline timeouts enforced by thread-join, not cooperative cancellation. Keep queries fast (`LIMIT 10`, 1-second timeout).
- No SIGHUP. Config changes need restart; data writes don't.

## D. LAN discovery and peer transport (resolved)

**Primary: `python-zeroconf`** (v0.148+, active, asyncio-native, used by Home Assistant in prod, pure-Python no Avahi-daemon required). Repo: https://github.com/python-zeroconf/python-zeroconf.

**Fallback ladder:**
1. LAN mDNS (primary)
2. **Tailscale**: detect via local socket (`tailscaled.sock` on mac/linux), enumerate peers, probe `/.well-known/indrex` on each. Tailscale has won the "laptops behind different NATs" category. ZeroTier / Nebula / raw WireGuard rejected for our invite-circle audience.
3. Explicit `~/.config/swf/peers.yaml` with `{pubkey, url, nickname}` rows. CLI: `swf peer add pubkey@host:port`. Copy-pasteable invite URI: `swf://<pubkey>@<host>:<port>`.
4. Gossip: once any two peers connect via 1–3, exchange signed peer-lists so a newly-joined device learns the whole circle after one successful handshake.

**Service-record schema**:
- mDNS service type: `_indrex-<circlehash>._tcp.local.` where `circlehash = first 8 bytes of blake3(circle_secret)`. Non-circle peers never even see us.
- TXT fields (encrypted with chacha20-poly1305 keyed on circle secret, modeled on SSB's `ssb-lan`):
  - `v`: protocol version
  - `pk`: ed25519 pubkey (base64url)
  - `pkfp`: short fingerprint for human matching
  - `dg`: blake3 of index-digest root
  - `ep`: path to digest endpoint
  - `sig`: signature over `v|pk|dg|ts`
- HTTP endpoints on the peer's local indrex server: `/.well-known/indrex`, `/d/v1/<digest-id>`, `/s/v1/<slice-id>`. Pubkey-signed request auth.

**Hard reality about LAN discovery:** mDNS fails on most conference wifi and much corporate/hotel wifi due to AP client isolation. Tailscale fallback is **mandatory, not optional**. This needs to be in the user-facing docs.

**UX gotchas:**
- macOS prompts for Local Network permission on first launch.
- Windows firewall prompts on first bind.
- User should be able to tag SSIDs trusted/untrusted; default-deny on cafe/conference SSIDs and fall through to Tailscale.

**Transport between discovered friends: Noise `KK`** (both B and D converged here independently). Both sides know each other's static pubkey by the time they talk, which is exactly the KK setting. libp2p already uses Noise. Pattern reference: https://noiseexplorer.com/patterns/KK/.

## Derivative decisions that fall out

These are not in the whiteboard but drop out of the four research reports. They need to be settled before code ships.

1. **URL canonicalization.** One function applied once on ingest, then URLs are only compared byte-equal thereafter. Specified rules:
   - Lowercase scheme and host.
   - Remove default ports (`:80` on http, `:443` on https).
   - Remove fragment.
   - Strip tracking params: `utm_*`, `fbclid`, `gclid`, `mc_cid`, `mc_eid`, `_hsenc`, `_hsmi`, `mkt_tok`, `ref`, `ref_src`, `igshid`, `si` on youtube.
   - Collapse duplicate `/` in path.
   - Remove trailing `/` on path (except when path is exactly `/`).
   - Sort remaining query parameters by key.
   - Percent-encode consistently using `urllib.parse.quote` with default safe chars.

   Single source of truth: `swf/canonical.py::canonical_url(url: str) -> str`. Called by `knowledge.world_write`, `index.index_page`, and the searxng engine's search function on inputs where relevant.

2. **Content hash definition (v0): key filters on URL, carry content hash only in attestations.** Rationale: trafilatura output is not byte-stable across versions, so hashing extracted markdown would churn the filter on every upgrade. URL-only filter is stable. When we add the attestation layer (B, v0), content_hash fields use `sha256(raw_html)` which IS stable. Raw-HTML archival becomes a v1 task (already in DESIGN.md TODO).

3. **WAL mode mandatory** on the FTS5 database. Set at DB creation: `PRAGMA journal_mode=WAL`. Without this, concurrent ingestor writes will block searxng reads.

4. **Circle secret is a first-class config artifact.** Generated once per trust zone, 32 bytes random, distributed via an existing secure channel (Signal, paper, in person). Stored in `~/.config/swf/circle.key` with 0600 perms. Used for: mDNS service-name fingerprinting, mDNS TXT encryption, per-recipient filter salting, slice feed namespace. TZ#1 (solo) has no circle secret; it is TZ#2 that introduces it.

5. **Transport crypto is Noise KK**, not handrolled TLS over pubkey auth. Rust `snow` or Python `dissononce` as the implementation.

6. **SSB is the reference project** to study before writing the friend layer. Do not copy code; the libraries have drifted. Copy the design.

## Staleness principle

A single global TTL is too blunt. Stable reference material ("what is a mixnet") can safely cache for months; news or live-event queries ("latest Ethereum gas prices") go stale in minutes. We split staleness into three composable mechanisms, shipped in two stages:

**v0.1 (shipped)**:
- **Global TTL**: `RA_CACHE_TTL_SEARCH` seconds, default 7 days. Anything older falls through to the network.
- **Temporal-marker auto-bypass**: if the query contains markers like "latest", "today", "current", "recent", "as of", or any year within +/-1 of the calendar year, the cache is skipped automatically and the user does not have to remember to pass `RA_BYPASS_CACHE=1`. See `_TEMPORAL_MARKERS` in `src/swf/web/providers.py`.
- **Explicit override**: `RA_BYPASS_CACHE=1` in the environment forces fresh.

**v0.2+ (planned)**:
- **Per-category TTL**: classify queries as research / news / reference at call time, set different TTLs per category. Research = 30 days, news = 1 hour, reference = indefinite.
- **Agent freshness hint**: an agent building a time-sensitive synthesis can pass `RA_FRESHNESS=news` to override the default for a whole run.
- **Domain-based decay**: URLs from `en.wikipedia.org` or `arxiv.org` get longer per-page TTLs than URLs from news domains or social media. Stored alongside the cache row.

Design invariant across all three: the system should **err on the side of hitting the network when ambiguous**. A false cache-hit (stale answer) is a worse failure than a false cache-miss (redundant network call), because the user cannot tell the stale answer is stale without round-tripping anyway.

## E. Networking transport: libp2p evaluation (deferred)

Recorded so we don't re-litigate it from scratch.

**Today's stack:** zeroconf mDNS for discovery (`_indrex._tcp.local.`) + plain HTTP/1.1 over TCP for transport + Ed25519 application-layer signatures over slice envelopes. **Not libp2p, not a DHT, not a custom binary protocol.** This is the same shape voxterm uses (mDNS + raw TCP/UDP + AES-GCM at the application layer — different transport, same philosophical pattern).

This is "p2p" in topology (no central server, every peer talks to every peer) but NOT in protocol stack. The simpler description: **HTTP federated search with cryptographic provenance at the application layer.**

### what libp2p would buy us, ranked by relevance to this project

| capability | what it gives | needed today? | trigger to revisit |
|---|---|---|---|
| stable peer identity (peer-id = `12D3KooW...` hash of pubkey, embedded in `multiaddr`) | peers identified by id, not URL; address can change without losing identity | no | peers regularly hop networks |
| cross-NAT discovery (Kademlia DHT + AutoNAT + DCUtR + circuit-relay v2) | route to a peer by id regardless of where they are; hole-punch through NATs | no | hives federate across the public internet |
| cross-LAN federation | two schools' hives can peer with each other across the internet without manual URL exchange | not yet | multiple physical hives in different cities |
| **content routing (Kademlia provider records + bitswap)** | "who has CID `bafkreig...`?" becomes a routing primitive; peers fetch bodies from each other | not yet, but **interesting** — we already have CIDs on every page | we want body sync at scale where "ask everyone" doesn't fit |
| transport encryption (Noise handshake) | every connection encrypted+authenticated by default; replaces plaintext HTTP | mildly | any deployment outside fully-trusted LAN |
| GossipSub pub/sub | one full node publishes "alice contributed," any subscriber receives without polling | no | distributed hive (multiple full nodes federating); third-party event consumers |
| polyglot client compat (Go, JS, Rust, Python all speak same protocol) | browser apps, phone apps, third-party tools plug in for free | no | ecosystem play / public API |
| multiplexed streams over one connection | several logical channels over one TCP/QUIC | marginal | high-frequency request workloads |

### costs of adopting libp2p today

1. **`py-libp2p` is alpha.** Go and JS implementations are mature; Python is not. Adopting means staking on alpha software OR running a Go sidecar.
2. **Dependency surface:** ~200 lines of "mDNS + http.server + urllib" becomes a full networking stack with multistream-select, NAT manager, identify protocol, bitswap, etc. Lots more to break.
3. **Most of the wins are at scale we don't have.** DHT, hole-punching, GossipSub, content routing — all overkill for one wall and 5–20 testers on the same Wi-Fi.
4. **Loss of debuggability with `curl` and `tcpdump`.** Plain HTTP is trivial to inspect; libp2p needs its own tooling.

### the incremental alternative (preferred)

Two changes get ~80% of what libp2p offers for ~5% of the complexity, and keep the transport debuggable:

1. **Adopt Noise handshake on top of TCP.** Already in the v2 ladder of section B. Use `noiseprotocol` (mature Python). ~80 lines. Closes the plaintext-HTTP-on-LAN window without rewriting anything else. Same primitive voxterm uses (theirs is AES-GCM with HKDF-derived keys; Noise gives you the same property with a standard handshake).
2. **`GET /content/<cid>` on peer-server.** When body sync becomes worth it, each peer answers "yes I have it / no I don't" by checking `pages.content_cid` in their indrex. No DHT needed at small N — asking everyone in a 20-peer LAN is cheap. Bodies come from `~/world_knowledge/web/<host>/...md` files we already keep.

### the three triggers that would tip us to libp2p

Any one of these:

1. **Hives federate across the public internet.** Multiple schools, multiple cities, peers behind NATs. Hand-rolling NAT traversal at that point is masochism.
2. **Content sync at scale where "ask everyone" doesn't fit.** Hundreds of peers, GBs of bodies, asymmetric availability. Bitswap + DHT provider records is the right tool.
3. **Third-party clients want to plug in.** Phone app, browser app, anyone running a libp2p client wants to drop into a hive without us shipping a custom server protocol.

Until one is on the roadmap: stay simple. Honest user-facing claim is "peer-to-peer on the LAN with cryptographic guarantees, no third-party infrastructure required" — which is true today regardless of whether we use libp2p.

## Open questions that need real-world measurement

Flagged so we don't pretend they're answered:

- How much does trafilatura output vary across versions on real URLs? Informs whether the extractor-version tag is load-bearing or decorative.
- What fraction of a real research-agent URL mix has canonical-hash short-circuits available (Wikipedia oldid, arXiv version, signed git)? Informs whether that v3 feature is worth building.
- What's the re-fetch false-positive rate on our corpus (personalization, A/B, cookie walls)? Informs whether re-fetch sampling is useful as a signal at all.
- TLSNotary proof size at April 2026 `alpha.14` — not in public benchmarks. Informs whether proofs live alongside markdown or are externally referenced.
- Equivocation detection in small (N=5–20) groups. CT assumes many auditors. Our regime is much smaller; gossip sufficiency is unclear.
- How does Windows 11 + tunneled adapter interact with python-zeroconf.

## Shipped so far

| ship | status | what it adds |
|---|---|---|
| v0 (searxng engine + WAL + URL canonicalization) | ✅ | `local_index` engine, `world_knowledge/` write-through |
| v0.1 (query cache) | ✅ | `search_results` table, cache short-circuit in `web_search`, staleness auto-bypass |
| v0.2 (MVP friend layer) | ✅ | `peer_server`, `local_friends` engine, `peers.yaml`, `swf-peer` CLI |
| v0.3 (discovery) | ✅ | `python-zeroconf` mDNS, Tailscale detection, `swf-peer discover/sync` |
| v0.4 (Ed25519 identity) | ✅ | keypair at `~/.config/swf/identity.key`, signed `/.well-known/indrex`, TOFU pubkey pinning |
| v0.5 (URL-membership digest) | ✅ | bloom filter with per-recipient salt, circle secret, `/digest/urls` endpoint |
| v0.6 (signed slices + merkle) | ✅ | sigchain + RFC 6962 binary merkle, inclusion proofs, verification |
| v0.7 (inversion: drop SearXNG) | ✅ | `swf.indrex` unifies the query primitive, `swf.fanout` runs in-process (local + friends + DDG), `web_search` is ~200 LOC with no daemon dependency. SearXNG engines kept for optional web UI. |
| v0.8 (slice-pull replication) | 📋 TODO | friends publish signed slices, peers pull and merge locally; queries stop traveling |
| v0.9 (local RAG / embeddings) | 📋 TODO | `sqlite-vec` index over world_knowledge, `ask_local(q) -> passages` tool |
| v0.10 (mine runs/*.json) | 📋 TODO | expose agent run history as a searchable Q&A corpus |
| Noise KK transport | 📋 TODO | swap plain HTTP for mutually-authenticated encrypted channel; interim is TOFU-pinned pubkeys over plain HTTP |

**Not yet wired into the live search flow** (primitives shipped, composition pending):

- Digest-gated friend queries: shipped as a primitive at `/digest/urls`. Query-time gating wants topic centroids (a different digest kind), not URL-membership, so deferred until topic centroids land.
- Slice publishing + slice-based search responses: `swf.slice` is ready to be used as the wire format for peer responses. Wiring it in means changing `peer_server`'s `/search` to return signed slices and `local_friends` to verify before admitting. Follow-on ship after 0.7 (so we don't rewrite transport twice).

## v0.2 — MVP friend layer (shipped)

Rather than tier inside Python `web_search`, all orchestration lives in SearXNG. Swarm hits SearXNG, SearXNG queries local + friends + public in parallel and merges. No Python code in the middle.

**Shipped:**
- `swf/peers.py`: config model, `~/.config/swf/peers.yaml` loader with a zero-dep fallback parser.
- `swf/peer_server.py`: stdlib `ThreadingHTTPServer` exposing `/health`, `/.well-known/indrex`, `/search?q=`. Binds `127.0.0.1` by default; user opts into LAN exposure via `SWF_BIND=0.0.0.0`. Entry point `swf-peer-server`.
- `swf/local_friends.py`: SearXNG offline engine that reads `peers.yaml` at query time and fans out in parallel (short per-peer timeouts, failures skipped silently). Engine weight 3.0, between `local_index` (4.0) and public engines (1.0).
- `swf/peer_cli.py`: `swf-peer add / list / remove / health`. The CLI writes `peers.yaml`; the SearXNG engine reads it. No SearXNG restart needed when peers change.
- Bind-mount added in `docker/docker-compose.yml`: host `~/.config/swf/peers.yaml` → container `/etc/swf/peers.yaml` read-only.
- Integration test `tests/test_two_peers_integration.py`: spins up two real HTTP peers on localhost with isolated `world_knowledge/` dirs, verifies cross-peer HTTP retrieval of distinctive sigils. 9 cases, all green.

**Explicitly deferred to next ships, not regressed:**
- Auto-discovery (mDNS + Tailscale) → 0.3
- Ed25519 identity + signed handshake + pubkey pinning → 0.4
- URL-membership digest + per-recipient salting → 0.5
- SSB-style slice sigchain + RFC 6962 merkle → 0.6
- Noise KK transport replacing plain HTTP → 0.7

**Security posture as of 0.2 (documented loudly):** plain HTTP, no authentication, LAN trust. Peers added by hand. Default bind is `127.0.0.1` so nothing leaves your machine unless the user explicitly opts in with `--bind 0.0.0.0`. Do not run 0.2 on a hostile network.

## v0 scope (what we ship this cycle)

Narrowly bounded to the single-user local-index-as-searxng-engine path. No friends, no digests, no attestation, no mDNS. Just: make our existing FTS5 index queryable through searxng, correctly.

**In scope:**
1. `swf/canonical.py` with `canonical_url()` per section on derivative decisions, tested.
2. `swf/local_index.py`: the ~60-line searxng offline engine from section C.
3. `searxng/settings.yml` example fragment + `docker/docker-compose.yml` showing the bind-mount pattern.
4. Update `swf/web/index.py` to set WAL mode at DB creation.
5. Update `swf/web/knowledge.py` and `swf/web/fetch.py` to run URLs through `canonical_url()` before write-through and before FTS5 insert.
6. Backfill / migration: if the existing `~/world_knowledge/index.db` lacks WAL and has uncanonicalized URLs, a `swf reindex` subcommand rebuilds it from the markdown files on disk (we already have `reindex_knowledge()` to extend).
7. Smoke test: run searxng with our engine mounted, issue a query against it, confirm local hits appear and merge correctly with public-engine results.
8. README + INDREX updates pointing at the new files.

**Out of scope (deferred, clearly named):**
- Bloom/RIBLT/MinHash/digests (A). Needs the circle-secret layer first.
- SSB sigchain / DSSE attestations / merkle (B).
- mDNS + Tailscale discovery (D).
- Noise KK transport (B,D).
- zkTLS (B v3).
- Ingestion worker that polite-fetches URLs searxng returns (separate from the engine; the engine only serves what's already been fetched by the agent).
- Raw HTML archival.
- Local embedding index with `sqlite-vec`.

## Repo layout after v0

```
searxng-wth-frnds/
├── DESIGN.md                          # R4 self-sovereign principles (kept as context)
├── INDREX.md                          # this file
├── ReadMe.md                          # updated with v0 run instructions
├── searxng/
│   └── settings.yml                   # example config with local_index engine registered
├── docker/
│   └── docker-compose.yml             # bind-mount pattern for local_index.py
├── src/
│   ├── swf/                           # new: searxng-wth-frnds package
│   │   ├── __init__.py
│   │   ├── canonical.py               # URL canonicalization (single source of truth)
│   │   └── local_index.py             # searxng offline engine adapter
│   └── (research_agent moved out: see github.com/dmarzzz/research-swarm)
│       └── ...
├── tests/
│   └── test_canonical.py              # unit tests for the canonicalizer
└── pyproject.toml
```
