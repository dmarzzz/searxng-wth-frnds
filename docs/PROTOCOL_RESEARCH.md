# Protocol Research: LAN-First Signed-Record Sync

**Branch:** `docs/phase-2-sync-research`
**Audience:** the implementer working on Phase 2 of the P2P sync stack.
**Scope:** survey adjacent sync protocols, extract patterns + footguns, recommend hardening for the existing "manifest + diff + LWW + signed envelopes" design.

The design under review:

- Signed, immutable record envelopes (ed25519). One author per `record_id`.
- LAN-only discovery via mDNS / Bonjour. ~50 trusted peers per cohort.
- Eventually consistent. LWW by wall-clock timestamp, tiebreak lex hash.
- Per-record append-only chain via `prev_hash` (Merkle-like, not a blockchain).
- Manifest + diff handshake: peers exchange `{record_id → latest_hash}` maps, then pull what's missing.
- Full version history kept locally in sqlite.
- Explicitly **not** a CRDT — single-writer-per-record means convergence is trivial.

---

## 1. TL;DR

- **Don't use wall-clock LWW. Use HLC (Hybrid Logical Clocks) under the hood and let "LWW" be a comparison rule on HLCs, not on raw `time.time()`.** Wall-clock LWW silently discards data when peer clocks disagree by more than the network round-trip — every distributed-systems writeup names this as the #1 LWW footgun. HLC fixes it for ~no extra bytes. [Kulkarni & Demirbas, 2014](https://cse.buffalo.edu/tech-reports/2014-04.pdf) | [Medium, "When QUORUM Isn't Enough"](https://medium.com/@mehedees/when-quorum-isnt-enough-how-distributed-clock-skew-silently-discards-data-mehedee-siddique-56b22d0dbd31)
- **Manifest-diff (`{record_id → latest_hash}`) is fine at ~50 peers but is O(N) in record count per sync — and that's the same shape Automerge's bloom-filter trick optimizes away.** For cohort-sized state it's not worth the complexity yet, but if `record_id` count ever exceeds ~10k, switch to either (a) Automerge-style bloom filters keyed by `(record_id, latest_hash)`, or (b) range-based set reconciliation à la Negentropy/Willow. RBSR is the most modern answer and is DoS-resistant where bloom filters are not. [logperiodic.com RBSR](https://logperiodic.com/rbsr.html) | [Kleppmann blog](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html) | [NIP-77 Negentropy](https://github.com/nostr-protocol/nips/blob/master/77.md)
- **mDNS is "the LAN is trusted" defaults all the way down. Layer authentication on top — do not rely on mDNS for cohort membership.** Discovery announces; trust is established by ed25519 keys cross-referenced against a cohort roster you ship out-of-band. SSB's Secret Handshake and Earthstar's share-secret model are the templates. [HackMag mDNS pentest](https://hackmag.com/security/multicast-dns-pentest) | [SSB protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
- **The single-writer-per-record invariant is doing enormous work — protect it religiously.** If the same author publishes two divergent chains for the same `record_id` (a "fork"), every protocol in the survey (Hypercore, SSB, Matrix) has a different defense and a different failure mode. You need a stated policy (likely: quarantine + log + don't replicate, like SSB's forked-feed response) before someone writes the first multi-device client. [SSB feed fork issue](https://github.com/ssbc/ssb-db/issues/157) | [Hypercore FAQ](https://github.com/tradle/why-hypercore/blob/master/FAQ.md)
- **Replay defense is cheap: cache `content_hash` (or signature bytes) of every accepted envelope and reject on duplicate.** Ed25519 has a signature-malleability gotcha — non-canonical `S` values are accepted by some libraries, so dedup by `content_hash`, not by signature bytes. [Ed25519 forgery advisory](https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw)

---

## 2. Protocol Survey

### 2.1 Hypercore / Hyperbee / Hyperdrive (Holepunch, formerly DAT)

**What it is, one sentence.** A signed append-only log (Hypercore) keyed by a single author's keypair, with a sparse-replication wire protocol built on Merkle proofs; Hyperbee is an append-only B-tree on Hypercore, Hyperdrive is a filesystem on Hyperbee. [Hypercore Protocol](https://hypercore-protocol.github.io/new-website/protocol/) | [holepunchto/hyperbee](https://github.com/holepunchto/hyperbee)

**Steal:**

- BLAKE2b-256 Merkle tree over the log, with the **root signed by the author's ed25519 key on every append**. That gives you per-record-chain integrity for free — receivers can verify any block against any signed root. [Hypercore Protocol](https://hypercore-protocol.github.io/new-website/protocol/)
- **Sparse replication via bitfields**: peers exchange compact bitfields describing which blocks they have. Their `Request` message carries a packed-bitfield `nodes` field telling the sender which Merkle "uncle/parent" hashes to include in the proof, so peers don't redundantly ship hashes the receiver already holds. [DEP-0010 wire protocol](https://www.datprotocol.com/deps/0010-wire-protocol/)
- **One request per block** to encourage load-balancing across multiple peers. Useful pattern if a single record ever has hundreds of versions.

**Avoid:**

- **The forking footgun.** "An actor could decide to revert Hypercore to a previous state, and share this fork. Another possibility is for the author to rewind and serve different versions of the history to different peers." [Hypercore FAQ](https://github.com/tradle/why-hypercore/blob/master/FAQ.md) Our `prev_hash` chains have the same property; an author with two devices can fork themselves. Hypercore basically punts this to application-layer detection.
- **Key rotation requires application-defined proofs** ("a proof is needed that the new key is a valid successor from the old one") — there is no built-in answer. Don't promise key rotation in the spec without specifying how.
- **Replication-stream nonce reuse.** Hypercore encrypts its replication stream with feed-key + incrementing nonce; the SSB protocol guide flags this same class of bug — nonce reuse with the same key is a key-recovery vulnerability. If our LAN transport ever uses authenticated encryption, the nonce discipline matters. [SSB protocol guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)

### 2.2 Earthstar

**What it is, one sentence.** Signed mutable key/value documents organized into "shares" (cohorts), where the share address grants discovery and the share secret grants write access; per-document keys are `(path, author)` with the newest version per author kept. [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works) | [es.5 data format](https://earthstar-project.org/specs/data-spec-es5)

**Steal:**

- **`(path, author) → latest` mapping** is exactly the semantic the implementer is building. Earthstar's "we discard old versions from the same author within a path" is the same invariant. [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works)
- **Deterministic canonical serialization for signing:** sort fields lexicographically, exclude `text` and `signature`, SHA-256, sign. Critical for cross-implementation compatibility. [es.5 data format](https://earthstar-project.org/specs/data-spec-es5)
- **Path-level write authorization via the `~author` convention in the path** (`/about/~@suzy.../displayName.txt` is writable only by `@suzy`). Cheap, declarative, no separate ACL needed.
- **Ephemeral documents with `deleteAfter`** and a mandatory `!` somewhere in the path. Libraries must enforce expiry at least once an hour; expired docs must not sync. Good template for any TTL feature.
- **Tiered trust via following relationships** rather than hard cohort gates — useful escape hatch if "everyone in the cohort sees everything" turns out too coarse.

**Avoid:**

- **Metadata leakage by design.** Author, path, and timestamp are always plaintext, even when content is encrypted. The spec discusses (but does not solve) "ways of nesting metadata inside another document to obscure it." [Earthstar data spec discussion](https://earthstar-project.org/specs/data-spec) Plan for this upfront if your records contain anything sensitive in `record_id` or author.
- **No member revocation.** "It's not currently possible to remove people from a share; instead you can make a new share and migrate everybody else there." [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works) For 50-peer cohorts, this is workable; for ones with churn, plan a cohort-rotation story.
- **No removal of old versions across the network.** Even ephemeral docs need "at least one library running at least every hour" to actually delete them everywhere — if everyone in the cohort goes offline, expired docs survive.
- Earthstar is migrating its data model to sit on top of **Willow** for v11 (see §2.3). Don't assume the current es.5 spec is the long-term answer; the project itself has voted for RBSR + Meadowcap. [Willow + Earthstar's Spring](https://gwil.garden/posts/willow-earthstar-big-year.html)

### 2.3 Iroh + Willow Protocol

**What it is, one sentence.** Willow is a namespace-based protocol with 3D-range-based set reconciliation (RBSR) as its sync core and Meadowcap (capability tokens) as its authorization layer; Iroh is an implementation that uses RBSR for its `iroh-docs` multi-writer key/value store. [Willow Specs](https://willowprotocol.org/specs/3d-range-based-set-reconciliation/index.html) | [n0-computer/iroh-docs](https://github.com/n0-computer/iroh-docs)

**Steal:**

- **Range-based set reconciliation** is the canonical answer to "I have a set of records, you have a set of records, sync efficiently without sending what we both already have." It recursively partitions the keyspace and exchanges fingerprints of ranges; only mismatched ranges descend. Communication rounds grow as **log of dataset size, not as the symmetric difference**. For a billion-element set with branching factor 16, ~4 round trips. [logperiodic.com RBSR](https://logperiodic.com/rbsr.html) | [Meyer 2023 arXiv](https://arxiv.org/abs/2212.13567)
- **Incremental fingerprints** (XOR of per-element hashes, or addition mod 2²⁵⁶) so adding/removing an element costs one hash, not a full rescan. Critical if you ever build the live-sync version. [logperiodic.com RBSR](https://logperiodic.com/rbsr.html)
- **Meadowcap capability tokens.** Capabilities answer four questions: *who, read or write, which entries, valid or forged?* Capabilities can be **delegated** (re-signed for a narrower scope) and **restricted** by subspace, path, or timestamp. Communal-namespace mode (each author owns their subspace, proven by signature) maps directly onto our single-writer-per-record model. [Meadowcap spec](https://willowprotocol.org/specs/meadowcap/index.html)

**Avoid:**

- **RBSR is overkill for ≤10k records on a 50-peer cohort.** The naive manifest-diff is O(N) records per sync but at N=1000, that's <100KB on the wire — completely fine. Only switch when you have a measured problem.
- **Cryptographic collision-finding against RBSR fingerprints.** Meyer's paper documents adversarial inputs that can stall sync. XOR-based fingerprints are weakest; addition mod 2²⁵⁶ is much harder. If you adopt RBSR, do not pick XOR. [logperiodic.com RBSR §security](https://logperiodic.com/rbsr.html)
- **Willow's 3D ranges (timestamp × path × subspace) are a learning curve.** For a flat record-ID space, the 1D special case is all you need. Don't try to model the full 3D version unless you actually want hierarchical paths + per-author subspaces.

### 2.4 Automerge sync protocol

**What it is, one sentence.** A two-party sync protocol over Automerge CRDT documents where each peer sends its commit graph heads plus a bloom filter summarizing changes-since-last-sync; the receiver tests its own commits against the filter and immediately ships any miss. [Kleppmann blog](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html) | [Automerge sync.State Rust docs](https://automerge.org/automerge/automerge/sync/struct.State.html)

**Steal:**

- **Bloom filter over commit hashes is dramatically smaller than the raw set.** 10 bits per commit, ~0.8% false positive rate, typically converges in one round trip with ~1% chance of two RTTs and 0.01% chance of three. [Kleppmann blog](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html) Way cheaper than our manifest if records get into the tens of thousands.
- **Sync state is stateful per-peer**: each side remembers the heads they last sent / received from each peer. The bloom filter then only summarizes *what's new since the last sync with this specific peer*. Tiny filter, fast convergence. [Automerge sync.State docs](https://automerge.org/automerge/automerge/sync/struct.State.html)
- **"Heads of the commit graph"** are a clean handoff metaphor — applies directly to our `record_id → latest_hash` map. Each peer publishes heads; if you don't recognize a head, you ask for the chain.

**Avoid:**

- **Bloom filters have a DoS vector.** Crafted inputs can drive false-positive rates much higher than the parameterized expectation; logperiodic.com cites a proof of concept "causing Automerge's sync system to degrade to 97% false-positive rate." [logperiodic.com RBSR §alternatives](https://logperiodic.com/rbsr.html) In a *trusted* cohort this is irrelevant, but if cohort membership ever opens up, it's a real concern.
- **Malformed sync messages have crashed Automerge clients** (issue #855 — WASM crash on malformed sync message). [Automerge#855](https://github.com/automerge/automerge/issues/855) Lesson: validate sync-message wire format before *anything* else, treat the parser as the security boundary.
- **Multi-peer simultaneous sync is non-obvious** (Automerge issue #536). [Automerge#536](https://github.com/automerge/automerge/issues/536) Per-peer sync state means concurrent syncs from peer A and peer B can confuse the bloom filter. Plan the locking story.

### 2.5 Yjs y-protocols (sync v1 / v2)

**What it is, one sentence.** A three-message sync protocol over Yjs CRDT documents — SyncStep1 (state vector), SyncStep2 (missing updates as a binary diff), Update (incremental change broadcast). [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md)

**Steal:**

- **State vectors are tiny.** A state vector is `{clientID → highest_seq}`; sending it costs `O(authors)` bytes, not `O(records)`. For our model, the analog is `{author_pubkey → highest_seq_or_timestamp}`. This is dramatically cheaper than a full manifest if you have many records per author. [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md)
- **Client-server symmetry**: in the client-server topology, the server replies to SyncStep1 with SyncStep2 *plus its own SyncStep1*. Two-way sync in one round trip. Worth mimicking.
- **V2 encoding has significantly better compression** than V1 for the same logical update payload. Opt-in. [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md)

**Avoid:**

- **The spec explicitly disclaims awareness authentication**: "awareness payloads are not authenticated by this protocol; a malicious peer can claim arbitrary cursor or presence data." [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md) Whatever side-channel signals we add (e.g. "peer is online", "peer is editing record X"), don't let them affect anything load-bearing without signing them.
- **Server may enforce read-only by inspecting the message-type prefix.** This is fragile authorization — a peer can craft Update messages and the prefix check is the only gate. Better to require signed envelopes on every Update.
- The sync protocol is **per-document**; there's no built-in story for "I want to sync 50 docs to this peer." You build a multiplexer.

### 2.6 Matrix federation

**What it is, one sentence.** Server-to-server event federation for the Matrix chat protocol, where every event is a signed JSON object referencing prev-events (DAG, not chain) and auth-events (the state events that authorize it), with state-resolution-v2 used to merge concurrent DAG branches. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/) | [State Resolution v2 explainer](https://matrix.org/docs/older/stateres-v2/)

**Steal:**

- **Every event carries `prev_events`, `auth_events`, content hash, and an Ed25519 signature.** Receivers run: signature check → hash check → auth check based on auth_events → auth check based on state-before-event. Four independent gates. We should run at least three: signature, content_hash, and chain-link validity. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/)
- **`origin_server_ts` is in POSIX milliseconds and is part of the signed event** — clock skew is *visible* (you can detect "this event claims to be from 12 hours in the future") rather than silently corrupting LWW.
- **Signing keys have an explicit expiry (`valid_until_ts`), capped at 7 days into the future.** Hard limit on the blast radius of a compromised signing key. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/)
- **Transaction IDs (`txnId`) for idempotency** — the sender must wait for a 200 OK before retrying with a different txnId. Cheap replay defense at the transport layer.
- **Soft-fail pattern**: an event that fails *current-state* auth but is internally valid is accepted (so the DAG keeps converging) but not relayed to clients. Stops ban-evasion attacks where a peer references an old DAG branch. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/) Useful if our `prev_hash` chains ever have a "you must obey current state" rule.

**Avoid:**

- **State-resolution-v2 is famously hard** ([Matrix.org "stateres v2 for the hopelessly unmathematical"](https://matrix.org/docs/older/stateres-v2/)). It exists because Matrix has multi-writer state with no single-writer invariant. **We have a single-writer-per-record invariant; we do not need state res. Do not invent state res by accident.**
- **Key revocation lag.** Keys can't be revoked retroactively beyond the 7-day window — a compromised key has a guaranteed exploit window. Plan key-compromise response accordingly.
- **DNS-based delegation in Matrix federation is a known weak point** (deprecated SRV records, requires TLS over DNS). We dodge this by being LAN-only, but if we ever federate cohorts across the WAN, this is a known sharp edge.
- **Synapse has shipped DoS advisories for incorrect application of auth rules** ([GHSA-jhjh-776m-4765](https://github.com/matrix-org/synapse/security/advisories/GHSA-jhjh-776m-4765)). Lesson: the auth-check logic must be *fast* — if it can be made expensive by a malicious event, you have a DoS.

### 2.7 libp2p gossipsub

**What it is, one sentence.** A pubsub mesh protocol where peers maintain a small "mesh" of trusted-enough peers for eager push and use "gossip" (lazy IHAVE/IWANT) to fill in for peers outside the mesh, with a peer-scoring system hardened against eclipse / sybil / spam attacks in v1.1. [gossipsub v1.1 spec](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) | [IPFS Blog: gossipsub v1.1](https://blog.ipfs.tech/2020-05-20-gossipsub-v1.1/)

**Steal:**

- **Timed cache of seen message IDs** for replay deduplication — exactly what we want at the envelope layer. Size + TTL the cache so it covers a worst-case network partition. [gossipsub v1.1 spec](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
- **Validators are explicit pluggable functions** that return Accept / Reject / Ignore. Reject penalizes the sender, Ignore drops silently. We should mirror this trichotomy for "bad envelope" handling. [rust-libp2p gossipsub](https://docs.rs/libp2p/latest/libp2p/gossipsub/struct.Behaviour.html)
- **Explicit peering** for trusted operators — connections outside the scoring system. For a 50-peer trusted cohort, every peer relationship is effectively "explicit peering." Worth borrowing the term.

**Avoid:**

- **Don't implement peer scoring.** It's 7 parameters + decay factors and exists because gossipsub runs on the open Ethereum/Filecoin internet. With 50 trusted peers on a LAN, the scoring complexity is pure cost. [gossipsub v1.1 §peer scoring](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md)
- **The IHAVE/IWANT lazy pull is overkill** for cohort-scale state. It's designed for thousands of nodes where eager push to everyone is bandwidth-fatal.
- **Mesh GRAFT/PRUNE machinery** is solving "the topology is too dense" — a problem we don't have.

### 2.8 IPFS pubsub

**What it is, one sentence.** Topic-based pubsub built on libp2p gossipsub (with a legacy floodsub for tiny networks), used as the messaging substrate for IPFS and as the basis for Filecoin / Ethereum 2.0 message propagation. [GossipSub paper PDF](https://research.protocol.ai/blog/2019/a-new-lab-for-resilient-networks-research/PL-TechRep-gossipsub-v0.1-Dec30.pdf)

**Steal:**

- **Topic naming as a coarse routing primitive.** "Topic per record_id" is too granular; "topic per cohort" with the envelope's record_id as a routing hint is the standard pattern.
- **Authenticated messages, validated *before* propagation.** "All pubsub messages are authenticated and must be syntactically validated before being propagated further." [libp2p-pubsub on Medium](https://medium.com/rahasak/libp2p-pubsub-with-golang-495539e6aae1) Same rule for us — verify ed25519 signature before re-broadcasting.

**Avoid:**

- IPFS pubsub has historically been ["best-effort and unreliable"](https://news.ycombinator.com/item?id=25407193) — no guarantees on delivery. If we use pubsub for record announcement, we still need the manifest-diff handshake for catch-up.
- Topic-flooding attacks: a malicious peer can publish a million different topics. If we ever expose topics to user input, gate it.

### 2.9 Veilid

**What it is, one sentence.** A DHT + private-routing framework (think "TOR meets IPFS") that gives you GetValue/SetValue over a multi-writer DHT, with onion-style safety routes + private routes for anonymous RPC. [Veilid how-it-works](https://veilid.com/how-it-works/) | [Veilid RPC](https://veilid.com/how-it-works/rpc/)

**Steal:**

- **Multi-writer DHT records with subkeys + sequence numbers** as a discovery primitive — if we ever need WAN-side peer discovery without a server, Veilid's DHT is the closest thing to "Bonjour over the internet." [Veilid private routing](https://veilid.com/how-it-works/private-routing/)
- **Schemas on DHT records** ("DHT record subkeys have sequence numbers and are eventually consistent across multiple writes and background synchronizations") — same eventual-consistency model we have, with structured keys. Worth a look if we extend beyond LAN.

**Avoid:**

- **Veilid is wholly designed for WAN privacy.** On a LAN cohort, it's solving the wrong problem (anonymity vs. discovery). The framework would add huge dependency surface.
- **Onion routing introduces ~3 hops of latency.** Bad fit for a LAN protocol where sub-100ms is reasonable.

### 2.10 Secure Scuttlebutt (SSB)

**What it is, one sentence.** Per-author append-only signed feeds gossipped over LAN + WAN, with Ed25519 identities, the Secret Handshake (a 4-step authenticated key exchange) for transport security, and `createHistoryStream` / EBT (epidemic broadcast trees) for replication. [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/) | [SSB Wikipedia](https://en.wikipedia.org/wiki/Secure_Scuttlebutt)

**Steal:**

- **LAN discovery: UDP broadcast every 1 second with `host:port:~shs:pubkey`.** Same shape as mDNS for our purposes, but the pubkey is in the announcement — so peer auth and discovery are *combined into the same packet*. [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/) Strongly consider putting the ed25519 pubkey into the mDNS TXT record for the same effect.
- **Secret Handshake** for authenticated key exchange — establishes mutual auth + shared encryption keys + ephemeral forward secrecy in 4 messages. Reference implementation for our LAN transport layer if/when we add encrypted channels. [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
- **EBT (Epidemic Broadcast Trees)** uses vector clocks to track per-feed sequence numbers and exchange "notes" indicating which feeds each side wants to send/receive. Very close to our manifest in spirit, but lazier — peers explicitly opt in to feeds.
- **Pub / Room servers as bootstrap infrastructure** — single-purpose nodes whose only job is "host invite codes + relay messages." If we ever need WAN bridging for cohorts, "shape-rotator-room" should look like an SSB room: it does NOT host data, only invites + relays.
- **Invite codes are `host:port:pubkey:seed`** with use-count limits, expiry, and (optionally) automatic follow-on-redemption. Template for cohort onboarding.

**Avoid:**

- **The forked-feed problem is unsolved in SSB.** A user appending from two devices in parallel forks their own feed; the SSB network's response is "drop the second-arriving fork and ban the identity." [ssb-db#157](https://github.com/ssbc/ssb-db/issues/157) For us, single-writer-per-record has the same shape — pick a policy before you ship.
- **Canonical JSON for signing is fragile**: field order, whitespace, and number encoding all matter. Many implementations have shipped subtle bugs around this. **Use deterministic canonical CBOR or a binary format with a pinned encoder**, not JSON.
- **Identity loss is terminal.** Losing your secret key in SSB means starting over with a new identity. There's no "social recovery." Multi-device == fork risk == identity reset.
- **Blob size limit of 5MB by default** because feeds are eager-pushed. If we ever put attachments on records, plan size limits early.
- **Nonce reuse** in the encrypted box stream is a key-recovery vulnerability. If you implement Secret Handshake or any AEAD, **per-direction nonce counter, never reset**.

### 2.11 HLC — Hybrid Logical Clocks

**What it is, one sentence.** A 64-bit hybrid timestamp combining ~48 bits of physical wall-clock millis with ~16 bits of monotonic logical counter, designed by Kulkarni & Demirbas (2014) to give you Lamport-style causality *and* human-readable timestamps in one value. [Kulkarni & Demirbas, 2014 PDF](https://cse.buffalo.edu/tech-reports/2014-04.pdf) | [Hybrid Clock writeup](https://singhajit.com/distributed-systems/hybrid-clock/)

**Steal (this is the big one):**

- **Replace `time.time()` LWW with HLC LWW.** Almost zero migration cost: an HLC is 64 bits, comparison is integer comparison. The update rule:

  - **Local event:** `new_l = max(prev_l, wall_clock_ms); new_c = (new_l == prev_l) ? prev_c + 1 : 0`
  - **Receive event with `(l_m, c_m)`:** `new_l = max(prev_l, l_m, wall_clock_ms); new_c = ` (carefully chosen so the result strictly exceeds all inputs).

- **CockroachDB pattern**: maxOffset is configured (e.g. 500ms); if a node's clock skew exceeds 80% of maxOffset, the node refuses to participate. Use this to detect "my clock is broken" instead of silently corrupting LWW. [Hybrid Clock writeup](https://singhajit.com/distributed-systems/hybrid-clock/)
- **Quarantine envelopes from the far future.** If an envelope's HLC physical component is more than (configurable) `MAX_SKEW_MS` ahead of local wall clock, set aside in a quarantine table rather than accept. Re-evaluate later. This bounds the damage of a "I crank my clock to year 3000" attack.

**Avoid:**

- **HLC does NOT detect concurrent events** — that's vector clocks' job. Two HLCs can compare strictly less-than even when the underlying writes were truly concurrent. For LWW that's fine (you wanted *a* tiebreak), but don't sell HLC as causality detection.
- **HLC degrades to Lamport clock if NTP is broken.** "Requires healthy NTP; significant clock drift degrades performance." [Hybrid Clock writeup](https://singhajit.com/distributed-systems/hybrid-clock/) On a LAN with chronyd/ntpd this is fine; if peers run on devices without sync, expect logical-counter inflation.

### 2.12 CRDTs the implementer should NOT use — but should understand the boundary

**Single-writer-per-record means LWW-Register is sufficient.** Everything else in the CRDT zoo is solving a problem we don't have. Key non-fits:

- **OR-Set / 2P-Set / G-Set** — for multi-writer sets where concurrent add/remove must converge without conflict. Our records have a single author; if you ever want "co-authored records," you need OR-Set semantics. [Wikipedia: CRDT](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type)
- **RGA / LSEQ / Yata / Treedoc** — sequence CRDTs for collaborative text. If you ever model record *content* as collaboratively-editable text, this is where you go; until then, ignore. [Wikipedia: CRDT](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type)
- **LWW-Element-Set** — almost what we have, but it allows reinsert-after-delete. Our single-writer model makes this trivially solvable by sequencing the deletes through the same author.
- **MV-Register** (multi-value) — when you need to *preserve* concurrent writes for human resolution instead of throwing one away. If users ever complain "my edit got lost," consider MV-Register for the affected record type instead of LWW.

**Garbage collection is the hard problem CRDTs share with our design** — "CRDTs achieve convergence by monotonically accumulating information, but production systems can't grow unbounded forever." [CRDT Dictionary, Duncan 2025](https://www.iankduncan.com/engineering/2025-11-27-crdt-dictionary/) See §3.5 for our pruning strategy.

### 2.13 Set-reconciliation primitives

**Minsky / Trachtenberg CPI sketches.** Information-theoretically optimal for small differences. Scales poorly: at ~4k elements CPU degrades sharply, and elements are typically limited to 64-bit. Useful for niches (Bitcoin's `minisketch` for txid reconciliation), not for general-purpose record sync. [logperiodic.com RBSR §alternatives](https://logperiodic.com/rbsr.html)

**IBLT (Invertible Bloom Lookup Tables) — Eppstein/Goodrich/Uyeda/Varghese.** Probabilistic; one round trip; fails *completely* if you overestimate the symmetric difference (you have to size the IBLT a priori). Recent RIBLT (rateless IBLT) variants fix this. [Eppstein et al. IBLT PDF](https://people.cs.georgetown.edu/~clay/classes/fall2017/835/papers/IBLT.pdf) | [Smaller IBLT 2024](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2024.54)

**Range-Based Set Reconciliation — Meyer 2023 (Willow / Negentropy).** Recursive partitioning; log-bounded round trips in dataset size; stateless servers possible; collision-resistant if fingerprint is not XOR. **The mature winner for non-tiny datasets.** [Meyer 2023 arXiv](https://arxiv.org/abs/2212.13567) | [Negentropy NIP-77](https://github.com/nostr-protocol/nips/blob/master/77.md)

**Bloom-filter-over-hashes (Automerge, Kleppmann/Howard).** Cheap; one round trip in 99% of cases; small false-positive rate is fine for sync (extra RTT) but bad for security (DoS). [Kleppmann blog](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html)

**Prolly Trees (Dolt / Noms).** Merkle tree over content-defined-chunked B-tree blocks; diff scales with the size of the difference, not the size of the tree; shared blocks across versions deduplicate naturally. [Dolt prolly tree docs](https://docs.dolthub.com/architecture/storage-engine/prolly-tree) | [Merklizing key/value store (Gustafson)](https://joelgustafson.com/posts/2023-05-04/merklizing-the-key-value-store-for-fun-and-profit/) Worth knowing about; not needed for 50-peer cohorts.

**Verdict for our scale:** at ≤10k records, plain manifest diff. At 10k–1M records, Automerge-style bloom or RBSR (RBSR if you expect adversarial inputs ever). >1M, RBSR or prolly trees.

---

## 3. Pattern Survey

### 3.1 Replay defenses

| Pattern | Used by | Notes |
|---|---|---|
| **Cache content-hash of accepted envelopes, dedup at ingress** | Hypercore, SSB, Matrix, gossipsub | Cheap, universal. Cache eviction policy: keep until the envelope's HLC is older than `MAX_CLOCK_SKEW + MAX_PARTITION_DURATION`. |
| **Dedup by signature bytes** | Some JWT systems | **Avoid.** Ed25519 signatures have a known malleability gotcha — non-canonical `S` (where `S >= L`) is accepted by many verifiers, letting an attacker mint two distinct "valid" signatures of the same content. [Ed25519 forgery advisory](https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw) Dedup by `content_hash` instead. |
| **`txnId`-based at-most-once on the transport** | Matrix federation | Cheap idempotency; complementary to envelope-level dedup. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/) |
| **Timed message cache + score penalty for replays** | libp2p gossipsub | Memcache holds recent IDs; replays are penalized via P3 score. We don't need scoring but should keep the timed cache. [gossipsub v1.1 spec](https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md) |
| **Nonce in encrypted transport, never reused** | SSB Secret Handshake, Hypercore replication | Mandatory if our LAN transport ever encrypts. Per-direction incrementing counter. |
| **JTI (JWT ID) + recent-jti cache** | Token-based auth systems | Same pattern as content-hash dedup but for auth tokens; relevant if we adopt UCAN-style capability tokens. [SSOJet JWT validation](https://ssojet.com/jwt-validation/validate-jwt-using-eddsa-in-akka-http/) |

**Recommendation:** **content-hash dedup cache with TTL = `2 * MAX_CLOCK_SKEW_MS + MAX_NETWORK_PARTITION_MS`**, falling back to "if it's older than the local LWW value, drop silently." That's protocol-layer replay defense at minimum cost.

### 3.2 Clock-skew handling

| Pattern | Used by | Notes |
|---|---|---|
| **HLC (Hybrid Logical Clock)** | CockroachDB, FoundationDB, MongoDB causal sessions | Captures causal order *and* keeps human-readable wall-clock-ish timestamps; almost free upgrade from wall-clock LWW. [Kulkarni & Demirbas, 2014 PDF](https://cse.buffalo.edu/tech-reports/2014-04.pdf) |
| **Drop future-dated events** | Many production systems | If `event.ts > now + MAX_SKEW`, refuse. Hard reject is brutal; **quarantine** is friendlier. |
| **Max-skew kill switch** | CockroachDB | If your node's clock skew exceeds 80% of `maxOffset`, suicide. Stops you corrupting cluster state. [Hybrid Clock writeup](https://singhajit.com/distributed-systems/hybrid-clock/) |
| **Lamport clocks + tiebreak** | Many academic systems | Pure causal order, no wall clock. Loses "when did this happen" intuition. |
| **`origin_server_ts` in signed payload** | Matrix federation | Skew is *visible* to receivers because it's part of the signed payload — they can flag "event claims to be from 12h in the future." [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/) |
| **NTP at the OS layer + small tolerance window** | Almost everyone | Necessary baseline; insufficient alone (see all the LWW-loses-data writeups). [Crowe LLP cybersecurity-watch](https://www.crowe.com/cybersecurity-watch/poisoning-attacks-round-2-beyond-netbios-llmnr) |

**Recommendation:** HLC in the envelope, hard-reject envelopes more than `MAX_SKEW_MS` ahead of local wall clock (default 60s for LAN), quarantine those rather than drop, surface "your clock is wrong" warning to the user when their own clock disagrees with the cohort median.

### 3.3 Authorization / cohort membership

| Pattern | Used by | Notes |
|---|---|---|
| **Shared secret as write-capability** | Earthstar | Whoever knows the share secret can write. Simple, no revocation. [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works) |
| **Cohort roster (signed list of pubkeys)** | Custom for trusted cohorts | Ship `cohort.json` with `{members: [pubkey, ...], roster_signature: ...}`. Every peer validates membership against the roster. Rotation = new roster. Could be the simplest answer for 50-peer cohorts. |
| **Capability tokens (UCAN, Meadowcap)** | UCAN (Fission), Meadowcap (Willow) | JWT-shaped tokens that bestow specific rights; delegable, narrowable, expirable, verifiable offline. [UCAN spec](https://ucan.xyz/specification/) | [Meadowcap spec](https://willowprotocol.org/specs/meadowcap/index.html) |
| **Path-prefix ownership via author binding** | Earthstar (`~author` paths), Meadowcap (subspaces) | Author cryptographically owns a path/subspace; writes to that path require signatures from that key. Maps directly onto single-writer-per-record. |
| **Invite codes as a one-shot capability** | SSB pubs/rooms | `host:port:pubkey:seed` blob; use-count/expiry/auto-follow attached. Operational pattern, not crypto. [SSB invite spec](https://ssbc.github.io/ssb-http-invite-spec/) |
| **Web of trust (follow graph)** | SSB | Replication is gated on whether you follow the author. No protocol-level "ban," just "everyone unfollows." |
| **Power levels / room-state-style authz** | Matrix | Multi-level RBAC encoded in signed state events. Powerful but invokes state-resolution; **almost certainly overkill for us**. [Matrix Room v2 spec](https://spec.matrix.org/unstable/rooms/v2/) |

**Recommendation:** Start with **signed cohort roster** — a `cohort.json` containing the list of authorized pubkeys plus an "operator" signature. Every envelope's author is checked against the roster. Roster updates are themselves signed envelopes. If/when you need finer-grained delegation (write access to specific records or paths), step up to **Meadowcap communal-namespace capabilities**, not UCAN — Meadowcap's communal model is purpose-built for "one author owns this subspace" and pairs naturally with the rest of the Willow ecosystem.

### 3.4 Bootstrap (key distribution + first-contact)

| Pattern | Used by | Notes |
|---|---|---|
| **Pubkey in mDNS TXT record** | (would-be) | Combine discovery + identity announcement. Peer X says "I'm at 10.0.0.5:7777, I'm pubkey ABCD." Receiver verifies pubkey is in cohort roster. **Recommended baseline.** [HackMag mDNS pentest](https://hackmag.com/security/multicast-dns-pentest) |
| **Invite codes with key seed** | SSB pubs/rooms | One-shot or N-use; carries `host:port:pubkey:seed`. [ssb-invite README](https://github.com/ssbc/ssb-invite) |
| **Share address + secret out of band** | Earthstar | Operator distributes the secret via Signal/email/QR. Cohort is "anyone who has the secret." [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works) |
| **DHT pubkey lookup** | Veilid, libp2p Kademlia | "Look up this pubkey, find their addrs." Overkill on LAN; useful for WAN federation. [Veilid how-it-works](https://veilid.com/how-it-works/) |
| **DID-based discovery** | UCAN ecosystem | Decentralized Identifiers; pubkey-as-identifier-as-URI. Heavyweight but interop-friendly. [UCAN spec](https://ucan.xyz/specification/) |

**Recommendation:** **Signed cohort roster (out of band) + mDNS announcement carrying pubkey + handshake that proves possession of the matching private key.** Three-step bootstrap, no DHT, no per-peer invite codes for trusted cohorts.

### 3.5 Eviction / pruning when history grows unbounded

| Pattern | Used by | Notes |
|---|---|---|
| **Per-record snapshot + truncate** | Raft, Mesos replicated log | Periodically materialize the LWW state into a "snapshot" envelope (also signed); peers learning the system can install the snapshot and skip the prefix. Old history can be pruned locally. [Mesos replicated log](https://mesos.apache.org/documentation/latest/replicated-log-internals/) |
| **Ephemeral with TTL (`deleteAfter`)** | Earthstar | Record carries an expiry; libraries delete expired records at least once an hour. Good for transient state, doesn't solve unbounded write history. [Earthstar es.5 data format](https://earthstar-project.org/specs/data-spec-es5) |
| **Sparse replication / partial download** | Hypercore, Hyperbee, Earthstar | Each peer only needs whatever subset of history matters to them. Pruning is a local decision; the canonical full history lives somewhere. [Hyperbee README](https://github.com/holepunchto/hyperbee) |
| **Sedimentree** | Automerge Beelay (research) | Compact older changes into "sedimentary" blocks, recent stays granular. Designed for unbounded edit history of long-lived CRDT docs. [Beelay sedimentree.md](https://github.com/automerge/beelay/blob/main/docs/sedimentree.md) |
| **Content-addressed dedup of shared blocks** | Prolly trees (Dolt/Noms) | Blocks shared across versions stored once. Helps storage, doesn't fix "history grows linearly with writes." [Dolt prolly tree docs](https://docs.dolthub.com/architecture/storage-engine/prolly-tree) |
| **Manual epoch rotation** | Earthstar (no member revocation) | When a share gets unwieldy, make a new share and migrate. Operational, not protocol-level. |

**Recommendation:** **Snapshot envelopes** (one per `record_id`, signed by author, encoding "the LWW state as of HLC T, with proof-of-extension from the chain"). When a snapshot reaches the cohort, all peers can prune older entries for that record_id locally. Combine with a configurable retention window ("keep at least the last N versions or last D days, whichever is larger").

---

## 4. Footgun Checklist

Specific traps to avoid, each with the protocol that demonstrated the hazard.

- **Wall-clock LWW silently discards data when clocks disagree** — concurrent writes with skewed timestamps lose the "earlier in real time but later in clock time" write. Cassandra, DynamoDB. Use HLC. [Medium: When QUORUM Isn't Enough](https://medium.com/@mehedees/when-quorum-isnt-enough-how-distributed-clock-skew-silently-discards-data-mehedee-siddique-56b22d0dbd31)

- **Single-writer fork (same author, two devices)** silently corrupts the `prev_hash` chain — Hypercore, SSB. Detect by tracking "highest seq we've seen from this author" and flagging incompatible chains. [Hypercore FAQ](https://github.com/tradle/why-hypercore/blob/master/FAQ.md) | [ssb-db#157](https://github.com/ssbc/ssb-db/issues/157)

- **mDNS announces hostname + service info to anyone on the LAN, including coffee-shop wifi neighbors** — Bonjour. Never put cohort-identifying info in the mDNS announcement that you wouldn't write on a sticker. Pubkey is fine (it's a public key); cohort name might leak who you are. [HackMag mDNS pentest](https://hackmag.com/security/multicast-dns-pentest)

- **Ed25519 signature malleability** — non-canonical `S` values are accepted by some implementations, breaking "dedup by signature bytes." Dedup by `content_hash` instead. [Ed25519 forgery advisory](https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw)

- **JSON canonical serialization for signing is brittle** — SSB has shipped multiple bugs around field ordering / whitespace / number encoding. Use deterministic canonical CBOR or a pinned binary encoder. [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)

- **Bloom-filter sync has a DoS vector at the false-positive rate** — Automerge has been demonstrated degrading to 97% FPR under adversarial input. Fine in trusted cohorts, not safe in open ones. [logperiodic.com RBSR](https://logperiodic.com/rbsr.html)

- **Malformed sync messages crash CRDT engines** — Automerge WASM crash on malformed sync message (#855). Treat the parser as the security boundary; fuzz it; reject before deserializing into protocol state. [Automerge#855](https://github.com/automerge/automerge/issues/855)

- **Replication-stream nonce reuse is a key-recovery bug** — SSB box stream; Hypercore replication. Per-direction monotonic counter, never reset on reconnect (or rekey on reconnect). [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)

- **No member revocation means cohort churn requires re-keying everyone** — Earthstar's "make a new share and migrate" pattern. Build the rotation tool before you need it. [Earthstar how-it-works](https://earthstar-project.org/docs/how-it-works)

- **Identity-key loss is terminal in feed-per-author models** — SSB. If a user's device dies and they didn't back up the private key, their feed dies too. Document recovery procedure (mnemonic backup, multi-device key sharing) explicitly. [SSB Wikipedia](https://en.wikipedia.org/wiki/Secure_Scuttlebutt)

- **mDNS spoofing on hostile LANs** lets an attacker advertise a fake peer — pentest writeups. Auth happens *after* discovery; never trust mDNS-discovered peers until they prove pubkey ownership. [HackMag mDNS pentest](https://hackmag.com/security/multicast-dns-pentest)

- **Key revocation has a fundamental lag** — Matrix caps `valid_until_ts` at 7 days, the window during which a compromised key can still federate events. Plan for "compromised key, what now?" before someone loses their laptop. [Matrix server-server spec v1.9](https://spec.matrix.org/v1.9/server-server-api/)

- **Auth-check perf is a DoS vector** — Synapse GHSA-jhjh-776m-4765 (DoS via incorrect application of auth rules). Keep auth checks O(1) per envelope; never recurse over the chain at validation time. [Synapse advisory](https://github.com/matrix-org/synapse/security/advisories/GHSA-jhjh-776m-4765)

- **State resolution is a tar pit** — Matrix needed v2 (and is working on v2.1 / "Project Hydra") because the original got it wrong. **Don't write state resolution.** The single-writer-per-record invariant is what saves us; defend it. [Matrix.org State Res v2.1 guide](https://matrix.org/docs/spec-guides/state-res-2.1/)

- **Awareness / presence channels become trust holes if unsigned** — y-protocols explicitly says "awareness payloads are not authenticated, a malicious peer can claim arbitrary cursor or presence data." [y-protocols PROTOCOL.md](https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md) Sign every channel that affects UI, not just record state.

- **RBSR with XOR fingerprints is collision-attackable** — Meyer's paper, logperiodic.com analysis. If you adopt RBSR, use addition mod 2²⁵⁶, not XOR. [logperiodic.com RBSR §security](https://logperiodic.com/rbsr.html)

- **IBLT fails completely if the size estimate is wrong** — Eppstein/Goodrich. Use only if symmetric difference is bounded and known, or move to rateless IBLT. [Eppstein et al. IBLT PDF](https://people.cs.georgetown.edu/~clay/classes/fall2017/835/papers/IBLT.pdf)

- **CRDT garbage collection is unsolved as a general problem** — every CRDT system reports it as the hardest practical issue. Plan pruning early; don't ship an "infinite history" promise. [Ian Duncan CRDT Dictionary](https://www.iankduncan.com/engineering/2025-11-27-crdt-dictionary/)

- **Topic flooding** in pubsub systems — IPFS pubsub has been spammed with thousands of topics. If you ever expose topic names to user input, gate it.

- **Bloom filter parameters can't be tuned without measurements** — Kleppmann's analysis assumes 10 bits/commit, 0.8% FPR; in production these need to adapt to the size of "changes since last sync." Hardcoding them is a footgun. [Kleppmann blog](https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html)

- **Ephemeral / TTL documents disappear only if someone runs the cleanup** — Earthstar requires "at least one library running at least every hour" to actually expire docs. Document the operational requirement or pick a different deletion model. [Earthstar es.5 data format](https://earthstar-project.org/specs/data-spec-es5)

---

## 5. Recommendations

Top 5 concrete changes / additions to the "manifest + diff + LWW + signed envelopes" design that meaningfully harden it without exploding scope:

### Rec 1. Replace wall-clock LWW with HLC LWW

**Cost:** ~50 LOC; envelope grows by 0 bytes (HLC fits in 64 bits, same as a unix-ms timestamp).
**Why:** Wall-clock LWW silently corrupts state under any clock skew. HLC fixes this without giving up wall-clock readability and gives you free causality tracking for the LWW comparison. Tiebreak on `lex(content_hash)` as already specified.
**How:** Every envelope carries `hlc_ts: u64` (48 bits ms-since-epoch | 16 bits counter). Comparison is plain integer comparison. On send, `max(local_hlc, wall_clock_ms_now)`; on receive, `max(local_hlc, incoming_hlc, wall_clock_ms_now)` with the counter incremented appropriately. Quarantine envelopes more than `MAX_SKEW_MS` (default 60_000) ahead of local wall clock. [Kulkarni & Demirbas, 2014](https://cse.buffalo.edu/tech-reports/2014-04.pdf)

### Rec 2. Specify the single-writer-fork policy *now*, before the first multi-device client

**Cost:** ~1 page of spec + a few hundred LOC of detection.
**Why:** Every protocol in the survey (Hypercore, SSB, Matrix) has been bitten by "the same identity publishes two divergent histories." Our `prev_hash` chains are exactly as vulnerable. With no policy, the first user with a phone and a laptop will silently corrupt their record_id.
**How:** Track `{author_pubkey, record_id} → (highest_seen_seq, last_hash)` for every chain. If a new envelope from the same author has a `prev_hash` that doesn't extend the known head, the chain has forked. Default response: **accept the first-seen branch, quarantine subsequent branches, log to operator, never replicate quarantined branches**. (SSB-style.) Alternative response: pick the branch with the higher HLC at the divergence point; surface conflict to UI. Pick one and document it.

### Rec 3. Combine discovery + identity in the mDNS announcement; cohort-roster gate

**Cost:** ~100 LOC; one signed JSON file ships with the cohort.
**Why:** mDNS is untrusted broadcast. The cohort needs an *out-of-band* roster anyway (you can't bootstrap trust over an attacker's network). Putting the pubkey *into* the mDNS TXT record lets us run roster-check at discovery time and reject non-cohort peers before establishing a TCP connection.
**How:**
- mDNS TXT record carries `pubkey=<base64 ed25519>`, `cohort_id=<short>`, `proto_v=<u8>`.
- Cohort roster is a signed JSON file `cohort.json`: `{cohort_id, members: [{pubkey, name, added_ts}, ...], roster_seq, operator_pubkey, operator_signature}`.
- On mDNS discovery, immediately gate: does `pubkey` appear in roster? If not, drop. If yes, open a connection and require an HLC-timestamped challenge-response signed by the matching private key as the first protocol message.
- Roster updates ship as signed envelopes (single-writer = operator). [SSB invite spec for inspiration](https://ssbc.github.io/ssb-http-invite-spec/) | [HackMag mDNS pentest](https://hackmag.com/security/multicast-dns-pentest)

### Rec 4. Content-hash dedup cache + ed25519-canonical-signature requirement

**Cost:** ~200 LOC; one sqlite table.
**Why:** Cheapest replay defense in the world; protects against benign duplicates (re-broadcast, retry storms) and adversarial replays (a malicious peer storing old envelopes and re-injecting them). The signature-canonicalization requirement closes the Ed25519 malleability gap.
**How:**
- On ingress, compute `content_hash = SHA-256(canonical_serialization(envelope_without_signature))`.
- Reject if `content_hash` is in the dedup cache.
- TTL the cache at `2 * MAX_SKEW_MS + MAX_NETWORK_PARTITION_MS` (default: 24h).
- Require that ed25519 signatures use canonical `S` (i.e. `S < L`). Most modern libraries (libsodium, NaCl, ring) reject non-canonical by default; verify ours does.
- Storage cost: 32-byte hash per envelope, GC'd by TTL. At 10k envelopes/day for 24h, ~320KB.
[Ed25519 forgery advisory](https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw)

### Rec 5. Snapshot envelopes + retention window for unbounded-history defense

**Cost:** ~1 page of spec, ~500 LOC.
**Why:** "Full version history kept locally" doesn't scale to power users who edit the same record 10k times. Every survey protocol that has solved this — Hypercore (sparse), Raft (snapshot+truncate), Automerge (sedimentree), Earthstar (ephemeral) — does it differently. Snapshot envelopes are the simplest: the author periodically issues a "snapshot of record_id X as of HLC T, with prev_hash pointing to the latest entry I'm snapshotting" envelope. New peers can install snapshots and skip the prefix.
**How:**
- A *snapshot envelope* is a regular envelope with `kind=snapshot, record_id, snapshot_state, snapshot_of_hash=<prev_hash of latest snapshotted entry>, hlc_ts`.
- On reception, peers may prune entries with `record_id = X` and `hlc_ts < snapshot.hlc_ts` from local storage, *if* the snapshot has been verified and they're past the retention window.
- Default retention window: `max(last_N_versions=10, last_D_days=30)`. Tune per record_id type.
- Snapshots are still signed by the original author of the record. (Single-writer invariant preserved.)
[Mesos replicated log](https://mesos.apache.org/documentation/latest/replicated-log-internals/) | [Automerge sedimentree](https://github.com/automerge/beelay/blob/main/docs/sedimentree.md)

---

### Bonus: things to **explicitly defer**

- **Range-Based Set Reconciliation (RBSR/Negentropy/Willow).** Worth knowing, worth ~not implementing at 50 peers / ≤10k records. Revisit when manifest size becomes measurably painful (the inflection is ~10k records or wire-cost > 1% of sync time). [Meyer 2023](https://arxiv.org/abs/2212.13567)
- **Capability tokens (UCAN/Meadowcap).** Defer until the cohort roster gets too coarse. The likely trigger is "we need users who can read but not write" or "we need a guest user who can only post in one record_id." [Meadowcap spec](https://willowprotocol.org/specs/meadowcap/index.html)
- **Encrypted LAN transport (Secret Handshake / Noise).** Defer if the LAN is genuinely trusted (cohort = home network or office VPN). Adopt if cohort = "people on the same hotel wifi." Don't reinvent — use Noise IK or borrow SSB's Secret Handshake design wholesale. [SSB Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
- **CRDT migration.** If a record ever needs multi-author concurrent edits (e.g. shared document content), step up to the appropriate CRDT (LWW-Element-Set for sets, RGA for text). Don't try to "make our LWW protocol multi-writer" — that road leads to state resolution v2. [Ian Duncan CRDT Dictionary](https://www.iankduncan.com/engineering/2025-11-27-crdt-dictionary/)

---

## References

- Holepunch / Hypercore: <https://hypercore-protocol.github.io/new-website/protocol/>, <https://github.com/holepunchto/hypercore>, <https://www.datprotocol.com/deps/0002-hypercore/>, <https://www.datprotocol.com/deps/0010-wire-protocol/>, <https://github.com/holepunchto/hyperbee>, <https://github.com/tradle/why-hypercore/blob/master/FAQ.md>
- Earthstar: <https://earthstar-project.org/docs/how-it-works>, <https://earthstar-project.org/specs/data-spec-es5>, <https://earthstar-project.org/specs/data-spec>, <https://gwil.garden/posts/willow-earthstar-big-year.html>
- Willow / Iroh / Meadowcap: <https://willowprotocol.org/specs/3d-range-based-set-reconciliation/index.html>, <https://willowprotocol.org/specs/meadowcap/index.html>, <https://willowprotocol.org/specs/rbsr/index.html>, <https://github.com/n0-computer/iroh-docs>, <https://docs.rs/iroh-docs/latest/iroh_docs/>, <https://github.com/earthstar-project/willow-rs>
- Automerge: <https://martin.kleppmann.com/2020/12/02/bloom-filter-hash-graph-sync.html>, <https://posit-dev.github.io/automerge-r/articles/sync-protocol.html>, <https://automerge.org/automerge/automerge/sync/struct.State.html>, <https://github.com/automerge/automerge/issues/855>, <https://github.com/automerge/automerge/issues/536>, <https://github.com/automerge/beelay/blob/main/docs/sedimentree.md>
- Yjs / y-protocols: <https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md>, <https://github.com/yjs/y-protocols/blob/master/sync.js>
- Matrix: <https://spec.matrix.org/v1.9/server-server-api/>, <https://spec.matrix.org/unstable/rooms/v2/>, <https://matrix.org/docs/older/stateres-v2/>, <https://matrix.org/docs/spec-guides/state-res-2.1/>, <https://github.com/matrix-org/synapse/security/advisories/GHSA-jhjh-776m-4765>, <https://matrix.org/blog/2025/08/project-hydra-improving-state-res/>
- libp2p gossipsub: <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.1.md>, <https://github.com/libp2p/specs/blob/master/pubsub/gossipsub/gossipsub-v1.0.md>, <https://blog.ipfs.tech/2020-05-20-gossipsub-v1.1/>, <https://research.protocol.ai/blog/2019/a-new-lab-for-resilient-networks-research/PL-TechRep-gossipsub-v0.1-Dec30.pdf>
- Veilid: <https://veilid.com/how-it-works/>, <https://veilid.com/how-it-works/private-routing/>, <https://veilid.com/how-it-works/rpc/>, <https://www.eff.org/deeplinks/2023/12/meet-spritely-and-veilid>
- SSB: <https://ssbc.github.io/scuttlebutt-protocol-guide/>, <https://en.wikipedia.org/wiki/Secure_Scuttlebutt>, <https://github.com/ssbc/ssb-invite>, <https://ssbc.github.io/ssb-http-invite-spec/>, <https://github.com/ssbc/ssb-db/issues/157>, <https://spec.scuttlebutt.nz/feed/messages.html>, <https://www.manyver.se/blog/announcing-ssb-rooms/>
- HLC: <https://cse.buffalo.edu/tech-reports/2014-04.pdf>, <https://singhajit.com/distributed-systems/hybrid-clock/>, <https://medium.com/@mehedees/when-quorum-isnt-enough-how-distributed-clock-skew-silently-discards-data-mehedee-siddique-56b22d0dbd31>
- CRDTs: <https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type>, <https://www.iankduncan.com/engineering/2025-11-27-crdt-dictionary/>
- Set reconciliation: <https://arxiv.org/abs/2212.13567>, <https://logperiodic.com/rbsr.html>, <https://github.com/nostr-protocol/nips/blob/master/77.md>, <https://github.com/hoytech/negentropy>, <https://people.cs.georgetown.edu/~clay/classes/fall2017/835/papers/IBLT.pdf>, <https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2024.54>, <https://docs.dolthub.com/architecture/storage-engine/prolly-tree>, <https://joelgustafson.com/posts/2023-05-04/merklizing-the-key-value-store-for-fun-and-profit/>
- Capabilities: <https://ucan.xyz/specification/>, <https://github.com/ucan-wg/spec>, <https://fission.codes/blog/a-guide-to-ucans/>
- mDNS / Bonjour: <https://hackmag.com/security/multicast-dns-pentest>, <https://hacktricks.wiki/en/network-services-pentesting/5353-udp-multicast-dns-mdns.html>, <https://www.crowe.com/cybersecurity-watch/poisoning-attacks-round-2-beyond-netbios-llmnr>, <https://blog.securelayer7.net/bonjour-service-mdnsresponder-exe-privilege-escalation-risks/>
- Ed25519 / replay: <https://github.com/digitalbazaar/forge/security/advisories/GHSA-q67f-28xg-22rw>, <https://eprint.iacr.org/2021/471.pdf>, <https://ssojet.com/jwt-validation/validate-jwt-using-eddsa-in-akka-http/>
- Snapshot / pruning: <https://mesos.apache.org/documentation/latest/replicated-log-internals/>
