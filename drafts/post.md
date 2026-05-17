---
draft: true
title: `searxng` wth frnds
status: WIP, circulating early for feedback
author: dmarz
date: 2026-04-18
tags: [search, p2p, indexing, self-sovereignty, the-machine]
---

> This is an early-stage research sketch, not a finalized spec. Parameters, formats, and even the basic shape are placeholders meant to be argued with. The goal at this stage is to find the right *seams* between subsystems and surface the questions that actually matter, not to ship a final design.

A few months ago I started experimenting with agent swarms for research. The intuition came from something like frame control in magic: if spending time imagining a problem from many different lenses and perspectives can 10x your own prompting, then designing scenarios with multiple agents working in parallel might scale that process up naturally.

A few iterations into [the experiment](https://github.com/Flashbots/research-agent-exp001), the hypothesis felt right (though too fuzzy to formally benchmark with current understanding). But my token spend also went vertical, and because I was often modifying scenarios and re-running them, I started looking into caching my search results. That's when it became obvious that the real bottleneck wasn't compute or tokens. It was the breadth and depth of search my agents could actually reach.

Around the same time I read Vitalik's [local-AI setup post](https://vitalik.eth.limo/general/2026/04/02/secure_llms.html), which makes the case that the substrate AI agents run on shouldn't depend on a centralized vendor. The same logic applies one layer up: the substrate agents *search through* shouldn't either. This document is the result of pulling on that thread.

## The frontier of search

**From a computational perspective**, search is three things layered: a *crawl* that fetches pages, an *index* that makes them retrievable by query, and a *ranker* that orders results when many match. All three have steep economies of scale, which is why the dominant model is one or a few centralized operators (Google in particular) doing the work and everyone else querying through them. Crawling at scale takes infrastructure; indexing takes petabytes; ranking well takes a long history of click signals to learn from.

**From a market perspective**, three buckets sit above this layer. Free engines (Google, Bing, DuckDuckGo) recoup their costs via ads, with your queries as the asset. Paid APIs ([Exa](https://exa.ai/), [Tavily](https://tavily.com/), [Brave](https://brave.com/search/api/), [SerpAPI](https://serpapi.com/)) wrap those engines or their own indexes and sell access via subscription, gated by a credential. Self-hosted aggregators ([SearXNG](https://github.com/searxng/searxng), pronounced "searching") avoid both business models because they don't host any index, just orchestrate calls. Independent indexers ([Marginalia](https://marginalia-search.com/), [Mwmbl](https://github.com/mwmbl/mwmbl), [Common Crawl](https://commoncrawl.org/)) exist but most struggle for sustainable funding at meaningful scale.

**From a research perspective**, search is rarely a single query. It's wide-then-narrow-then-wide-then-narrow: scope a topic, drill into a lead, scope adjacent territory, drill in again. Public engines are tuned for the head of the wide phase; the narrow phase is mostly the user clicking links by hand.

**From an agent perspective**, this strains. Agents query faster (a research loop fires dozens of queries per task), iteratively (each query informed by previous results, so latency compounds), and repetitively (most agent queries are queries the agent or its operator has already made before). They look like bots to anti-scraping defenses, even when their owner pays for access. And they search through a different distribution: less head ("who won the Super Bowl"), more long tail ("how do I get Loopix to work with libp2p"), because the head is mostly trivia and the tail is where research lives.

**A note on search ecology.** Scraping imposes real costs on crawled sites (bandwidth, server load), and most site owners don't love it when machines hammer them. Centralized search engines partly justify the cost by sending traffic back: the page hosting the answer at least gets visitors and possibly ad impressions. Local indexers don't generate that return flow. They consume the page once, cache it, and serve their owner forever after. At individual scale this is rounding error; at agent-swarm scale it could meaningfully shift content economics, plausibly creating a new sub-ecology of pages that explicitly opt in (or out) of being locally cached. No clean answer yet, worth flagging.

What this picture suggests: the centralized-crawler-plus-paid-aggregator stack was the right answer for human queriers. For an agent that compounds repeats, lives in the long tail, and hates per-hop latency, the substrate wants to look different. Local-first, community-shared, latency-conscious, with anonymity primitives that don't degrade under iteration. The rest of this document proposes three ideas for what that substrate could look like.

## Three Ideas for Agentic Search

This document proposes three extensions to a standard searxng setup. Each layers on top of the previous: Idea 1 alone is useful, Idea 2 multiplies it, Idea 3 reuses the substrate from Idea 2 for anonymity. The shared prerequisite for any of this: participants are building local indexes from their searxng results over time and storing the content. Without that, none of these ideas have anything to work with.

### Idea 1: Local-first indexes

The simplest version of all of this: every URL searxng returns to you lands in a local index. Polite fetch (rate-limit per-domain, honor `robots.txt`, identifying UA), main-content extraction, store. Over time your local index becomes a meaningful slice of the web shaped by what you've actually cared about. Mechanically this can sit in front of searxng as a proxy that intercepts queries: return local hits when sufficient; forward to searxng on miss; index whatever searxng returns. The metasearch becomes the *fallback*, not the front.

There is a long lineage of personal-archive tooling this builds on. [Memex](https://en.wikipedia.org/wiki/Memex) (Vannevar Bush, 1945) is the conceptual ancestor: a personal device that records everything you've read and lets you find associations through it. [Pinboard](https://pinboard.in/) (since 2009) is the long-running archival bookmark service. [Wallabag](https://wallabag.org/) (since 2013) is self-hosted read-later with a full local archive. [ArchiveBox](https://archivebox.io/) (since ~2017) is the closest functional match for what Idea 1 needs: a self-hosted internet archive that takes URLs from browser history, bookmarks, Pocket, or Pinboard, saves HTML / PDFs / media / WARC / SQLite, and builds full-text search over the lot. [Promnesia](https://github.com/karlicoss/promnesia) is a browser extension that surfaces "I've seen this before" annotations as you browse, building a graph of where you've been.

Combined with a local LLM, a local indrex closes the loop on running an autonomous research workflow against the web you've already touched, with no external dependency for repeats.

What Idea 1 can't do alone: help you find something you've never searched for. That's where Idea 2 comes in.

### Idea 2: Searxng with friends

Idea 1 gives you your slice of the web. Idea 2 connects slices across a trust circle. Three sources of results, all just **search engines** as far as searxng is concerned: the public engines searxng already aggregates, your own **indrex** from Idea 1, and your **friends'** indrexes. (Indrex = "index" portmanteau'd with [Indra's Net](https://en.wikipedia.org/wiki/Indra%27s_net), the Mahayana metaphor of an infinite net of jewels each reflecting all the others.) The result merger ranks and dedups across all three, querying in order: local first, then friends, then public.

Friends are added by hand, not by DHT or open peer discovery. Each friend periodically publishes a small **digest** of what their indrex covers (URL coverage, topic summary, recency); friends share *slices* of their indrex on request, only what's relevant to a query. The trust circle is small and explicit by design.

The substantive discussion of this idea (trust models for friends, content verifiability mechanisms, friend-to-friend authorization, long-tail community-built coverage, why this works where YaCy didn't) lives in the Discussion section below. A more thorough buildout is being developed separately and will be linked here when ready.

### Idea 3: Unobservability via anonymous broadcast

Even with Ideas 1 and 2 in place, the public engines you fall back to still see your queries. Idea 3 takes the trust circle from Idea 2 and uses it as a substrate for the strongest identity-privacy property in the standard taxonomy: **unobservability** against a global passive adversary, with no cryptographic assumption required.

The networking profile of search shapes which anonymity primitive fits. Search traffic is bursty rather than streaming; iterative for agents (query, parse, query again, dozens of times per task); latency-compounding across iterations; small payloads outbound, larger inbound; interactive (you wait for the answer before sending the next query). This profile maps badly onto **onion routing** ([Tor](https://www.torproject.org/)), where every hop adds latency and every iteration multiplies the cost. It also maps badly onto traditional **mixnets** ([Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska), [Nym](https://nymtech.net/)), where batching adds round-trip latency that human-scale traffic absorbs but iterative agent traffic doesn't. It maps surprisingly well onto **DC nets** ([Dining Cryptographers](https://en.wikipedia.org/wiki/Dining_cryptographers_problem)), where a fixed group of participants exchanges anonymous broadcast messages each round via XOR. The anonymity property holds *information-theoretically*: no cryptographic assumption is needed for the anonymity itself, only for the underlying secure channels.

DC nets historically failed to find traction because classical implementations required every participant online every round. A trust circle of ~10–50 friends with always-on indexers is exactly that condition, achieved voluntarily. Modern variants ([Dissent](https://www.usenix.org/conference/osdi12/technical-sessions/presentation/wolinsky), Verdict) scale further with partition + delegate schemes. The circle from Idea 2 becomes a DC-net group with very little additional infrastructure.

Two qualitatively different anonymity sub-problems hide inside Idea 3, requiring different primitives. **Unauthorized resources** (public endpoints, IP pseudonymity is the leak) and **authorized resources** (credentialed APIs, the credential is the leak). The Discussion section covers both, including the open question of how nodes get paid for running anonymity infrastructure without re-introducing the identity-coupling the substrate exists to remove. A useful side effect: the same DC-net group also gives you anonymous communication between members, not just anonymous search.

## Discussion

The three ideas above are intentionally compact. The depth follows below: trust models and verifiability for friends, the long-tail community-built coverage argument, the anonymity primitive comparison, the authorized-vs-unauthorized resource split, paying for the substrate without breaking anonymity, and the byproduct of anonymous communication.

### Trust models: friends, lying, foot-guns

Within the trust circle, the question of whether your friends are *lying* mostly answers itself: if you don't trust someone, don't add them. The trust-circle move is precisely to bound the adversarial model so we can stop reasoning about Sybils and impersonators. What's left is foot-guns: a friend whose extraction pipeline silently grabbed nav junk instead of article body, whose page is six months stale, or whose URL → fetch chain ended somewhere unexpected. The goal here is to catch *bugs and rot*, not malice. **Non-adversarial integrity, not adversarial security.**

| Source | Trust posture | What we need |
|---|---|---|
| **Public search engines** | Maximally adversarial; the business model is reading your queries; capable of cross-query and cross-time correlation | Strong identity privacy. Honest provenance via DNS/TLS, but no enforceable check on whether they're honest about *ranking* |
| **Friends' indrexes** | Trusted (added by hand); not trusted with arbitrary capabilities | Relaxed identity. Light integrity check to catch their bugs, not their lies |
| **Your own indrex** | Fully trusted | Whatever your own machine enforces |

The asymmetry is the load-bearing point: maximalist anonymity against a public engine is correct, but the same posture against a friend you're directly asking is both pointless (you have to tell them what you want, or no answer comes back) and counterproductive (it forecloses on the entire reason peer search exists). The system should let you dial paranoia per-counterparty rather than applying one global setting.

For friends specifically, several cheap mechanisms compose to make foot-guns easy to spot:

- **Self-signed slices.** Every shared slice of an indrex is signed by the friend's pubkey. Provenance ("this came from Alice") is verifiable, even if the *content* isn't audited.
- **Per-document fetch attestations.** Each indexed document carries `(URL, fetched-at, post-extraction content hash)`. A receiver can re-fetch and check whether the extraction agrees. Catches stale content, broken extraction, redirect drift.
- **Cross-peer agreement.** When two friends have indexed the same URL, compare hashes. Disagreement is a *signal*, not a verdict; could be staleness, a different extractor, or a real problem.
- **Comparison against public hashes.** For content with stable canonical hashes (papers, releases, signed software, Wikipedia revisions), check the friend's hash against the public one.
- **Sample-based audit.** Randomly re-fetch a small fraction of received slices and track per-friend agreement rates as a soft reputation score.
- **Extractor-version tags.** Slices declare which extractor version produced them, so disagreement caused by extractor upgrades can be distinguished from genuine content mismatch.

What this is *not*: not adversarial (a motivated peer can construct slices that match a re-fetch but rank or frame deceptively); not real-time (audits run async); not a substitute for trust-circle curation.

One distinction worth making explicit: the trust circle moves the human into the trusted set, but a human's *machine* is not the same as the human. A friend whose laptop is compromised becomes a vector for malice without being malicious themselves. The structural answer for higher-stakes deployments is short-lived per-friend session keys with bounded blast radius: auto-rotate, auto-expire, no permanent credential exchange that survives a host compromise.

### Authorization between friends

Trusting a friend doesn't mean you want them to see *everything*. You might be happy to share the slices of your indrex covering work and research with one friend, while wanting your slices covering health, family, finances, or anything else personal to stay within smaller scopes (or never leave your machine at all). Trust is multi-dimensional even within a circle.

This calls for some kind of per-slice authorization model: each slice carries access tags, each friend (or sub-group) has a set of permitted tags, and the sharing layer respects the intersection. Implementation is open, but the requirement is real. Without it, the trust-circle move silently leaks personal information through whichever slice happens to match a friend's query topic.

### Long-tail content and community-built indexes

Public engines optimize for popular pages. The long tail isn't *missing* from their indexes (it's mostly there), but it's buried under several pages of better-SEO'd alternatives. For most users, "buried on page 8" is functionally equivalent to "doesn't exist."

For some categories of long-tail content, dedicated indexes solve this: arxiv for academic papers, github for code, Hacker News / Lobsters for tech opinion. But there are large categories with no canonical index: the friend-of-a-friend's blog post that exactly addresses your obscure technical issue, microblogging that lives in DM threads or gist comments, the two-author wiki for a niche scientific subdomain, working notes that authors don't bother to SEO.

A solo crawler can't dent the long tail (the long tail is, by definition, vast). But a small community focused on related interests has a meaningful chance: ten people each searching organically over a year, in a tightly-scoped subdomain, build a community indrex that materially exceeds Google's surfacing of that subdomain, without any of them doing intentional indexing work beyond keeping what they searched for.

To make the scale concrete: 10 friends × ~200 search-result URLs touched per active day × 90-day retention ≈ 180,000 unique URLs in the community indrex. For a tightly-scoped subdomain (say, the active researchers in a niche field) this readily exceeds Google's effective ranked coverage of the same subdomain, with no one running a crawler.

The dynamic worth understanding: **community indrexes are useful at scales smaller than community search engines have ever been useful before** because the cost of indexing is no longer "build a crawler"; it's "keep what you already searched for." The minimum viable community is much smaller than YaCy ever managed.

YaCy bet on permissionless P2P crawling, where anyone could join the network, spider arbitrary pages, contribute to a shared index. The bet broke three ways. Open membership reintroduced sybil and spam problems that centralized engines were already spending billions to suppress. Each node had to operate a crawler, which is significant ongoing infrastructure work and a real time commitment. And the resulting index was generic, chasing whatever any user happened to crawl, so it never developed the topical depth needed to outperform Google anywhere specific. The trust-circle move addresses all three: by-invite groups don't have a sybil problem, query-driven indexing eliminates crawler overhead, and a community of friends with overlapping interests builds depth in *their* subdomain as a side effect, not as a goal.

### The Pfitzmann/Hansen hierarchy

The [Pfitzmann/Hansen privacy terminology](https://dud.inf.tu-dresden.de/literatur/Anon_Terminology_v0.34.pdf) defines a hierarchy of identity-privacy properties, each strictly stronger than the last:

- **Unlinkability**: the upstream can't link two queries to the same user.
- **Pseudonymity**: queries carry a stable pseudonym (e.g. an IP), but the pseudonym isn't bound to a real-world identity.
- **Sender anonymity**: the upstream can't identify the originator of a query within an anonymity set.
- **Unobservability**: a network observer can't even tell you're using the system at all.

Searxng's defaults give you part of (1), most of (2), none of (3) and (4). Routing through a friend's instance buys part of (3) by giving you their IP pseudonymity plus k-anonymity within the trust circle (a [Crowd, in the Reiter & Rubin (1998)](https://www.freehaven.net/anonbib/cache/crowds:tissec.pdf) sense). Idea 3 gets you to (4).

Why agents care about (4) specifically: iterative query patterns leave a much bigger surface than human queries, and timing patterns alone can defeat sender anonymity if the adversary is global passive. For high-sensitivity research, unobservability is the only property that actually holds up.

### Authorized vs unauthorized resources

There are two qualitatively different anonymity problems hiding inside "I want to query a search engine without it knowing it's me." They want different primitives.

**Unauthorized resources** are public endpoints you can hit without credentials (Google's search page, a public API rate-limited only by IP). The peer fabric upgrades searxng's existing request-layer privacy (no cookies, no Referer, no fingerprint forwarded, UA rotated): route upstream queries through a randomly-chosen friend's instance and you pick up their IP pseudonymity plus k-anonymity within the trust circle. Layer DC-net broadcast over this for unobservability against a global passive adversary. (Cf. [PIR](https://en.wikipedia.org/wiki/Private_information_retrieval) for the rigorous version of payload anonymity: retrieving a record without the database learning which record. The analogue against a search engine is much harder, since the engine has to read the query to *interpret* it, not just to retrieve.)

**Authorized resources** are credentialed APIs (anything behind an API key, any logged-in search). The credential carries identity by construction. The natural mirror of the friend-as-Crowd move is a **shared credential pool**: each friend in the trust circle contributes API keys, queries draw from the pool, an account-Crowd at the credential layer rather than the IP layer. *But this only relocates the trust problem*: whoever runs the pool has to construct the outbound request, so they see the plaintext of every authorized query. The pool becomes a new identifying party.

Closing that gap requires primitives that hide the query from the credential layer itself. The most concrete proposal is [**Buterin & Crapis's "ZK API Usage Credits: LLMs and Beyond"**](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104): prepay once into a smart contract (the paper's examples: $100 → 500 LLM queries; $10 → 10,000 RPC calls), then spend the credits anonymously, with the credential issuer unable to link successive uses of the same prepaid bundle. Other primitives in the same family: **anonymous credentials** (BBS+, [Coconut](https://arxiv.org/abs/1802.07344), [Privacy Pass](https://datatracker.ietf.org/doc/rfc9576/)) where the upstream is willing to issue tokens whose use can't be linked back to issuance; or **threshold/MPC signing** where the pool holds key shares and the user contributes the query so no single party (pool included) sees both the credential and the plaintext together.

(Note: zkTLS is *not* the right primitive here. It lets a client prove *to a third party* that a TLS exchange happened, but the pool would still need to read the query to send it on the user's behalf. zkTLS's natural fit is the friend content-integrity case above: letting a relayer prove what an upstream actually served them.)

Both authorized and unauthorized cases also benefit from **verifiability**. We can't enforce that the upstream is honest about ranking, but the bytes claiming to be from `google.com` should actually be from `google.com`. DNS plus TLS handle this for the unauthorized case. For authorized cases, [zkTLS](https://tlsnotary.org/)-style proofs from the requesting client (proving what the upstream returned over a real TLS session) become useful as a future-work primitive.

### Paying for the substrate without breaking anonymity

DC-net nodes (or any anonymity infrastructure) aren't free to run. Inside a tight trust circle, friends run for friends as a local public good. Beyond that, node operators need compensation, and how you pay matters because the wrong payment mechanism quietly defeats the property the substrate exists to provide.

The naive answer is stablecoin micropayments (x402, Lightning, machine payment protocols). It works mechanically but introduces a new identity-coupling problem: every payment links the payer's crypto identity to their use of the anonymity service. That's exactly what the service was supposed to remove.

Two routes around this:

- **Stealth addresses** ([ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) and similar). Payments hit a fresh address per transaction derived from the recipient's pubkey. Operators can claim payments without knowing which payer sent which; payers can't be linked to their payments by passive observers.
- **ZK proof of payment.** Prove "I have a valid prepaid credit" without revealing which credit or which prior payment created it. This is exactly the Buterin & Crapis ZK API Credits pattern from the previous subsection. The same primitive solves both "pay for an API call without leaking who you are" and "pay for an anonymity-service call without leaking who you are."

A friction note: every additional payment hop is one more thing that must work for an agent to make a query. Trust circles dodge this entirely (friends serve friends without per-query payment). Broader deployments don't, and paying for anonymity is itself a friction point that limits how far the model can spread without the right primitives in place.

### Anonymous communication as a byproduct

DC nets give the trust circle anonymous broadcast as a primitive. Search queries are one application, but they're not the only one. Once friends are wired together as a DC-net group for sending search queries to the public web, the same substrate carries arbitrary anonymous messages between members.

This is incidental to the search use case but worth flagging: if you're building this anyway for search-anonymity reasons, you also have the foundation for a small anonymous message-passing system. Members of a research swarm can vote, negotiate, signal interest in topics, or coordinate without their participation being externally linkable (and, when needed, without it being internally linkable either). The strongest anonymity property in the standard taxonomy applied to the smallest unit of coordination (a few friends) is a real primitive, not just a search-acceleration trick.

## Open questions

Collected and called out so we don't lose them.

1. **Adversarial trust** *(deferred but central)*. How do peers know they aren't being fed poisoned slices (pages with truthful URLs but adversarial extracted content meant to game ranking)? Options on the table: signed slices + manual peer add (works for tight trust circles); web-of-trust scores; reputation-decay; staking. For v0 we're explicitly trusting peers added by hand. **Any wider deployment must answer this first.**
2. **Query-to-friend privacy.** Even within a trust circle, sending a query to a friend leaks intent. Topic-vector digests and bloom-filter URL probes can pre-filter cheaply without revealing the full query, but a friend who *receives* the actual query still knows what was asked. PIR / PSI variants exist but are heavy.
3. **Sybil resistance** for wider circles. Subset of (1) but worth tracking separately because the mitigations are different (sybil-resistance vs. content-trust).
4. **Staleness and refresh policy.** When does a slice become "too old to serve"? Per-domain? Per-topic? Triggered by upstream changes? A 90-day default is a placeholder.
5. **Coordination-free ranking.** Score-fusion across engines that share content is a known-weird problem. Naive merging double-counts popular pages.
6. **Crawler ethics at scale.** Even query-driven indexing crawls real sites. We need polite defaults *baked in* (rate limits, `robots.txt` respect, identifying UA, opt-out path) so this doesn't become an extractive system in aggregate even if each individual user is small.
7. **Storage growth.** Full-content slices add up fast. Per-user budget, LRU eviction, or topic-targeted pruning all need design.
8. **What is "the indrex", really?** Is it (a) URLs the user has clicked, (b) all results returned to the user, (c) the full set fetched by the indexing loop? Each gives different size/quality/privacy tradeoffs.

## Possible further extensions

- **Layered slice exchange.** Share slices of an indrex at different fidelity tiers (URL list / + snippets and embeddings / + full extracted content) so peers escalate bandwidth and trust on demand.
- **Topic-vector digests + semantic peer routing.** Pick the right friend to ask without disclosing what you're about to ask.
- **Bloom-filter URL digests.** At scales beyond a few dozen friends or ~1M URLs per indrex, plain URL manifests in digests get unwieldy. A signed bloom filter compresses "do you have URL X?" probes with bounded false-positive rate, at the cost of leaking probabilistic membership to anyone who can probe. Worth introducing only when the scale demands it.
- **Federated re-ranking.** Friends contribute click/dwell signals to a shared learned ranker, with [differential privacy](https://en.wikipedia.org/wiki/Differential_privacy) guarantees.
- **Indrex topic assignments inside research groups.** Explicit "I'm responsible for the X subdomain" commitments, like custody assignments in PeerDAS but for content topics.
- **Integration with the [Flashbots research swarm](https://github.com/Flashbots/research-agent-exp001).** DSPy agents both feed and query the indrex, turning research output into shared substrate.
- **WAN trust circles.** Signed peer adds and reputation-decay for friends across the internet.
- **Slashing-backed audit reputation.** Friends post a small economic bond; slices that fail audit slash the bond. Lighter than full sybil-resistance but creates a real cost for repeated bad-faith contribution to the trust circle.

## Out of scope / non-goals

- Replacing public search engines for the general public.
- Operating without trust assumptions at the membrane: circles are by-invite. The substrate underneath stays permissionless. Anyone can run a node, form a circle, and exit any circle taking their indrex with them. **Walkaway test:** a user must be able to leave any trust circle without losing their data or being held hostage by a peer.
- Real-time indexing of live news / streams.
- Becoming a general-purpose CDN or content-distribution network.
- Censorship resistance as a first-class property (a nice byproduct, not a goal).

## Related work and prior art

- **[SearXNG](https://github.com/searxng/searxng).** The substrate we're extending.
- **[YaCy](https://yacy.net/).** Predecessor: permissionless P2P distributed search since 2003. The "Long-tail content and community-built indexes" subsection above examines why the original bet broke.
- **[RetroShare](https://retroshare.cc/).** F2F P2P platform with PGP-keyed friend links, content search via friend-broadcast, and anonymous multi-hop tunnels for distant queries. The closest existing F2F architecture to what's proposed here; an honest "is this just RetroShare with extra steps?" comparison is warranted.
- **[Mwmbl](https://github.com/mwmbl/mwmbl).** Non-profit community-crawled web index where volunteers run a CLI/Firefox-extension crawler. The strongest contemporary data point on whether community-scale indexing actually scales.
- **[Marginalia](https://marginalia-search.com/).** Single-operator independent crawler/indexer favoring text-heavy non-SEO content. Empirical demonstration that a small operator can index meaningfully into the long tail.
- **[Secure Scuttlebutt (SSB)](https://scuttlebutt.nz/).** Append-only signed feeds gossiped along friend-graph edges, working offline and over LAN. The right reference for the gossip/sync vocabulary in the slice-exchange layer.
- **Personal-archive lineage for Idea 1.** [Memex](https://en.wikipedia.org/wiki/Memex) (1945), [Pinboard](https://pinboard.in/), [Wallabag](https://wallabag.org/), [ArchiveBox](https://archivebox.io/), [Promnesia](https://github.com/karlicoss/promnesia). See Idea 1 for how each fits.
- **[Common Crawl](https://commoncrawl.org/).** The "shared crawl" half of the idea, without the metasearch front-end or peer-driven topicality.
- **[GNUnet](https://www.gnunet.org/) / [Freenet](https://freenetproject.org/).** Peer-shared content addressing with explicit trust modeling; relevant especially for the slice-exchange and query-privacy parts.
- **IPFS / libp2p.** Content-addressed storage and a useful set of building blocks (libp2p discovery, gossipsub) even if the "peer-shared *search*" framing differs from the IPFS "peer-shared *bytes*" framing.
- **[Buterin & Crapis, "ZK API Usage Credits: LLMs and Beyond"](https://ethresear.ch/t/zk-api-usage-credits-llms-and-beyond/24104).** The most concrete proposal in the auth-resource anonymity direction; reused in Idea 3 for paying anonymity-service operators without breaking anonymity.
- **[PeerDAS](https://ethresear.ch/t/peerdas-a-simpler-das-approach-using-battle-tested-p2p-components/16541)** and **[S/Kademlia DAS notes](https://notes.ethereum.org/@dankrad/S-Kademlia-DAS).** Closest stylistic ancestors for *this document*, and a useful reference for how custody / discovery / sampling get factored in a system whose hard problems are p2p-shaped.

## Pushback wanted

Feedback, dissent, and "this is just YaCy with extra steps" objections welcome. The most useful pushback at this stage: are the three ideas actually independently valuable, or does any of them collapse without the others to prop it up? Is DC nets at trust-circle scale a real implementation path or a hopeful gesture? Does the friend-to-friend authorization story for Idea 2 hide more complexity than it admits? And: do the three extensions aggregate into something usable, or just into three separate things that share a network diagram?
