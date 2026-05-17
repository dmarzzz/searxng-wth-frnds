# searxng-wth-frnds v0.3

Local-First Search + LAN Anonymous Friend Search + Self Public Egress + Anonymous Tickets/Receipts

## 0. Working name

searxng-wth-frnds

Local-first search with optional anonymous LAN friend-circle search, explicit privacy-path metadata, and anonymous LAN quota/receipt primitives.

User-facing name should be calmer:

```
SWF Search Router
Local/Friend/Public Search Router
```

---

## 1. Goal

Build a search stack where:

1. Queries are answered from the user's own archive whenever possible.
2. If local results are insufficient, the query can be sent to a trusted LAN/friend circle.
3. In the real DC-net path, the requester is hidden inside the active LAN circle.
4. Friend peers may still see the query content.
5. If no private path is sufficient, the system may fall back to self public egress if policy allows.
6. Every response reports the actual delivery path and the original result provenance.
7. The system never silently pretends a public-egress result was private.
8. LAN friend search can be rate-limited with anonymous query tickets.
9. Useful providers can receive bounded anonymous positive receipts without deanonymizing the requester.

The anonymous ticket design should be Privacy-Pass-like: a peer proves it has a valid authorization token without revealing which long-lived peer identity received that token. Privacy Pass itself defines privacy-preserving authorization using unlinkable tokens, with distinct issuance and redemption flows.

---

## 2. Non-goals for this version

This version intentionally does not define:

- WAN friend search.
- WAN public egress through external peers.
- WAN DC-net routing.
- Bulk document transfer over DC-net.
- Query privacy against friend-circle members.
- Provider anonymity.
- Formal DC-net cryptographic proof.
- Full abuse-blame protocol.
- Global reputation.
- Public reputation federation.

This version does define LAN anonymous query tickets and LAN anonymous receipts at the application layer.

---

## 3. Core search paths

The router supports these paths in order:

```
LOCAL_CACHE
  Result bundle served from local cache.

LOCAL_INDREX
  Query answered from ~/world_knowledge SQLite FTS5 archive.

LAN_FRIEND_DIRECT_PLACEHOLDER
  Non-anonymous LAN friend placeholder.
  Development only.

LAN_FRIEND_DCNET
  Query anonymously broadcast through real LAN DC-net.
  Friend peers see the query content.

SELF_PUBLIC_EGRESS
  This device queries public search engines through configured local SearXNG/public adapter.

NO_RESULT
  No acceptable route.
```

Do not use `LAN_FRIEND_DCNET` for a placeholder transport. Use `LAN_FRIEND_DIRECT_PLACEHOLDER`.

---

## 4. High-level architecture

```
research_agent / user / API caller
        |
        v
web_search(q, policy)
        |
        +--> LOCAL_CACHE
        |
        +--> LOCAL_INDREX
        |
        +--> LAN_FRIEND_DCNET or LAN_FRIEND_DIRECT_PLACEHOLDER
        |
        +--> SELF_PUBLIC_EGRESS
```

Existing components:

```
SearXNG
  - local_index engine
  - local_friends engine
  - public engines: DuckDuckGo, Brave, etc.

~/world_knowledge/
  - local fetched pages
  - SQLite FTS5 indrex
```

New components:

```
src/swf/search_policy.py
src/swf/search_router.py
src/swf/search_response.py
src/swf/local_cache.py
src/swf/local_indrex.py
src/swf/public_egress.py
src/swf/dcnet_client.py
src/swf/dcnet_daemon.py
src/swf/local_friends_dcnet.py
src/swf/anonymous_tickets.py
src/swf/anonymous_receipts.py
src/swf/reputation.py
```

---

## 5. Required invariant

Every search response must include:

```
delivery_path:
  How this response was delivered for this request.

origin_paths:
  Where the underlying results originally came from.

dominant_origin_path:
  Highest-risk origin path represented in the result set.

privacy_level:
  Human/agent-readable privacy classification.

network_used_this_request:
  Whether this request used any network.

public_egress_used_this_request:
  Whether this request queried public engines from this device/network.
```

This replaces the old single `path` field.

The reason is critical: `LOCAL_CACHE` can serve results that were originally obtained through `SELF_PUBLIC_EGRESS`. Without origin tracking, cache becomes privacy laundering.

Example:

```json
{
  "status": "ok",
  "delivery_path": "LOCAL_CACHE",
  "origin_paths": ["SELF_PUBLIC_EGRESS"],
  "dominant_origin_path": "SELF_PUBLIC_EGRESS",
  "privacy_level": "local_replay_of_public_result",
  "network_used_this_request": false,
  "public_egress_used_this_request": false,
  "warning": "Returned from local cache, but these results were originally obtained through self public egress."
}
```

---

## 6. Privacy-level enum

```
local_only
  No network used for this request.
  Results originated from local-only sources.

local_replay
  No network used for this request.
  Results came from cache; inspect origin_paths.

local_replay_of_public_result
  No network used this request, but cached results originally came from public egress.

anonymous_within_lan_circle_query_visible
  Requester hidden inside active LAN anonymity set.
  Friend peers can see query content.

not_anonymous_placeholder
  Development placeholder. Do not claim anonymity.

public_from_self
  Query sent to public engines from this device/network or configured local egress.

public_from_self_tor
  Query sent to public engines through configured Tor SOCKS egress after leak checks.

none
  No route used.
```

Do not use `anonymous_within_lan_circle` without `query_visible`.

---

## 7. Threat model

### 7.1 In scope

The system attempts to protect against:

- **Silent public downgrade**: A query must not fall back to public egress without metadata or required confirmation.
- **Result provenance confusion**: Cached public results must not be mislabeled local-only.
- **LAN requester identification**: Real LAN DC-net should hide which active peer issued the query.
- **Query spam**: LAN friend search should require anonymous query tickets once Phase 6 is enabled.
- **Receipt spam**: Anonymous positive receipts must be scarce and one-time-use.
- **Malformed peer responses**: Invalid, oversized, malformed, or unverifiable peer responses are rejected.
- **Provider archive leakage**: Friend responders search only shareable corpus, not full private local archive.

### 7.2 Out of scope

- Host compromise.
- Browser compromise.
- Local malware.
- Query privacy from friend peers.
- Provider anonymity.
- WAN anonymity.
- Global sybil resistance.
- Malicious majority of LAN peers.
- Colluding receipt inflation beyond quota limits.

### 7.3 Honesty rule

`LAN_FRIEND_DCNET` hides who asked only within the active circle. It does not hide what was asked from the circle.

---

## 8. Route taxonomy

```
LOCAL_CACHE
LOCAL_INDREX
LAN_FRIEND_DIRECT_PLACEHOLDER
LAN_FRIEND_DCNET
SELF_PUBLIC_EGRESS
NO_RESULT
MIXED
```

`MIXED` is reserved. For v0, prefer single-route result sets. Mixing local, friend, and public results is allowed only when every result carries full per-result metadata.

---

## 9. Policy model

Public fallback needs more than a boolean.

Use:

```
public_egress:
  mode: allow | confirm | deny
```

Also distinguish friend query visibility and cache origin policy.

### 9.1 Default policy

```yaml
search_policies:
  default:
    route_order:
      - LOCAL_CACHE
      - LOCAL_INDREX
      - LAN_FRIEND_DCNET
      - SELF_PUBLIC_EGRESS

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: true
      lan_friend_direct_placeholder: false
      self_public_egress: true

    public_egress:
      mode: allow
      confirm_on_sensitive_query: true
      confirm_after_suspicious_private_failure: true

    cache:
      allow_result_cache: true
      allowed_origin_paths:
        - LOCAL_INDREX
        - LAN_FRIEND_DCNET
        - SELF_PUBLIC_EGRESS
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: true

    anonymous_tickets:
      require_for_lan_friend_search: true

    routing_goal: balanced
```

### 9.2 Private-circle policy

This is not "fully private." Friends can see the query.

```yaml
  private_circle:
    route_order:
      - LOCAL_CACHE
      - LOCAL_INDREX
      - LAN_FRIEND_DCNET

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: true
      lan_friend_direct_placeholder: false
      self_public_egress: false

    public_egress:
      mode: deny

    cache:
      allow_result_cache: true
      allowed_origin_paths:
        - LOCAL_INDREX
        - LAN_FRIEND_DCNET
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: true

    anonymous_tickets:
      require_for_lan_friend_search: true

    routing_goal: privacy_first
```

### 9.3 Local-only policy

```yaml
  local_only:
    route_order:
      - LOCAL_CACHE
      - LOCAL_INDREX

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: false
      lan_friend_direct_placeholder: false
      self_public_egress: false

    public_egress:
      mode: deny

    cache:
      allow_result_cache: true
      allowed_origin_paths:
        - LOCAL_INDREX
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: false

    anonymous_tickets:
      require_for_lan_friend_search: false

    routing_goal: privacy_first
```

### 9.4 Dev placeholder policy

```yaml
  dev_placeholder_friends:
    route_order:
      - LOCAL_CACHE
      - LOCAL_INDREX
      - LAN_FRIEND_DIRECT_PLACEHOLDER
      - SELF_PUBLIC_EGRESS

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: false
      lan_friend_direct_placeholder: true
      self_public_egress: true

    public_egress:
      mode: confirm

    cache:
      allow_result_cache: true
      allowed_origin_paths:
        - LOCAL_INDREX
        - LAN_FRIEND_DIRECT_PLACEHOLDER
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: true

    anonymous_tickets:
      require_for_lan_friend_search: false

    routing_goal: dev
```

---

## 10. Query context

Before routing, build:

```
QueryContext:
    request_id: str
    raw_query: str
    normalized_query: str
    query_hmac: str
    created_ms: int
    caller: str | None
    policy_name: str
    requested_top_k: int
    inferred_intent: QueryIntent
    sensitivity: QuerySensitivity
    freshness_requirement: FreshnessRequirement
```

### 10.1 Query intent enum

```
navigational
fact_lookup
local_archive_lookup
freshness_required
deep_research
unknown
```

### 10.2 Freshness requirement

```
none
prefer_fresh
require_fresh
```

Freshness-sensitive terms include:

```
latest
today
current
recent
this week
price
weather
score
schedule
CVE
release date
2026
```

Intent inference is a routing hint, not a security boundary.

---

## 11. Response schema

### 11.1 Top-level SearchResponse

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "request_id": "req_01J...",
  "created_ms": 1760000000000,
  "completed_ms": 1760000001234,

  "policy": {
    "requested": "default",
    "effective": "default",
    "routing_goal": "balanced"
  },

  "delivery_path": "LAN_FRIEND_DCNET",
  "origin_paths": ["LAN_FRIEND_DCNET"],
  "dominant_origin_path": "LAN_FRIEND_DCNET",
  "privacy_level": "anonymous_within_lan_circle_query_visible",

  "network_used_this_request": true,
  "public_egress_used_this_request": false,
  "friend_query_visible": true,

  "anonymous_ticket": {
    "required": true,
    "presented": true,
    "accepted": true,
    "ticket_family": "QUERY_TICKET_V1",
    "issuer_key_id": "sha256:..."
  },

  "fallbacks_tried": ["LOCAL_CACHE", "LOCAL_INDREX"],
  "fallback_reason": "local routes insufficient",
  "privacy_downgrade": false,

  "warnings": [
    "Friend peers can see the query content."
  ],

  "attempts": [],
  "results": [],

  "debug": {
    "query_hmac": "hmac-sha256:...",
    "sufficiency": {
      "sufficient": true,
      "reason": "min_results_and_score_met"
    }
  }
}
```

### 11.2 Status enum

```
ok
partial
no_results
no_acceptable_route
confirmation_required
error
```

### 11.3 Attempt object

```json
{
  "path": "LAN_FRIEND_DCNET",
  "status": "timeout",
  "started_ms": 1760000000000,
  "completed_ms": 1760000003000,
  "duration_ms": 3000,
  "reason": "round_timeout",
  "results_count": 0,
  "network_used": true,
  "public_egress_used": false,
  "suspicious_failure": false
}
```

### 11.4 Result object

```json
{
  "result_id": "res_01J...",
  "canonical_url": "https://example.org/foo",
  "display_url": "example.org/foo",
  "title": "Example Title",
  "snippet": "A sanitized plain-text snippet...",
  "score": 0.82,
  "rank": 1,

  "delivery_path": "LAN_FRIEND_DCNET",
  "origin_path": "LAN_FRIEND_DCNET",
  "source": "friend_indrex",

  "provider": {
    "provider_pubkey": "ed25519:...",
    "provider_label": null,
    "provider_score_local": 0.74
  },

  "freshness": {
    "fetched_at_ms": 1760000000000,
    "indexed_at_ms": 1760000000000,
    "served_at_ms": 1760000001234,
    "staleness_days": 2
  },

  "verification": {
    "verified_slice": false,
    "content_hash": "sha256:...",
    "merkle_root": null,
    "inclusion_proof": null,
    "sigchain_head": null,
    "dsse_attestation": null,
    "verification_status": "not_checked"
  },

  "receipt": {
    "receipt_eligible": true,
    "service_proof_hash": "sha256:...",
    "receipt_challenge": "base64url:..."
  },

  "safety": {
    "html_sanitized": true,
    "url_validated": true,
    "share_scope": "friends"
  }
}
```

All peer/public fields are untrusted and must be escaped before UI rendering.

---

## 12. Local cache

`LOCAL_CACHE` returns previously computed result bundles without using the network during this request.

A cached result may be returned only if:

1. The cache entry matches normalized query.
2. The cache entry has not expired.
3. The cache entry's origin_path is allowed by active policy.
4. The response discloses delivery_path and origin_paths separately.

### 12.1 Cache key

Do not persist raw queries as cache keys by default.

```
query_hmac = HMAC-SHA256(local_cache_secret, normalized_query)
```

### 12.2 Cache entry schema

```json
{
  "schema": "swf.cache_entry.v1",
  "query_hmac": "hmac-sha256:...",
  "normalized_query_len": 42,
  "created_ms": 1760000000000,
  "expires_ms": 1760086400000,

  "delivery_path_when_cached": "SELF_PUBLIC_EGRESS",
  "origin_paths": ["SELF_PUBLIC_EGRESS"],
  "dominant_origin_path": "SELF_PUBLIC_EGRESS",
  "privacy_level_when_cached": "public_from_self",

  "results": [],
  "warnings": [
    "Originally obtained through self public egress."
  ]
}
```

### 12.3 Cache TTL defaults

```yaml
cache:
  enabled: true
  default_ttl_hours: 24
  local_indrex_ttl_hours: 168
  lan_friend_ttl_hours: 24
  self_public_ttl_hours: 12
  persist_raw_queries: false
```

### 12.4 Cache invariant

`local_only` must not return cached public-egress results unless explicitly configured to allow that origin.

Default: do not allow it.

---

## 13. Local indrex

SQLite FTS5 is appropriate for this route because it provides SQLite full-text-search virtual tables, MATCH, relevance ranking, highlighting, and snippets. Its query syntax supports phrases, prefixes, NEAR groups, column filters, and boolean operators, so raw user text should not be passed as unrestricted FTS syntax unless advanced mode is enabled.

### 13.1 Local document table

```sql
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    canonical_url TEXT,
    display_url TEXT,
    title TEXT NOT NULL,
    body_text TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_path TEXT,
    content_hash TEXT NOT NULL,
    fetched_at_ms INTEGER,
    indexed_at_ms INTEGER NOT NULL,
    deleted_at_ms INTEGER,

    share_scope TEXT NOT NULL DEFAULT 'private',
    sensitivity_label TEXT NOT NULL DEFAULT 'unknown',

    CHECK (share_scope IN ('private', 'local_only', 'friends', 'public')),
    CHECK (sensitivity_label IN ('unknown', 'low', 'medium', 'high'))
);
```

### 13.2 FTS table

```sql
CREATE VIRTUAL TABLE documents_fts USING fts5(
    title,
    body_text,
    content='documents',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
```

### 13.3 Local search scope

Local user search may search all documents visible to the user.

Friend responder search must only search:

```
share_scope IN ('friends', 'public')
```

Friend responders must never return:

- file:// URLs
- localhost URLs
- private LAN URLs
- source_path values
- raw filesystem paths
- documents with sensitivity_label = high
- private snippets

### 13.4 Safe query builder

```python
def build_safe_fts_query(q: str) -> str:
    """
    Convert user text into conservative FTS5 phrase/term query.
    Do not expose raw boolean, NEAR, prefix, or column syntax by default.
    """
```

---

## 14. Sufficiency heuristic

```yaml
sufficiency:
  min_results: 3
  min_unique_hosts: 2
  min_top_score: 0.25
  min_mean_score: 0.18
  max_staleness_days: null
  require_fresh_for_freshness_queries: true
  allow_single_exact_hit: true
```

### 14.1 Pseudocode

```python
def sufficient(result_set, ctx, policy):
    if result_set.status not in {"ok", "partial"}:
        return Sufficiency(False, "route_failed")

    results = [r for r in result_set.results if r.score is not None]

    if not results:
        return Sufficiency(False, "no_results")

    if ctx.freshness_requirement == "require_fresh":
        if not result_set.meets_freshness(policy.sufficiency):
            return Sufficiency(False, "freshness_not_met")

    if exact_navigational_hit(results, ctx):
        return Sufficiency(True, "single_exact_hit")

    if len(results) < policy.sufficiency.min_results:
        return Sufficiency(False, "too_few_results")

    if unique_hosts(results) < policy.sufficiency.min_unique_hosts:
        return Sufficiency(False, "too_little_source_diversity")

    if max(r.score for r in results) < policy.sufficiency.min_top_score:
        return Sufficiency(False, "top_score_too_low")

    if mean_top_scores(results, n=3) < policy.sufficiency.min_mean_score:
        return Sufficiency(False, "mean_score_too_low")

    return Sufficiency(True, "thresholds_met")
```

Some queries should continue toward public search even if local has results, but only if policy allows public egress.

---

## 15. Router algorithm

```python
def web_search(q: str, policy_name: str = "default", caller=None) -> SearchResponse:
    ctx = make_query_context(q, policy_name, caller)
    policy = load_effective_policy(policy_name)
    attempts: list[SearchAttempt] = []

    if not q or not q.strip():
        return error_response(ctx, policy, reason="empty_query")

    if policy.allow.local_cache:
        r = search_local_cache(
            ctx,
            allowed_origin_paths=policy.cache.allowed_origin_paths,
        )
        attempts.append(r.attempt)
        if sufficient(r, ctx, policy):
            return build_response(
                ctx=ctx,
                policy=policy,
                delivery_path="LOCAL_CACHE",
                origin_paths=r.origin_paths,
                results=r.results,
                attempts=attempts,
                privacy=derive_privacy_from_cache(r),
            )

    if policy.allow.local_indrex:
        r = search_local_indrex(ctx, top_k=policy.top_k)
        attempts.append(r.attempt)
        if sufficient(r, ctx, policy):
            return build_response(
                ctx=ctx,
                policy=policy,
                delivery_path="LOCAL_INDREX",
                origin_paths=["LOCAL_INDREX"],
                results=r.results,
                attempts=attempts,
                privacy_level="local_only",
            )

    if policy.allow.lan_friend_dcnet:
        if not policy.friend_query_visibility.allow_query_visible_to_friends:
            attempts.append(policy_denied_attempt(
                path="LAN_FRIEND_DCNET",
                reason="friend_query_visibility_not_allowed",
            ))
        else:
            r = search_lan_friend_dcnet(ctx, top_k=policy.top_k)
            attempts.append(r.attempt)

            if sufficient(r, ctx, policy):
                return build_response(
                    ctx=ctx,
                    policy=policy,
                    delivery_path="LAN_FRIEND_DCNET",
                    origin_paths=["LAN_FRIEND_DCNET"],
                    results=r.results,
                    attempts=attempts,
                    privacy_level="anonymous_within_lan_circle_query_visible",
                    warnings=["Friend peers can see the query content."],
                )

            if r.attempt.suspicious_failure:
                if policy.public_egress.confirm_after_suspicious_private_failure:
                    return confirmation_required_response(
                        ctx=ctx,
                        policy=policy,
                        attempts=attempts,
                        proposed_path="SELF_PUBLIC_EGRESS",
                        reason="private_route_failed_suspiciously",
                    )

    if policy.allow.lan_friend_direct_placeholder:
        r = search_lan_friend_direct_placeholder(ctx, top_k=policy.top_k)
        attempts.append(r.attempt)
        if sufficient(r, ctx, policy):
            return build_response(
                ctx=ctx,
                policy=policy,
                delivery_path="LAN_FRIEND_DIRECT_PLACEHOLDER",
                origin_paths=["LAN_FRIEND_DIRECT_PLACEHOLDER"],
                results=r.results,
                attempts=attempts,
                privacy_level="not_anonymous_placeholder",
                warnings=[
                    "This LAN friend path is a non-anonymous development placeholder."
                ],
            )

    if not policy.allow.self_public_egress or policy.public_egress.mode == "deny":
        return no_acceptable_route_response(
            ctx=ctx,
            policy=policy,
            attempts=attempts,
            available_fallback="SELF_PUBLIC_EGRESS",
            reason="self_public_egress_disabled_by_policy",
        )

    if public_requires_confirmation(ctx, policy):
        return confirmation_required_response(
            ctx=ctx,
            policy=policy,
            attempts=attempts,
            proposed_path="SELF_PUBLIC_EGRESS",
            reason="public_egress_requires_confirmation",
        )

    r = search_self_public_egress(ctx, top_k=policy.top_k)
    attempts.append(r.attempt)

    return build_response(
        ctx=ctx,
        policy=policy,
        delivery_path="SELF_PUBLIC_EGRESS",
        origin_paths=["SELF_PUBLIC_EGRESS"],
        results=r.results,
        attempts=attempts,
        privacy_level="public_from_self",
        privacy_downgrade=True,
        fallback_reason="no private route returned sufficient results",
        warnings=[
            "This query was sent to public search engines from this device/network."
        ],
    )
```

---

## 16. Public egress confirmation

When confirmation is required:

```json
{
  "status": "confirmation_required",
  "delivery_path": "NO_RESULT",
  "privacy_level": "none",
  "proposed_path": "SELF_PUBLIC_EGRESS",
  "reason": "public_egress_requires_confirmation",
  "warning": "This query would be sent to public search engines from this device/network.",
  "confirmation": {
    "confirmation_id": "cnf_01J...",
    "expires_ms": 1760000005000,
    "binds": {
      "query_hmac": "hmac-sha256:...",
      "policy": "default",
      "proposed_path": "SELF_PUBLIC_EGRESS"
    }
  },
  "results": []
}
```

Confirmation token must bind:

- query_hmac
- policy
- proposed path
- caller identity, if available
- expiry

---

## 17. LAN friend search interface

This defines the interface and safety contract, not the full DC-net cryptographic protocol.

```python
class FriendSearchTransport(Protocol):
    name: str
    privacy_level: str

    def discover_peers(self) -> PeerDiscoveryResult:
        ...

    def active_circle(self) -> ActiveCircle:
        ...

    def search(self, req: FriendSearchRequest) -> FriendSearchOutcome:
        ...
```

### 17.1 Active circle metadata

```
ActiveCircle:
    epoch_id: str
    active_peer_count: int
    min_anonymity_set_met: bool
    membership_fixed_for_round: bool
    requester_anonymity_claim: str
    transport_kind: Literal[
        "dcnet_real",
        "direct_placeholder",
        "disabled"
    ]
```

`LAN_FRIEND_DCNET` may be reported only if:

- transport_kind = dcnet_real
- active_peer_count >= configured min_anonymity_set
- membership_fixed_for_round = true
- min_anonymity_set_met = true
- requester_anonymity_claim != none

### 17.2 Minimum anonymity set

```yaml
lan_dcnet:
  min_anonymity_set: 3
  recommended_anonymity_set: 5
```

Three is a minimum, not a strong guarantee against collusion.

---

## 18. LAN peer discovery

```yaml
peer_discovery:
  mdns: true
  peers_yaml: true
  tailscale: false
```

mDNS is useful for LAN discovery because it supports DNS-like operations on the local link without a conventional unicast DNS server, but mDNS records are local-link visible metadata and should not contain personal names or unnecessary durable identifiers.

Discovery safety rules:

- Do not publish personal names in mDNS service records.
- Do not publish provider keys unless opted in.
- Prefer generic service names.
- Allow static peers_yaml for high-trust circles.
- Require out-of-band fingerprint confirmation for durable peer identity keys.

---

## 19. Identity separation

```
Peer identity key:
  Durable Ed25519 key.
  Used for membership, allowlisting, TOFU, authenticated control.
  Never inside anonymous SEARCH_V1.

Provider/content key:
  Durable Ed25519 key.
  Used for signed result bundles and content provenance.
  May appear inside encrypted responses.

One-time reply key:
  Fresh X25519 keypair per query.
  Used for encrypted anonymous responses.
  Included in anonymous SEARCH_V1.
  Not signed by requester identity.

Anonymous query ticket:
  Unlinkable bearer credential.
  Proves query quota without peer identity.

Anonymous receipt ticket:
  Unlinkable bearer credential.
  Allows bounded positive reputation feedback.
```

X25519/Curve25519 and related curves are specified for practical security and efficient implementations in RFC 7748; use well-reviewed libraries rather than handwritten crypto.

---

## 20. LAN friend request and response messages

### 20.1 SEARCH_V1

```json
{
  "schema": "swf.friend_search.search.v1",
  "qid": "base64url-128-bit-random",
  "query": "dc nets practical deployment",
  "top_k": 8,
  "reply_pubkey": "x25519:base64...",
  "created_ms": 1760000000000,
  "ttl_ms": 5000,
  "max_response_bytes": 16384,

  "anonymous_query_ticket": {
    "family": "QUERY_TICKET_V1",
    "issuer_key_id": "sha256:...",
    "epoch_id": "epoch_01J...",
    "token": "base64url:...",
    "spend_context": "sha256:..."
  },

  "capabilities": {
    "accepts_verified_slices": true,
    "accepts_plain_snippets": true,
    "accepts_receipt_challenges": true
  }
}
```

Validation:

- qid must be 128 bits or larger.
- query length <= max_query_bytes.
- top_k <= max_top_k.
- ttl_ms <= max_ttl_ms.
- reply_pubkey must be fresh.
- anonymous query ticket must be valid if policy requires tickets.
- message must not include durable requester identity.

### 20.2 RESPONSE_V1

```json
{
  "schema": "swf.friend_search.response.v1",
  "qid": "same-qid",
  "responder_ephemeral_pubkey": "x25519:base64...",
  "aead": "chacha20-poly1305",
  "nonce": "base64...",
  "ciphertext": "base64...",
  "created_ms": 1760000001000
}
```

Encrypted plaintext:

```json
{
  "schema": "swf.friend_search.bundle.v1",
  "qid": "same-qid",
  "provider_pubkey": "ed25519:...",
  "provider_signature": "ed25519sig:...",
  "served_at_ms": 1760000001000,
  "index_scope": "friends",
  "results": [],
  "receipt_challenges": []
}
```

Provider identity should be inside ciphertext, not exposed to transport observers.

---

## 21. Friend responder behavior

A responder:

1. Validates SEARCH_V1 size, qid, ttl, top_k, reply key, and ticket.
2. Checks local answering policy.
3. Searches only shareable corpus.
4. Builds compact result bundle.
5. Sanitizes title, URL, snippet.
6. Generates receipt challenges for eligible results.
7. Signs bundle with provider/content key.
8. Encrypts bundle to requester one-time reply key.
9. Returns through configured friend transport.

### 21.1 Responder policy

```yaml
friend_responder:
  enabled: true
  answer_queries: true
  max_query_bytes: 512
  max_top_k: 8
  max_response_bytes: 16384
  max_snippet_chars: 240
  max_results_per_query: 8
  search_share_scopes:
    - friends
    - public
  deny_sensitivity_labels:
    - high
  allow_file_urls: false
  allow_localhost_urls: false
  allow_private_ip_urls: false
  rate_limit:
    max_rounds_per_minute: 20
    max_cpu_ms_per_query: 100
```

---

## 22. Self public egress

`SELF_PUBLIC_EGRESS` means this device queries public engines through the local SearXNG instance or configured public adapter.

SearXNG's `engines:` configuration controls which engines are available, and SearXNG settings can enable, disable, remove, or keep only selected engines; therefore the router should call SearXNG with an explicit engine allowlist for public egress, rather than letting ordinary SearXNG fanout decide privacy policy.

### 22.1 Config

```yaml
self_public_egress:
  enabled: true
  require_confirmation: false

  searxng:
    base_url: "http://127.0.0.1:8888"
    format: "json"
    engines:
      - duckduckgo
      - brave
    categories:
      - general
    timeout_ms: 5000

  network:
    mode: direct   # direct | tor_socks5 | disabled
    tor_socks5_proxy: "socks5h://127.0.0.1:9050"
    require_tor_dns_leak_check: true
```

### 22.2 Response metadata

```json
{
  "delivery_path": "SELF_PUBLIC_EGRESS",
  "origin_paths": ["SELF_PUBLIC_EGRESS"],
  "privacy_level": "public_from_self",
  "public_egress_used_this_request": true,
  "egress": {
    "adapter": "searxng",
    "network_mode": "direct",
    "engines_requested": ["duckduckgo", "brave"],
    "engines_returned": ["duckduckgo"]
  },
  "warning": "This query was sent to public search engines from this device/network."
}
```

Hard rule:

> Do not use a third-party public SearXNG instance and label it `SELF_PUBLIC_EGRESS`
> unless the response discloses that the third-party SearXNG instance also saw the query.

If added later, call that:

```
PUBLIC_VIA_EXTERNAL_SEARXNG
```

---

## 23. HTTP API

### 23.1 Bind behavior

```yaml
api:
  bind: "127.0.0.1"
  port: 7780
  auth_required: true
  cors:
    enabled: false
  csrf_protection: true
  allow_browser_origins: []
```

Prefer Unix socket for local agent integrations:

```yaml
api:
  unix_socket: "~/.swf/search.sock"
```

### 23.2 POST /web_search

Request:

```json
{
  "q": "dc nets practical deployment",
  "policy": "default",
  "top_k": 8,
  "routing_goal": "balanced",
  "allow_cached": true
}
```

Response:

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "LOCAL_INDREX",
  "origin_paths": ["LOCAL_INDREX"],
  "dominant_origin_path": "LOCAL_INDREX",
  "privacy_level": "local_only",
  "network_used_this_request": false,
  "public_egress_used_this_request": false,
  "fallbacks_tried": ["LOCAL_CACHE"],
  "results": []
}
```

### 23.3 POST /web_search/preview_route

Does not execute public egress.

```json
{
  "q": "latest rust CVE",
  "policy": "default"
}
```

Response:

```json
{
  "status": "ok",
  "would_try": [
    "LOCAL_CACHE",
    "LOCAL_INDREX",
    "LAN_FRIEND_DCNET",
    "SELF_PUBLIC_EGRESS"
  ],
  "public_egress_possible": true,
  "public_egress_requires_confirmation": true,
  "reason": "freshness_query"
}
```

### 23.4 GET /health

```json
{
  "status": "ok",
  "local_indrex": {
    "enabled": true,
    "documents": 123456,
    "last_indexed_ms": 1760000000000
  },
  "lan_friend": {
    "enabled": true,
    "transport": "dcnet_real",
    "active_peer_count": 5,
    "min_anonymity_set_met": true,
    "tickets_required": true
  },
  "self_public_egress": {
    "enabled": true,
    "mode": "direct"
  }
}
```

---

## 24. Logging and telemetry

Default logging must not include raw queries.

```yaml
logging:
  raw_queries: false
  query_hmac: true
  include_paths: true
  include_attempt_reasons: true
  include_peer_ids: false
  include_provider_pubkeys: false
  include_ticket_nullifiers: false
  include_receipt_nullifiers: false
```

Allowed log event:

```json
{
  "event": "search_completed",
  "request_id": "req_01J...",
  "query_hmac": "hmac-sha256:...",
  "policy": "default",
  "delivery_path": "SELF_PUBLIC_EGRESS",
  "origin_paths": ["SELF_PUBLIC_EGRESS"],
  "public_egress_used": true,
  "duration_ms": 1200
}
```

Disallowed by default:

- raw query
- raw snippets
- full friend URLs
- peer IP addresses
- ticket tokens
- ticket nullifiers
- receipt tokens
- receipt nullifiers
- local filesystem paths

---

## 25. Failure taxonomy

```
empty_query
policy_denied
cache_miss
cache_origin_not_allowed
local_index_unavailable
local_index_error
insufficient_results
freshness_not_met
no_peers_online
minimum_anonymity_set_not_met
dcnet_daemon_unreachable
round_timeout
malformed_response
decrypt_failed
provider_signature_invalid
response_too_large
too_many_peer_responses
anonymous_ticket_missing
anonymous_ticket_invalid
anonymous_ticket_double_spent
anonymous_ticket_wrong_epoch
anonymous_ticket_issuer_untrusted
anonymous_receipt_invalid
anonymous_receipt_double_spent
anonymous_receipt_wrong_epoch
suspicious_private_route_failure
public_egress_disabled
public_egress_requires_confirmation
public_egress_error
```

Example:

```json
{
  "path": "LAN_FRIEND_DCNET",
  "status": "unavailable",
  "reason": "anonymous_ticket_double_spent",
  "results": []
}
```

---

## 26. Downgrade protection

```yaml
downgrade_protection:
  public_after_no_peers: allow
  public_after_timeout: confirm
  public_after_malformed_response: confirm
  public_after_min_anonymity_not_met: confirm
  public_after_suspicious_failure: confirm
  public_after_ticket_failure: deny
```

Ticket failure should not trigger public egress. If a LAN query ticket is missing, invalid, or double-spent, that is an authorization failure, not a search-insufficiency signal.

---

## 27. Phase 6: Anonymous tickets, receipts, and bounded reputation

This is the newly filled-in section.

### 27.1 Why Phase 6 matters for LAN

Phase 6 is useful before WAN because LAN friend search has two immediate abuse problems:

1. **Query spam**: A peer can flood the friend circle with expensive or annoying queries.
2. **Reputation spam**: A peer can falsely inflate a provider's reputation unless positive feedback is scarce.

Anonymous tickets solve the first problem by proving quota without revealing requester identity.

Anonymous receipts partially solve the second problem by making positive feedback scarce and one-time-use. They do not prove that the provider was objectively useful; they prove only that some authorized anonymous peer spent a limited receipt on that provider.

This is enough for LAN-local ranking. It is not enough for global reputation.

### 27.2 Design stance

Use two separate primitives:

- **Anonymous query tickets**: Required to send LAN_FRIEND_DCNET searches. Anti-spam mechanism.
- **Anonymous receipt tickets**: Optional positive feedback after a provider serves useful results. Reputation signal.
- **Provider service proofs**: Signed by providers. Bind a receipt opportunity to an actual response bundle.

Do not combine these into one complicated credential for v1.

### 27.3 Recommended crypto family

For v1, use one-time blind tokens similar to Privacy Pass public-verifiable tokens.

Privacy Pass RFC 9578 specifies two issuance variants: privately verifiable tokens using a VOPRF and publicly verifiable tokens using a blind RSA signature scheme. Public verification is simpler for LAN friend search because all peers can verify a query ticket without sharing an issuer private key.

For future multi-use rate limits, look at ARC or ACT-style credentials, but treat them as future work because current ARC/ACT documents are Internet-Drafts, not stable RFCs. ARC is designed to let a credential produce a fixed number of unlinkable tokens for presentation contexts; ACT drafts describe a credit-style credential where spending credits invalidates the old credential and returns a credential with the remaining balance.

For richer attribute-bearing anonymous credentials, BBS or Coconut-like schemes are candidates. BBS proofs are designed for unlinkable selective-disclosure presentations, but their own drafts warn that headers, revealed values, and side channels can still create linkability. Coconut supports threshold issuance, selective disclosure, private/public attributes, re-randomization, and unlinkable selective revelations.

Practical rule:

```
v1:
  One-time blind tokens.

v2:
  Threshold issuance.

v3:
  Anonymous credentials with attributes or rate-limited multi-use credentials.
```

### 27.4 Actors

- **Circle Member**: A durable LAN friend identity allowed into the circle.
- **Client**: The anonymous requester spending a query ticket.
- **Origin**: The party consuming a token. For query tickets, the origin is the LAN friend circle. For receipt tickets, the origin is the provider or receipt board.
- **Issuer**: Entity that issues blinded tokens to authenticated circle members.
- **Verifier**: Entity that checks token validity and double-spend status.
- **Receipt Board**: Optional LAN-local append-only board for anonymous receipts.

For v1, the issuer may be a single elected peer. For stronger safety, move to threshold issuance later.

### 27.5 Issuer models

#### 27.5.1 Single issuer

Pros:
- Simple.
- Easy to implement.
- Good for small trusted LAN circle.

Cons:
- Can deny issuance.
- Can observe issuance timing.
- Can create partitioning if quotas vary.
- Single point of policy control.

The issuer should not be able to link blinded issued tokens to later redemptions cryptographically, but issuance side channels still matter.

#### 27.5.2 Rotating issuer

Each epoch has one issuer.
Issuer rotates among trusted peers.

This reduces permanent control by one peer, but does not eliminate side channels.

#### 27.5.3 Threshold issuer

t-of-n peers issue partial blind credentials.
Client combines partial credentials into one usable token/credential.

This is the preferred future direction. It is not required for v1.

#### 27.5.4 Local-only issuer

Each user mints their own local tokens.

Not acceptable for anti-spam.

Self-issued tickets prove nothing to peers.

### 27.6 Epochs

Tickets and receipts are scoped to epochs.

```yaml
anonymous_credentials:
  epoch_duration_hours: 24
  max_clock_skew_ms: 300000
  accept_previous_epoch_ms: 600000
```

Each epoch has:

- circle_id
- epoch_id
- issuer_key_id
- query_ticket_quota
- receipt_ticket_quota
- member_roster_commitment

Example:

```json
{
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "issuer_key_id": "sha256:...",
  "member_roster_commitment": "sha256:..."
}
```

### 27.7 Quotas

Use equal quota buckets by default.

```yaml
anonymous_credentials:
  query_tickets_per_member_per_epoch: 50
  receipt_tickets_per_member_per_epoch: 20
  equal_quota_buckets: true
  allow_custom_per_member_quota: false
```

Reason: if one peer receives a unique number of tokens, that can partition anonymity.

If different quotas are needed, use coarse public buckets:

```
small: 10 query tickets
normal: 50 query tickets
large: 200 query tickets
```

But the bucket itself becomes a privacy-relevant attribute.

### 27.8 Ticket families

```
QUERY_TICKET_V1
  Spent to send one LAN friend search request.

RECEIPT_TICKET_V1
  Spent to issue one positive provider receipt.

PROVIDER_SERVICE_PROOF_V1
  Signed provider statement that it served a result bundle.

ABUSE_REPORT_V1
  Reserved.
  Not anonymous by default in v1.
```

Do not use anonymous negative receipts in v1. Anonymous negative feedback is too easy to weaponize.

### 27.9 Query ticket issuance

At epoch start, each durable peer authenticates to the issuer using its peer identity and requests blinded query tickets.

High-level flow:

1. Peer authenticates to issuer using durable peer identity.
2. Peer proves membership in current circle.
3. Peer prepares N blinded token requests.
4. Issuer checks quota.
5. Issuer signs blinded requests.
6. Peer unblinds signatures.
7. Peer stores usable anonymous query tickets locally.

The issuer stores:

- peer_identity
- epoch_id
- quota_issued_count

The issuer must not store:

- unblinded token
- token preimage
- future spend nullifier
- raw query

### 27.10 Query ticket structure

Logical structure:

```json
{
  "family": "QUERY_TICKET_V1",
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "issuer_key_id": "sha256:...",
  "token_body": {
    "nonce": "256-bit-random",
    "scope": "LAN_FRIEND_DCNET",
    "cost_class": "standard_query"
  },
  "issuer_signature": "blind-signature-output"
}
```

The exact cryptographic encoding depends on the token library. Do not invent a new blind-signature scheme.

### 27.11 Query ticket redemption

`SEARCH_V1` includes a query ticket.

```json
"anonymous_query_ticket": {
  "family": "QUERY_TICKET_V1",
  "issuer_key_id": "sha256:...",
  "epoch_id": "epoch_2026-04-29",
  "token": "base64url:...",
  "spend_context": "sha256:..."
}
```

Recommended spend context:

```
spend_context =
  H(
    "swf.query_ticket.spend.v1" ||
    circle_id ||
    epoch_id ||
    qid ||
    round_id ||
    route = "LAN_FRIEND_DCNET"
  )
```

Nullifier:

```
query_ticket_nullifier =
  H("swf.query_ticket.nullifier.v1" || canonical_token_encoding)
```

Peers verify:

1. Issuer key is trusted for this circle and epoch.
2. Ticket signature is valid.
3. Ticket family is QUERY_TICKET_V1.
4. Ticket epoch is acceptable.
5. Ticket scope is LAN_FRIEND_DCNET.
6. Nullifier has not been spent.
7. Spend context matches this qid/round.

If valid, peers record the nullifier until epoch expiry plus grace period.

### 27.12 Query ticket privacy rules

A query ticket must not contain:

- peer identity
- provider key
- device name
- IP address
- unique quota bucket unless unavoidable
- issue timestamp more precise than epoch

Ticket redemption leaks:

- Someone with a valid ticket spent one query.
- The query content.
- The epoch and circle.

Ticket redemption should not leak:

- Which member received the ticket.
- Which durable peer identity asked the query.

Issuance timing can still leak. Mitigation:

- Issue tickets in batches at epoch start.
- Use equal quota buckets.
- Allow prefetch.
- Avoid per-query online issuance.
- Optionally use cover issuance.

### 27.13 Ticket storage

Tickets are bearer credentials. If stolen, they can be spent.

Store locally:

```yaml
ticket_store:
  path: "~/.swf/tickets.sqlite"
  encrypt_at_rest: true
  persist_spent_tokens: true
  persist_raw_tokens: true
  raw_token_file_permissions: "0600"
```

Ticket table:

```sql
CREATE TABLE anonymous_tickets (
    id INTEGER PRIMARY KEY,
    family TEXT NOT NULL,
    circle_id TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    issuer_key_id TEXT NOT NULL,
    token_ciphertext BLOB NOT NULL,
    token_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    issued_at_ms INTEGER,
    spent_at_ms INTEGER,
    spend_context TEXT,
    CHECK (family IN ('QUERY_TICKET_V1', 'RECEIPT_TICKET_V1')),
    CHECK (status IN ('available', 'spent', 'expired', 'revoked'))
);
```

Spent nullifier table:

```sql
CREATE TABLE spent_ticket_nullifiers (
    nullifier TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    circle_id TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    spent_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
```

### 27.14 Query ticket failure behavior

If LAN friend search requires tickets and no valid ticket is available:

```json
{
  "status": "no_acceptable_route",
  "delivery_path": "NO_RESULT",
  "privacy_level": "none",
  "reason": "anonymous_ticket_missing",
  "available_fallback": "SELF_PUBLIC_EGRESS",
  "public_egress_used_this_request": false,
  "results": []
}
```

Do not automatically public-egress because a ticket is missing. That would make ticket exhaustion a privacy downgrade vector.

### 27.15 Receipt design overview

A receipt is an anonymous positive signal:

> "Someone in the circle spent one scarce receipt token to credit provider P."

It is not a proof that:

- the provider was objectively correct;
- the requester was honest;
- there was no collusion;
- the result was clicked or read.

Therefore, receipts should affect local ranking slowly and with caps.

### 27.16 Receipt eligibility

A result is receipt-eligible only if the provider response included a valid provider service proof.

Provider service proof:

```json
{
  "schema": "swf.provider_service_proof.v1",
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "qid": "base64url-128-bit-random",
  "provider_pubkey": "ed25519:...",
  "response_digest": "sha256:...",
  "served_at_ms": 1760000001000,
  "receipt_challenge_nonce": "base64url-128-bit-random",
  "receipt_classes": ["useful_result", "verified_slice"],
  "provider_signature": "ed25519sig:..."
}
```

response_digest:

```
H(canonical SearchResultBundle without provider_signature)
```

service_proof_hash:

```
H("swf.service_proof.v1" || canonical_service_proof)
```

The requester stores the full service proof locally. Public receipt boards should store only the hash unless explicit audit mode is enabled.

### 27.17 Receipt ticket issuance

Receipt tickets are issued like query tickets, but with a different family and quota.

High-level flow:

1. Peer authenticates to issuer as a circle member.
2. Peer requests blinded RECEIPT_TICKET_V1 tokens.
3. Issuer signs up to quota.
4. Peer stores anonymous receipt tickets.

Receipt tokens are not bound to a specific provider at issuance time.

This preserves privacy but means a requester can spend receipts on any provider. That is acceptable only because receipts are scarce and capped.

### 27.18 Receipt ticket structure

```json
{
  "family": "RECEIPT_TICKET_V1",
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "issuer_key_id": "sha256:...",
  "token_body": {
    "nonce": "256-bit-random",
    "scope": "PROVIDER_POSITIVE_RECEIPT",
    "receipt_class": "useful_result"
  },
  "issuer_signature": "blind-signature-output"
}
```

Receipt class enum:

```
useful_result
saved_result
verified_slice
high_quality_snippet
```

Avoid negative anonymous receipt classes in v1.

### 27.19 Receipt redemption

Requester sends a receipt through delayed LAN anonymous transport, preferably not immediately after the query.

```json
{
  "schema": "swf.anonymous_receipt.v1",
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "provider_pubkey": "ed25519:...",
  "receipt_class": "useful_result",
  "receipt_token": {
    "family": "RECEIPT_TICKET_V1",
    "issuer_key_id": "sha256:...",
    "token": "base64url:..."
  },
  "service_proof_hash": "sha256:...",
  "result_digest": "sha256:...",
  "created_ms": 1760000050000
}
```

Spend context:

```
H(
  "swf.receipt_ticket.spend.v1" ||
  circle_id ||
  epoch_id ||
  provider_pubkey ||
  receipt_class ||
  service_proof_hash
)
```

Receipt nullifier:

```
H("swf.receipt_ticket.nullifier.v1" || canonical_token_encoding)
```

Verification:

1. Issuer key trusted for circle and epoch.
2. Receipt token signature valid.
3. Token family is RECEIPT_TICKET_V1.
4. Scope is PROVIDER_POSITIVE_RECEIPT.
5. Receipt class allowed.
6. Provider key is syntactically valid.
7. Nullifier has not been spent.
8. service_proof_hash is present.
9. If full service proof is available, provider signature verifies.

### 27.20 Receipt delivery modes

#### 27.20.1 Local-only receipt

No network.

- Requester updates local provider ranking.
- Safest privacy.
- No durable provider reputation outside requester's machine.

#### 27.20.2 Direct encrypted receipt to provider

- Requester encrypts receipt to provider_pubkey.
- Provider learns it received a receipt.
- Requester identity remains absent.
- Timing may correlate.

This should be delayed and batched.

#### 27.20.3 LAN receipt board

- Requester submits anonymous receipt to a shared LAN board.
- Board stores provider_pubkey, receipt_class, epoch, nullifier hash, service_proof_hash.

The board must not store raw requester identity.

#### 27.20.4 DC-net receipt round

- Receipts are submitted in separate anonymous rounds.
- Best privacy.
- More complex.

Recommended v1:

- local-only receipt first;
- then delayed LAN receipt board;
- then DC-net receipt round.

### 27.21 Receipt privacy rules

Do not include in public receipt records:

- requester identity
- raw query
- qid by default
- raw result URL by default
- full service proof by default
- exact click timestamp
- IP address
- device name

Public receipt board record:

```json
{
  "schema": "swf.receipt_board_record.v1",
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "provider_pubkey": "ed25519:...",
  "receipt_class": "useful_result",
  "receipt_nullifier_hash": "sha256:...",
  "service_proof_hash": "sha256:...",
  "accepted_at_ms_bucket": 1760000000000
}
```

Use coarse timestamp buckets.

### 27.22 Preventing fake positive receipts

You cannot fully prevent colluding peers from spending their own scarce receipts on each other.

You can prevent or limit:

- **Unlimited fake receipts**: receipt tokens are scarce.
- **Double-spent receipts**: nullifiers are tracked.
- **Receipts from non-members**: issuer signature required.
- **Receipts for nonexistent provider keys**: provider key validation required.
- **Receipts for providers that never answered, unless provider colludes**: service_proof_hash required; full service proof can be audited locally or by provider.
- **One provider gaining unlimited reputation in one epoch**: per-provider caps.

Reputation rule:

> Anonymous receipts are bounded positive hints, not ground truth.

### 27.23 Reputation accounting

#### 27.23.1 Local provider score

```yaml
reputation:
  enabled: true
  local_provider_scores: true
  network_receipts: true
  receipt_board: true
  decay_half_life_days: 30
```

Score inputs:

Strong local positive:
- user clicked result
- user saved result
- user manually marked useful
- verified slice valid

Weak network positive:
- anonymous receipt accepted

Negative local:
- malformed response
- invalid provider signature
- spammy duplicate URLs
- snippet mismatch after fetch
- repeated timeout

Network receipts should have lower weight than local user actions.

#### 27.23.2 Suggested weights

```yaml
reputation_weights:
  local_click: 1.0
  local_save: 2.0
  manual_useful: 3.0
  verified_slice_valid: 1.5
  anonymous_receipt_useful_result: 0.25
  anonymous_receipt_verified_slice: 0.5
  malformed_response: -1.0
  invalid_signature: -3.0
  spam_duplicate: -1.0
  timeout: -0.1
```

#### 27.23.3 Caps

```yaml
reputation_caps:
  max_receipt_score_per_provider_per_epoch: 5.0
  max_receipts_per_provider_per_epoch: 20
  max_score_from_network_receipts_ratio: 0.35
```

This prevents anonymous receipts from dominating local experience.

### 27.24 Provider reputation table

```sql
CREATE TABLE provider_reputation (
    provider_pubkey TEXT PRIMARY KEY,
    local_score REAL NOT NULL DEFAULT 0,
    receipt_score REAL NOT NULL DEFAULT 0,
    total_score REAL NOT NULL DEFAULT 0,
    last_updated_ms INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    malformed_count INTEGER NOT NULL DEFAULT 0,
    invalid_signature_count INTEGER NOT NULL DEFAULT 0,
    timeout_count INTEGER NOT NULL DEFAULT 0
);
```

Receipt table:

```sql
CREATE TABLE anonymous_receipts (
    receipt_id INTEGER PRIMARY KEY,
    provider_pubkey TEXT NOT NULL,
    receipt_class TEXT NOT NULL,
    circle_id TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    service_proof_hash TEXT,
    result_digest TEXT,
    receipt_nullifier_hash TEXT NOT NULL UNIQUE,
    accepted_at_ms INTEGER NOT NULL,
    source TEXT NOT NULL,
    CHECK (source IN ('local_only', 'direct_provider', 'receipt_board', 'dcnet_receipt_round'))
);
```

### 27.25 Anonymous receipt abuse cases

**Case: provider self-inflates**

A provider uses its own receipt quota on itself.

Mitigation:
- Allowed but bounded.
- Equal receipt quota.
- Per-provider epoch cap.
- Network receipts low weight.
- Local user actions higher weight.

**Case: colluding group inflates one provider**

Mitigation:
- Bounded by group receipt quotas.
- Cap network receipt influence.
- Decay over time.
- Display local trust source.

**Case: malicious peer submits negative anonymous reports**

Mitigation:
- No anonymous negative receipts in v1.
- Negative reports are local-only or authenticated abuse reports.

**Case: receipt timing links requester to query**

Mitigation:
- Delay receipts.
- Batch receipts.
- Use coarse timestamp buckets.
- Use receipt rounds separate from search rounds.
- Prefer DC-net receipt round later.

**Case: issuer partitions users**

Mitigation:
- Equal quota buckets.
- Public issuer_key_id.
- Public epoch config.
- Roster commitment.
- Optional threshold issuer.

### 27.26 Anonymous ticket and receipt APIs

#### 27.26.1 POST /credentials/issue

Authenticated local call to obtain blinded ticket batch.

```json
{
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "families": {
    "QUERY_TICKET_V1": 50,
    "RECEIPT_TICKET_V1": 20
  }
}
```

Response:

```json
{
  "status": "ok",
  "issuer_key_id": "sha256:...",
  "issued": {
    "QUERY_TICKET_V1": 50,
    "RECEIPT_TICKET_V1": 20
  }
}
```

#### 27.26.2 GET /credentials/status

```json
{
  "circle_id": "circle_01J...",
  "epoch_id": "epoch_2026-04-29",
  "tickets": {
    "QUERY_TICKET_V1": {
      "available": 43,
      "spent": 7,
      "expired": 0
    },
    "RECEIPT_TICKET_V1": {
      "available": 18,
      "spent": 2,
      "expired": 0
    }
  }
}
```

#### 27.26.3 POST /receipts/submit

```json
{
  "provider_pubkey": "ed25519:...",
  "receipt_class": "useful_result",
  "service_proof_hash": "sha256:...",
  "result_digest": "sha256:...",
  "delivery": "receipt_board"
}
```

Response:

```json
{
  "status": "ok",
  "receipt_path": "receipt_board",
  "privacy_level": "anonymous_receipt_query_not_included",
  "receipt_nullifier_hash": "sha256:..."
}
```

### 27.27 Ticket config

```yaml
anonymous_credentials:
  enabled: true
  epoch_duration_hours: 24
  max_clock_skew_ms: 300000
  accept_previous_epoch_ms: 600000

  issuer:
    mode: single          # single | rotating | threshold
    issuer_key_id: "sha256:..."
    require_member_auth_for_issuance: true
    equal_quota_buckets: true

  query_tickets:
    enabled: true
    required_for_lan_friend_dcnet: true
    tickets_per_member_per_epoch: 50
    cost_standard_query: 1
    cost_expensive_query: 3
    reject_on_missing_ticket: true

  receipt_tickets:
    enabled: true
    tickets_per_member_per_epoch: 20
    allow_classes:
      - useful_result
      - saved_result
      - verified_slice
    allow_negative_receipts: false

  spent_nullifiers:
    persist: true
    retention_epochs: 3
    gossip_between_peers: true

  privacy:
    issue_at_epoch_start: true
    equal_batch_sizes: true
    delay_receipts_ms_min: 60000
    delay_receipts_ms_max: 3600000
    receipt_timestamp_bucket_ms: 3600000
```

### 27.28 Receipt board config

```yaml
receipt_board:
  enabled: true
  storage_path: "~/.swf/receipt_board.sqlite"
  accept_anonymous_receipts: true
  require_receipt_ticket: true
  require_service_proof_hash: true
  publish_raw_service_proofs: false
  publish_qid: false
  max_receipts_per_provider_per_epoch: 20
  max_receipt_score_per_provider_per_epoch: 5.0
```

### 27.29 Phase 6 security invariant

> A query ticket must authorize one LAN friend query without identifying the requester.
>
> A receipt ticket must authorize one positive reputation event without identifying the requester.
>
> Neither ticket type may trigger public egress fallback when missing or invalid.
>
> Receipts must never be treated as proof of truth, only as bounded positive feedback.

### 27.30 Phase 6 implementation order

```
6A. Local ticket store and issuer skeleton.
6B. Query ticket issuance/redemption for LAN_FRIEND_DCNET.
6C. Spent nullifier database and double-spend rejection.
6D. Local-only receipts.
6E. Provider service proofs.
6F. Anonymous receipt tickets.
6G. Delayed receipt submission.
6H. Receipt board.
6I. Reputation score integration.
6J. Threshold issuer research/prototype.
```

Do 6A–6C before network receipts. Query tickets are more important than receipts.

---

## 28. Result verification fields

```json
"verification": {
  "verified_slice": false,
  "content_hash": "sha256:...",
  "merkle_root": null,
  "inclusion_proof": null,
  "sigchain_head": null,
  "dsse_attestation": null,
  "verification_status": "not_checked"
}
```

verification_status enum:

```
not_provided
not_checked
valid
invalid
unsupported
```

Rule:

> verified_slice = true only if requester validated proof against trusted or TOFU-accepted provider/content key.

---

## 29. Module responsibilities

### 29.1 search_policy.py

- Load YAML config.
- Validate policy schema.
- Resolve aliases.
- Expose immutable SearchPolicy objects.
- Reject impossible route combinations.

Reject:

- placeholder friend transport in production;
- public_egress.mode = allow with local_only;
- unknown route names;
- cache origins broader than route policy unless explicit.

### 29.2 search_response.py

- Enums for paths, status, privacy levels, reason codes.
- SearchResponse model.
- SearchResult model.
- SearchAttempt model.
- Invariant validation.
- JSON serialization.

Invariants:

- SELF_PUBLIC_EGRESS implies public_egress_used_this_request = true.
- LOCAL_CACHE requires non-empty origin_paths.
- local_only implies no public origin paths.
- LAN_FRIEND_DIRECT_PLACEHOLDER implies not_anonymous_placeholder.
- LAN_FRIEND_DCNET requires min anonymity set met.
- anonymous_ticket.accepted = true if tickets are required and route is LAN_FRIEND_DCNET.

### 29.3 search_router.py

- Normalize query.
- Build QueryContext.
- Run route order.
- Apply sufficiency.
- Apply downgrade protection.
- Handle confirmation.
- Return SearchResponse.

### 29.4 local_cache.py

- HMAC query keys.
- Store/retrieve result bundles.
- Preserve origin paths.
- Expire stale entries.
- Enforce cache-origin policy.

### 29.5 local_indrex.py

- Open SQLite read-only where possible.
- Build safe FTS5 query.
- Search local corpus.
- Normalize scores.
- Return LOCAL_INDREX result set.

### 29.6 dcnet_client.py

- Create SEARCH_V1.
- Generate one-time reply key.
- Attach anonymous query ticket.
- Collect/decrypt RESPONSE_V1 bundles.
- Validate friend results.
- Return structured result set.

### 29.7 dcnet_daemon.py

- Peer discovery.
- Active circle tracking.
- Friend responder.
- Message validation.
- Ticket verification.
- Rate limiting.
- Transport adapter lifecycle.

### 29.8 anonymous_tickets.py

- Blind token issuance client.
- Ticket store.
- Ticket selection.
- Ticket redemption metadata.
- Nullifier generation.
- Spent nullifier sync.
- Issuer key validation.

### 29.9 anonymous_receipts.py

- Provider service proof creation.
- Receipt eligibility.
- Receipt ticket spending.
- Delayed receipt submission.
- Receipt board client.
- Receipt validation.

### 29.10 reputation.py

- Local provider scores.
- Receipt score integration.
- Decay.
- Caps.
- Malformed-response penalties.

### 29.11 public_egress.py

- Call local SearXNG public engines.
- Enforce engine allowlist.
- Attach egress metadata.
- Return SELF_PUBLIC_EGRESS result set.

---

## 30. Full config v0.3

```yaml
search:
  default_policy: default
  top_k: 8

  sufficiency:
    min_results: 3
    min_unique_hosts: 2
    min_top_score: 0.25
    min_mean_score: 0.18
    max_staleness_days: null
    require_fresh_for_freshness_queries: true
    allow_single_exact_hit: true

  downgrade_protection:
    public_after_no_peers: allow
    public_after_timeout: confirm
    public_after_malformed_response: confirm
    public_after_min_anonymity_not_met: confirm
    public_after_suspicious_failure: confirm
    public_after_ticket_failure: deny

  cache:
    enabled: true
    persist_raw_queries: false
    default_ttl_hours: 24
    local_indrex_ttl_hours: 168
    lan_friend_ttl_hours: 24
    self_public_ttl_hours: 12

  local_indrex:
    enabled: true
    db_path: "~/world_knowledge/indrex.sqlite"
    max_results: 20
    advanced_fts_syntax: false
    search_private_corpus_for_local: true
    search_shareable_corpus_for_friends: true

  self_public_egress:
    enabled: true
    searxng:
      base_url: "http://127.0.0.1:8888"
      format: "json"
      engines:
        - duckduckgo
        - brave
      timeout_ms: 5000
    network:
      mode: direct
      tor_socks5_proxy: "socks5h://127.0.0.1:9050"
      require_tor_dns_leak_check: true

  lan_dcnet:
    enabled: true
    transport: dcnet_real
    round_timeout_ms: 3000
    max_rounds_per_query: 2
    min_anonymity_set: 3
    recommended_anonymity_set: 5
    top_k: 8
    max_query_bytes: 512
    max_response_bytes: 16384

    peer_discovery:
      mdns: true
      peers_yaml: true
      tailscale: false

    responder:
      enabled: true
      answer_queries: true
      search_share_scopes:
        - friends
        - public
      deny_sensitivity_labels:
        - high
      max_snippet_chars: 240
      allow_file_urls: false
      allow_localhost_urls: false
      allow_private_ip_urls: false

  anonymous_credentials:
    enabled: true
    epoch_duration_hours: 24
    max_clock_skew_ms: 300000
    accept_previous_epoch_ms: 600000

    issuer:
      mode: single
      issuer_key_id: "sha256:..."
      require_member_auth_for_issuance: true
      equal_quota_buckets: true

    query_tickets:
      enabled: true
      required_for_lan_friend_dcnet: true
      tickets_per_member_per_epoch: 50
      cost_standard_query: 1
      cost_expensive_query: 3
      reject_on_missing_ticket: true

    receipt_tickets:
      enabled: true
      tickets_per_member_per_epoch: 20
      allow_classes:
        - useful_result
        - saved_result
        - verified_slice
      allow_negative_receipts: false

    spent_nullifiers:
      persist: true
      retention_epochs: 3
      gossip_between_peers: true

    privacy:
      issue_at_epoch_start: true
      equal_batch_sizes: true
      delay_receipts_ms_min: 60000
      delay_receipts_ms_max: 3600000
      receipt_timestamp_bucket_ms: 3600000

  receipt_board:
    enabled: true
    storage_path: "~/.swf/receipt_board.sqlite"
    accept_anonymous_receipts: true
    require_receipt_ticket: true
    require_service_proof_hash: true
    publish_raw_service_proofs: false
    publish_qid: false
    max_receipts_per_provider_per_epoch: 20
    max_receipt_score_per_provider_per_epoch: 5.0

  reputation:
    enabled: true
    local_provider_scores: true
    network_receipts: true
    receipt_board: true
    decay_half_life_days: 30
    weights:
      local_click: 1.0
      local_save: 2.0
      manual_useful: 3.0
      verified_slice_valid: 1.5
      anonymous_receipt_useful_result: 0.25
      anonymous_receipt_verified_slice: 0.5
      malformed_response: -1.0
      invalid_signature: -3.0
      spam_duplicate: -1.0
      timeout: -0.1
    caps:
      max_receipt_score_per_provider_per_epoch: 5.0
      max_receipts_per_provider_per_epoch: 20
      max_score_from_network_receipts_ratio: 0.35

  api:
    bind: "127.0.0.1"
    port: 7780
    auth_required: true
    cors:
      enabled: false
    csrf_protection: true

  logging:
    raw_queries: false
    query_hmac: true
    include_paths: true
    include_attempt_reasons: true
    include_peer_ids: false
    include_provider_pubkeys: false
    include_ticket_nullifiers: false
    include_receipt_nullifiers: false
```

---

## 31. Example responses

### 31.1 Local success

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "LOCAL_INDREX",
  "origin_paths": ["LOCAL_INDREX"],
  "dominant_origin_path": "LOCAL_INDREX",
  "privacy_level": "local_only",
  "network_used_this_request": false,
  "public_egress_used_this_request": false,
  "friend_query_visible": false,
  "fallbacks_tried": ["LOCAL_CACHE"],
  "results": []
}
```

### 31.2 LAN friend DC-net success with ticket

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "LAN_FRIEND_DCNET",
  "origin_paths": ["LAN_FRIEND_DCNET"],
  "dominant_origin_path": "LAN_FRIEND_DCNET",
  "privacy_level": "anonymous_within_lan_circle_query_visible",
  "network_used_this_request": true,
  "public_egress_used_this_request": false,
  "friend_query_visible": true,
  "active_circle": {
    "active_peer_count": 5,
    "min_anonymity_set_met": true,
    "epoch_id": "epoch_2026-04-29"
  },
  "anonymous_ticket": {
    "required": true,
    "presented": true,
    "accepted": true,
    "ticket_family": "QUERY_TICKET_V1",
    "issuer_key_id": "sha256:..."
  },
  "fallbacks_tried": ["LOCAL_CACHE", "LOCAL_INDREX"],
  "warnings": [
    "Friend peers can see the query content."
  ],
  "results": []
}
```

### 31.3 Missing ticket

```json
{
  "schema": "swf.search_response.v1",
  "status": "no_acceptable_route",
  "delivery_path": "NO_RESULT",
  "origin_paths": [],
  "dominant_origin_path": "NO_RESULT",
  "privacy_level": "none",
  "reason": "anonymous_ticket_missing",
  "available_fallback": "SELF_PUBLIC_EGRESS",
  "public_egress_used_this_request": false,
  "warnings": [
    "LAN friend search requires an anonymous query ticket. Public fallback was not attempted."
  ],
  "results": []
}
```

### 31.4 Public fallback

```json
{
  "schema": "swf.search_response.v1",
  "status": "ok",
  "delivery_path": "SELF_PUBLIC_EGRESS",
  "origin_paths": ["SELF_PUBLIC_EGRESS"],
  "dominant_origin_path": "SELF_PUBLIC_EGRESS",
  "privacy_level": "public_from_self",
  "network_used_this_request": true,
  "public_egress_used_this_request": true,
  "friend_query_visible": false,
  "privacy_downgrade": true,
  "fallbacks_tried": [
    "LOCAL_CACHE",
    "LOCAL_INDREX",
    "LAN_FRIEND_DCNET"
  ],
  "fallback_reason": "no private route returned sufficient results",
  "warnings": [
    "This query was sent to public search engines from this device/network."
  ],
  "results": []
}
```

### 31.5 Anonymous receipt accepted

```json
{
  "schema": "swf.anonymous_receipt_response.v1",
  "status": "ok",
  "receipt_path": "receipt_board",
  "privacy_level": "anonymous_receipt_query_not_included",
  "provider_pubkey": "ed25519:...",
  "receipt_class": "useful_result",
  "receipt_nullifier_hash": "sha256:...",
  "warning": "Anonymous receipts are bounded reputation hints, not proof of correctness."
}
```

---

## 32. Acceptance tests

Policy tests:
- local_only never calls network.
- private_circle never calls public egress.
- default public fallback reports public_from_self.
- public confirmation blocks egress until confirmed.

Cache tests:
- cached public results are never labeled local_only.
- cache respects allowed_origin_paths.
- cache response contains delivery_path and origin_paths.

Placeholder tests:
- LAN_FRIEND_DIRECT_PLACEHOLDER always returns not_anonymous_placeholder.
- Placeholder cannot be enabled by production policy.

Friend tests:
- friend responder never searches private share_scope.
- friend responder rejects file://, localhost, private-IP URLs.
- malformed friend response rejected.
- too-small active circle cannot report LAN_FRIEND_DCNET.

Ticket tests:
- LAN_FRIEND_DCNET rejects missing ticket when required.
- invalid ticket rejected.
- double-spent ticket rejected.
- wrong-epoch ticket rejected.
- ticket failure does not trigger public egress.
- ticket redemption response does not reveal peer identity.

Receipt tests:
- receipt requires valid receipt ticket.
- double-spent receipt rejected.
- negative anonymous receipt rejected in v1.
- receipt board does not store raw query.
- receipt board does not store qid by default.
- receipt score caps are enforced.

Downgrade tests:
- malformed friend response triggers confirmation before public fallback.
- timeout behavior follows downgrade_protection config.
- no hidden public egress possible.

API tests:
- unauthenticated localhost request rejected.
- browser-origin request rejected unless explicitly allowed.
- confirmation token binds query_hmac and route.

Logging tests:
- raw query absent from logs by default.
- snippets absent from logs by default.
- provider keys absent from logs by default.
- ticket nullifiers absent from logs by default.
- receipt nullifiers absent from logs by default.

FTS tests:
- dangerous FTS syntax escaped in non-advanced mode.
- parser errors return structured failures.

Response invariant tests:
- every response has delivery_path.
- every result has origin_path.
- SELF_PUBLIC_EGRESS implies public_egress_used_this_request = true.
- local_only implies no public origin paths.
- LAN_FRIEND_DCNET with tickets required implies anonymous_ticket.accepted = true.

---

## 33. Revised implementation plan

### Phase 0: Metadata and invariants

- search_response.py
- search_policy.py
- response invariant checker
- reason-code enum
- privacy metadata tests

### Phase 1: Local cache and local indrex

- LOCAL_CACHE
- LOCAL_INDREX
- safe FTS query builder
- cache origin tracking
- local_only tests

### Phase 2: Self public egress

- SELF_PUBLIC_EGRESS via local SearXNG
- engine allowlist
- public confirmation flow
- public warning metadata
- downgrade protection

### Phase 3: LAN friend placeholder

- LAN_FRIEND_DIRECT_PLACEHOLDER
- simple LAN transport
- not_anonymous_placeholder label
- share_scope enforcement
- malformed response handling

### Phase 4: Real LAN DC-net adapter

- Real LAN DC-net transport behind the same interface.
- Router should not change.
- Adapter must attest active set, epoch, fixed membership, and min anonymity set.

### Phase 5: Local reputation

- local provider score
- manual usefulness feedback
- click/save feedback
- signature/proof validation score boost
- no network receipts yet

### Phase 6: Anonymous tickets and receipts

```
6A. Ticket store and issuer skeleton.
6B. Query ticket issuance/redemption.
6C. Spent nullifier database.
6D. Local-only receipts.
6E. Provider service proofs.
6F. Receipt ticket issuance/redemption.
6G. Delayed receipt submission.
6H. Receipt board.
6I. Reputation integration.
6J. Threshold issuer prototype.
```

### Phase 7: Hardening

- side-channel review
- issuance timing review
- receipt timing review
- peer collusion simulations
- quota partitioning tests

---

## 34. Final hardened thesis

> searxng-wth-frnds should answer locally first, ask a LAN friend circle only when the user accepts query visibility to that circle, require anonymous LAN query tickets to prevent spam without deanonymizing requesters, allow scarce anonymous receipts as bounded provider-reputation hints, and fall back to self public egress only when policy permits — while reporting both delivery path and original result provenance for every response.
