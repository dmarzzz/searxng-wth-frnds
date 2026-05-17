# Search policy cookbook

The four built-in policies cover most cases (`default`, `private_circle`,
`local_only`, `dev_placeholder_friends`). Sometimes you want something
specific to a moment — a public event, a sensitive research session, a
traveling laptop. This is a recipe book.

Each recipe is a YAML block you can drop into a config under
`search_policies:` and load with `SearchPolicy.parse_all(...)`. The
parser will reject combinations that violate §29.1; the comments call
out which rule each example would otherwise trip.

If you don't know the field meanings, read **`docs/SEARCH_ROUTER.md`**
first.

---

## 1. "Conference mode" — public-only, no friends

You're at a conference on hostile Wi-Fi. You want public web search
through your local SearXNG, but **no LAN friend chatter** (you don't
trust the network) and **no cache replay of friend results from
yesterday** (peer trust is moment-by-moment).

```yaml
search_policies:
  conference:
    route_order: [LOCAL_CACHE, LOCAL_INDREX, SELF_PUBLIC_EGRESS]

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: false
      lan_friend_direct_placeholder: false
      self_public_egress: true

    public_egress:
      mode: allow
      confirm_on_sensitive_query: true
      confirm_after_suspicious_private_failure: false

    cache:
      allow_result_cache: true
      # Drop friend origins from the allow-list, so any cached entry
      # tagged with a friend origin is refused outright (subset gate).
      allowed_origin_paths:
        - LOCAL_INDREX
        - SELF_PUBLIC_EGRESS
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: false

    anonymous_tickets:
      require_for_lan_friend_search: false  # moot — DCNET is off

    routing_goal: balanced
```

**Why this works.** `route_order` excludes both LAN routes, so the
router never tries them. Even if a result-set was previously cached
from a friend, the subset-gate on `cache.allowed_origin_paths` refuses
to replay it. `confirm_on_sensitive_query: true` makes the router
return `status=confirmation_required` for queries containing the
heuristic sensitivity substrings ("medical", "passport", etc.) — the
client must explicitly retry to send them to public engines.

---

## 2. "Field research" — strictly local, private to the bone

You're in a place where any network query could compromise your
research subject. The device should never make a network request from
this profile, **and `local_only` enforcement should crash loudly if
something tries.**

```yaml
search_policies:
  field_research:
    route_order: [LOCAL_CACHE, LOCAL_INDREX]

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: false
      lan_friend_direct_placeholder: false
      self_public_egress: false

    public_egress:
      mode: deny
      confirm_on_sensitive_query: false
      confirm_after_suspicious_private_failure: false

    cache:
      allow_result_cache: true
      # Only LOCAL_INDREX origins. The §29.2 invariant
      # "local_only privacy ⇒ no non-local origins" will reject any
      # accidental friend or public origin even if the cache somehow
      # ends up with one.
      allowed_origin_paths:
        - LOCAL_INDREX
      disclose_origin_paths: true

    friend_query_visibility:
      allow_query_visible_to_friends: false

    anonymous_tickets:
      require_for_lan_friend_search: false

    routing_goal: privacy_first
```

**Why this works.** Same shape as the built-in `local_only` but with
slightly different intent. The hard guarantee is the §29.2 invariant
chain: any response constructed under this policy will have
`privacy_level=local_only` if it has results at all — and that level
explicitly forbids `network_used_this_request=true`,
`public_egress_used_this_request=true`, and any non-local origin path.
A bug in router logic that tried to label a network response as
`local_only` would `raise InvariantError` rather than ship.

---

## 3. "Trusted school network" — friends-only, no public

A community deployment (e.g. a school or maker-space) where the local
hive is the trust boundary and public web search is intentionally off.
Friend peers are explicitly trusted; their query visibility is
acceptable in this context.

```yaml
search_policies:
  community_hive:
    route_order: [LOCAL_CACHE, LOCAL_INDREX, LAN_FRIEND_DCNET]

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

**Why this works.** Same as the built-in `private_circle`, named for
the community context. The hive members get fast LOCAL_INDREX answers
from their own archive, fall through to the DC-net for queries that
need broader coverage, and never accidentally hit the open web. The
`anonymous_tickets.require_for_lan_friend_search: true` keeps the
DC-net rate-limited so a curious user can't drown the LAN.

---

## 4. "Throwaway research host" — open hive, public welcome

A dedicated research host that runs publicly, archives everything,
and shares with whoever asks. Maximally permissive; the host owner
knows nothing here is private.

```yaml
search_policies:
  open_research:
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
      confirm_on_sensitive_query: false
      confirm_after_suspicious_private_failure: false

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
      require_for_lan_friend_search: false  # no quota

    routing_goal: latency_first
```

**Why this works.** Same shape as `default` but with both confirmation
hooks turned off (we already accepted that this host's queries can be
public) and `anonymous_tickets` disabled (no quota — this is a
high-traffic public host). `routing_goal: latency_first` will, in
later phases, bias the sufficiency heuristic toward "first acceptable
result" instead of "best available across routes."

---

## 5. "Demo wall" — dev placeholder, locally controlled

For local development of the wall-renderer or for a teardown demo
where you want to see the LAN_FRIEND_DIRECT_PLACEHOLDER path light up
without the DC-net complication.

```yaml
search_policies:
  dev_demo:
    route_order:
      - LOCAL_CACHE
      - LOCAL_INDREX
      - LAN_FRIEND_DIRECT_PLACEHOLDER
      - SELF_PUBLIC_EGRESS

    allow:
      local_cache: true
      local_indrex: true
      lan_friend_dcnet: false
      lan_friend_direct_placeholder: true   # ← the dev opt-in
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

**Why this works.** The policy name **must** be `dev` or start with
`dev_` (PolicyError otherwise). That's the §29.1 placeholder-in-
production check: the placeholder transport doesn't claim anonymity
and would falsely advertise a privacy property in production, so its
opt-in is gated on a name convention that's hard to type by accident.

`LAN_FRIEND_DIRECT_PLACEHOLDER` responses always carry
`privacy_level=not_anonymous_placeholder` and a warning string in the
response. The wall should render those visibly differently from real
DCNET responses.

---

## Common antipatterns the parser rejects

These will all raise `PolicyError` at parse time. Don't waste a
deployment cycle on them.

```yaml
# ❌ placeholder enabled but name doesn't start with `dev`/`dev_`
search_policies:
  totally_fine:                              # name lacks the dev_ prefix
    allow:
      lan_friend_direct_placeholder: true    # → PolicyError "dev-only"
```

```yaml
# ❌ public_egress.mode = allow but allow.self_public_egress = false
search_policies:
  contradiction:
    allow:
      self_public_egress: false
    public_egress:
      mode: allow                            # → PolicyError "contradiction"
```

```yaml
# ❌ cache origin broader than route policy
search_policies:
  cache_overreach:
    route_order: [LOCAL_INDREX]
    allow:
      local_indrex: true
      self_public_egress: false
    public_egress:
      mode: deny
    cache:
      allowed_origin_paths:
        - SELF_PUBLIC_EGRESS                 # → PolicyError "cache would replay"
```

```yaml
# ❌ unknown route name in route_order
search_policies:
  typo:
    route_order: [LOCAL_INDREX, MOON_RELAY]  # → PolicyError "unknown route"
```

```yaml
# ❌ route in order but disallowed
search_policies:
  inconsistent:
    route_order: [LOCAL_INDREX, LAN_FRIEND_DCNET]
    allow:
      local_indrex: true
      lan_friend_dcnet: false                # → PolicyError "in order but allow=false"
```

```yaml
# ❌ cache.allowed_origin_paths includes LOCAL_CACHE
search_policies:
  recursive_cache:
    cache:
      allowed_origin_paths:
        - LOCAL_CACHE                        # → PolicyError "cannot include LOCAL_CACHE"
```

---

## Loading custom policies

```python
import yaml
from swf.search import SearchPolicy, BUILT_IN_POLICIES, web_search

# Parse a YAML doc with multiple policies under `search_policies:`.
with open("/etc/swf/policies.yaml") as f:
    custom = SearchPolicy.parse_all(yaml.safe_load(f))

# Merge with built-ins (custom names override built-ins).
all_policies = {**BUILT_IN_POLICIES, **custom}

# Pass into the router.
resp = web_search("differential privacy",
                  policy_name="conference",
                  policies=all_policies)
```

The router resolves the `policy_name` against the dict you pass; if
omitted it uses `BUILT_IN_POLICIES` directly.

---

## Choosing a `routing_goal`

`routing_goal` is a hint that biases tiebreakers and (in later phases)
sufficiency thresholds. The four legal values:

| value | meaning |
|---|---|
| `balanced` | Default. §14 thresholds applied as-is. |
| `privacy_first` | Prefer the most-private acceptable route over a "better" but more-public one. Sufficiency stays loose for private routes. |
| `latency_first` | First acceptable result wins. Loosens sufficiency thresholds across all routes. |
| `dev` | Looser everything; for local development. Used only by `dev_*` policies. |

In Phase 1 these only affect how the router *labels* the response (the
`policy.routing_goal` field). Phase 2+ wires real behavior into
sufficiency overrides.

---

## What to put in version control

Don't commit `policies.yaml` with embedded secrets. The only secrets
the search router cares about are:

- `~/.config/swf/cache_secret.bin` — auto-generated, never edit
- `SWF_QUERY_HMAC_SECRET` — env, optional

Policies themselves are plain config; commit them. A team that runs a
shared SWF deployment should have a single `policies.yaml` checked
into the ops repo, with at least:

- `default` — overrides the built-in if your team wants different
   thresholds
- one named per deployment context (`conference`, `office_internal`,
   …)

Switching between them is a single CLI argument; rotating between
them mid-session is by changing the request body's `policy` field.
