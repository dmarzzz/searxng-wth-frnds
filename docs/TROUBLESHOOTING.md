# Troubleshooting

Symptom → likely cause → command. Distilled from real debug
sessions; the underlying machinery for each is in
`docs/SPEC_v0.3.md` + `docs/THREAT_MODEL.md`.

If something here doesn't match your situation, run `swf-node doctor`
first — it covers ~80% of the symptoms below in one command.

## "no peers discovered"

**Likely cause:** mDNS isn't crossing your network boundary.

```bash
swf-peer discover                      # print every DiscoveredPeer
dns-sd -B _indrex._tcp local.          # macOS: confirm the service is on the LAN
avahi-browse -rt _indrex._tcp          # linux: same
```

If `swf-peer discover` returns peers but they have `pubkey: None`,
they're running pre-PR-#59 firmware that didn't put pubkey in the
TXT record. Update them.

If `dns-sd`/`avahi-browse` returns nothing, mDNS isn't being routed:

- **Guest Wi-Fi** typically has client isolation enabled. There's no
  fix from inside swf-node; switch to a real network or use Tailscale.
- **VLAN boundary.** mDNS doesn't traverse VLANs without a reflector
  (`avahi-daemon` with `enable-reflector=yes`, or `mdns-repeater`).
- **AP with client isolation.** Same fix.
- **Linux without avahi**: not actually a problem — `python-zeroconf`
  is a self-contained mDNS responder. swf↔swf works without avahi.
  But `avahi-browse` (and other non-swf clients) won't see the
  service unless avahi is running.

**Workaround:** hand-pin via `swf-peer add <name> http://<host>:7777`.

## "peers discovered but no traffic"

**Likely cause:** bundles are empty.

```bash
curl http://<peer-ip>:7777/index/pages?since=0&limit=5 | jq
# look at .pages — if [] then bundles are empty
sqlite3 ~/world_knowledge/index.db "SELECT count(*) FROM pages_meta WHERE share_scope IN ('friends','public')"
```

Pre-v0.8 nodes had a bug where `pages_meta` was never populated by
the user-fetched ingest path (PR #66 fix). On those nodes, the
`/index/pages` filter `WHERE share_scope IN ('friends','public')`
returns zero rows because every row is implicit-private.

**Fix:** upgrade the peer to v0.8+ and either index new pages (which
will get `pages_meta` rows) or run a one-shot backfill SQL:

```sql
INSERT OR IGNORE INTO pages_meta(url, share_scope, source_type, content_hash, fetched_at_ms, updated_at)
SELECT p.url, 'friends', 'user_fetched', c.content_cid, NULL,
       strftime('%Y-%m-%dT%H:%M:%SZ','now')
FROM pages p
LEFT JOIN page_cids c ON c.url = p.url;
```

The same logic applies in reverse: if *your* node's bundles are
empty, your `pages_meta` is empty. Same fix.

## "search returns nothing"

**Likely cause:** the indrex DB is missing or its schema is stale.

```bash
swf-node migrate                       # apply additive migrations
swf-node --check                       # verify schemas
sqlite3 ~/world_knowledge/index.db .schema
```

If `pages_meta` is missing entirely, you're on a very old build. PR
#43 introduced it; PR #58 bootstraps it on first ingest. Upgrade.

## "/.well-known/indrex 404"

**Cause:** the route is on the peer-protocol surface; only HEAD/GET
are accepted.

```bash
curl -i http://<peer>:7777/.well-known/indrex      # GET, expects 200
```

If the peer is on `--bind 127.0.0.1`, you can't reach them from
another host. Have them rebind:

```bash
SWF_BIND=0.0.0.0 swf-node
```

Check firewall: TCP 7777 must be open inbound on the peer.

## "peers say I'm running the wrong version"

**Cause:** mDNS TXT records are cached aggressively.

```bash
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder    # macOS
sudo systemctl restart avahi-daemon                              # linux
```

If `swf-peer discover` shows you advertising the old version after a
swf-node restart, the OS-level cache is stale. The flush above
forces re-resolution.

## "ConnectionResetError flood from 127.0.0.1"

**Cause:** something local is opening sockets to swf-node and
RST-ing them. Not swf-node's fault, but it'll fill the log.

```bash
lsof -nP -iTCP:7777 -sTCP:LISTEN
sudo lsof -i :7777                     # who else is talking
```

Common culprits: a stale dev-tool poller, a broken health-check
loop, a misbehaving browser extension. Find and kill the offender.
swf-node's FD count (visible in `/metrics/snapshot
process.num_fds`) will drop back to ~10 once the source stops.

## "high FD count / leaking file descriptors"

**Cause:** usually correlated with the RST flood above. Each
half-handshake leaves an FD until the OS closes it.

```bash
curl -sS http://127.0.0.1:7777/metrics/snapshot | jq .values
# look at process.num_fds — should be < 100 in steady state
```

If FDs keep climbing without RST flooding, that's a real leak. Open
an issue with `lsof -p <pid> | wc -l` output and the daemon log.

## "init / daemon won't start: identity exists but mode is wrong"

```bash
chmod 600 ~/.config/swf/identity.key
```

The daemon refuses to use a key with permissive mode. Other users on
the box could otherwise read it.

## "swf-node doctor says SearXNG unreachable"

```bash
echo $SEARXNG_URL                      # confirm it's set
curl -v $SEARXNG_URL/healthz           # confirm it answers
docker compose -f docker-compose.searxng-test.yml ps    # confirm it's running
```

If you don't *want* SearXNG, unset `SEARXNG_URL`. The router walks
LOCAL_CACHE → LOCAL_INDREX → LAN_FRIEND_DCNET (if enabled) and
returns NO_RESULT instead of trying public egress.

## "tests/p2p_review/test_vacuum_events_keeps_recent fails on the full suite"

Pre-existing test pollution. Pass when run in isolation. Track:
GitHub issue (if reported), PR #67's commit message, the test
auto-uses the global `events` table whose state bleeds across
tests in the same process. Mark `slow` in a future cleanup or
introduce a fixture-level vacuum reset.

```bash
pytest tests/test_p2p_review.py::test_vacuum_events_keeps_recent -q   # passes in isolation
```

## "peer keeps getting pruned from my peers table"

PR #62 added geth/reth-style peer scoring. Peers that consecutively
fail liveness checks (`GET /health` non-200 or no response within
`LIVENESS_TIMEOUT_S`) get scored down and pruned.

```bash
curl -sS http://127.0.0.1:7777/metrics/snapshot | jq '.values | with_entries(select(.key | startswith("peers")))'
sqlite3 ~/world_knowledge/index.db "SELECT pubkey, nickname, consecutive_failures, next_attempt_at FROM peers"
```

Common causes:
- Peer is offline but mDNS hasn't withdrawn the record yet.
- Peer's IP changed (laptop went to sleep, IP renewed). PR #61's
  network-change watchdog handles this on the producer side; if
  it's still happening, file an issue.
- Peer is behind a firewall that drops TCP after idle.

## "I want to start fresh"

```bash
bash scripts/reset-state.sh
```

Prompts before each removal. Removes identity, search caches,
reputation, tickets, and the entire `world_knowledge/` archive.
After this, `swf-node init` to bootstrap fresh.
