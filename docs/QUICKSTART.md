# Convent-box quickstart

Zero to a running swf-node + hivemind sink on a Pi or laptop. For
laptop-peer mode (no hivemind), the README's first run is shorter —
this doc is the convent-box recipe.

## Prereqs

- Linux or macOS, Python 3.10+ (`python3 --version`).
- LAN reachability: TCP 7777 inbound, UDP 5353 (mDNS) in/out on the
  same broadcast domain as your other peers.
- Optional: Docker (Linux only — Docker Desktop on macOS won't pass
  multicast). `pyrage` for reservoir keygen (`pip install pyrage`).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/dmarzzz/searxng-wth-frnds/main/scripts/install.sh \
    | SWF_NODE_REF=v0.8.0 bash
```

This `pipx install`s `swf-node` from git. Manual equivalent:
`pipx install "git+https://github.com/dmarzzz/searxng-wth-frnds.git@v0.8.0"`.

Docker alternative (Linux server, host networking required for mDNS):

```bash
docker run --network host \
    -v "$HOME/.config/swf:/home/swf/.config/swf" \
    -v "$HOME/world_knowledge:/home/swf/world_knowledge" \
    ghcr.io/dmarzzz/swf-node:v0.8.0
```

## First run

```bash
swf-node init                 # generate identity + config skeleton
swf-node --check              # read-only self-test
```

Expected `--check` output (one line per check, exits 0 on all-pass):

```
[ok] identity: pubkey=… fp=…
[ok] world_knowledge.db: schema_version=…
[skip] alchemists.yml: no .alchemists.yml configured (checked 1 location(s))
[skip] reservoir.yml: no .reservoir.yml configured (checked 1 location(s))
[skip] convent_signing_key: SWF_CONVENT_SIGNING_KEY unset
…
```

The three `[skip]`s above are expected on a fresh laptop — they go
`[ok]` once you finish the convent-box steps below. Then:

```bash
swf-node --full               # foreground; Ctrl-C to stop
```

`--full` boots the daemon with metrics + community subsystems on
:7777. Bind, port, and mDNS controls are env vars (`SWF_BIND`,
`SWF_PORT`, `SWF_NO_MDNS`) — see [`docs/CONFIG.md`](CONFIG.md).

## Configure as a convent box

A convent box is a swf-node that runs `--hivemind-sink` — it
advertises `_sr-hivemind._tcp.local.` so voxterm clients on the LAN
discover it, signs incoming `transcript.batch` payloads with its
alchemist key, and is listed as an alchemist in the cohort's roster.

### 1. Alchemist Ed25519 keypair

```bash
mkdir -p ~/.config/swf
python3 - <<'PY'
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

priv = Ed25519PrivateKey.generate()
seed = priv.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
pub  = priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()

out = Path.home() / ".config/swf/convent-signing.key"
out.write_bytes(seed)
out.chmod(0o600)
print(f"pubkey: ed25519:{pub}")
PY
```

Copy the printed `pubkey: ed25519:…` line — it goes in
`.alchemists.yml` below. The 32-byte seed lands at
`~/.config/swf/convent-signing.key` with mode 0600.

### 2. `.alchemists.yml`

The signing-list YAML for cohort + transcript bundle authors. Every
peer's `convent-signing.key` pubkey MUST appear here or signed
bundles get rejected as `author_not_alchemist`.

```yaml
# ~/.config/swf/.alchemists.yml
schema_version: 1
alchemists:
  - id: convent-local
    pubkey: ed25519:<paste the pubkey from step 1>
  # add more peers here as they join the cohort
  # - id: alchemist-02
  #   pubkey: ed25519:…
```

### 3. Reservoir (X25519 / age recipient)

The `.reservoir.yml` lists age recipients used to encrypt
`cohort.depth` + `transcript.batch` payloads.

```bash
python3 -c "
from pyrage import x25519
ident = x25519.Identity.generate()
print('# private (keep secret):', str(ident))
print('pubkey:', ident.to_public())
"
```

Save the private string somewhere safe (it's the age decryption key).
Put the `age1…` pubkey in:

```yaml
# ~/.config/swf/.reservoir.yml
schema_version: 1
generated_at: '2026-05-04T00:00:00Z'
keys:
  - id: convent-local
    pubkey: age1<paste the pubkey here>
    distributed_to: null
```

### 4. Wire env + run

```bash
export SWF_ALCHEMISTS_FILE=~/.config/swf/.alchemists.yml
export SWF_RESERVOIR_FILE=~/.config/swf/.reservoir.yml
export SWF_CONVENT_SIGNING_KEY=~/.config/swf/convent-signing.key

swf-node --check                                   # all should now be [ok]
swf-node --full --hivemind-sink --bind 0.0.0.0
```

### 5. Verify on the LAN

```bash
dns-sd -B _sr-hivemind._tcp.                       # macOS — should list this host
avahi-browse -rt _sr-hivemind._tcp                 # linux — same
curl -s http://<host>:7777/alchemists | jq         # roster from disk
```

`/alchemists` is the source of truth for what `POST /bundles` will
accept; if your convent pubkey isn't here, edit the YAML (hot-reload
picks it up; #116) or fix the `SWF_ALCHEMISTS_FILE` path.

## Sanity check: round-trip a signed bundle

Post a `cohort.surface` envelope signed by your alchemist key, then
read it back.

```bash
python3 - <<'PY' > /tmp/env.json
import base64, json
from pathlib import Path
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from swf.bundles import sign_envelope

seed = (Path.home() / ".config/swf/convent-signing.key").read_bytes()
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub  = priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()

env = {
  "magic": "swf-bundle-v1",
  "kind": "cohort.surface",
  "record_id": "convent-local",
  "version": 0,
  "author": {"pubkey": f"ed25519:{pub}", "signed_at": "2026-05-04T00:00:00Z"},
  "encryption": None,
  "payload": base64.b64encode(b'{"hello":"world"}').decode(),
}
env["signature"] = sign_envelope(env, priv=priv)
print(json.dumps(env))
PY

curl -sX POST http://127.0.0.1:7777/bundles \
    -H 'Content-Type: application/json' --data @/tmp/env.json | jq
curl -s 'http://127.0.0.1:7777/bundles?kind=cohort.surface' | jq '.bundles[0]'
```

(`swf.bundles` is on the python path of the same `pipx`/venv that
runs the daemon; from a different shell, `pipx runpip swf-node`'d
interpreter or `python -m swf` env works.)

A 200 + `{"valid":[…]}` on POST and a non-empty `bundles[]` on GET
means the verifier accepted your signature and the cohort store
persisted it.

## Operations

- **Logs.** swf-node writes `[peer-server] …` lines to stderr.
  Redirect with `swf-node --full --hivemind-sink --bind 0.0.0.0 2>&1 | tee /var/log/swf-node.log`,
  or use the systemd unit at [`examples/systemd/swf-node.service`](../examples/systemd/swf-node.service)
  + `journalctl --user -u swf-node -f`.
- **Health gauges.** `curl -s http://127.0.0.1:7777/metrics/snapshot | jq .values`
  — `peers.count_active`, `process.num_fds`, `bundles.*` are the ones
  that matter.
- **Backup.** Everything is plain SQLite + markdown:
  `cp ~/world_knowledge/index.db /backup/index.db.$(date +%F)`,
  plus `tar czf swf-state.tar.gz ~/.config/swf ~/.local/share/swf ~/world_knowledge`.
  See [`docs/OPERATING.md`](OPERATING.md#state-backup--restore).
- **Rotating an alchemist key.** Edit `.alchemists.yml`; the loader
  hot-reloads on mtime change (#116) — no restart, no `SIGHUP`. The
  `[bundles] alchemists.yml reloaded …` stderr line confirms it.
- **Adding a peer manually.** Drop into `~/.config/swf/peers.yaml`:
  ```yaml
  peers:
    - name: bob-convent
      url: http://bob.local:7777
      pubkey: null    # TOFU-pinned on first contact
  ```
  Or use `swf-peer add bob-convent http://bob.local:7777`.

## Common gotchas

- `403 author_not_alchemist` on POST /bundles → `curl /alchemists`,
  confirm the signing pubkey is listed; otherwise edit the YAML (no
  restart).
- mDNS not surfacing in `dns-sd` / `avahi-browse` → check
  `--bind 0.0.0.0` (loopback bind disables mDNS); check the LAN
  isn't isolating Wi-Fi clients (5GHz vs 2.4GHz, guest network, AP
  client isolation).
- `swf-node --check` shows `[skip]` for alchemists / reservoir /
  convent_signing_key → set `SWF_ALCHEMISTS_FILE`, `SWF_RESERVOIR_FILE`,
  `SWF_CONVENT_SIGNING_KEY` and re-run.
- `[fail] alchemists.yml: schema_version must be int 1` → first line
  of the YAML must be `schema_version: 1` (an int, not a string).
- mDNS service shows up but bundles never propagate → check the peer
  is on the same LAN broadcast domain (mDNS doesn't cross VLANs).

## Where to get help

- Symptom → cause map: [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
- Full env-var reference: [`docs/CONFIG.md`](CONFIG.md).
- Wire-protocol surface: [`docs/SPEC_v0.3.md`](SPEC_v0.3.md). Bundle
  envelopes / cohort + transcript flow are in `SHAPE-ROTATOR-OS-SPEC.md`
  §3.6–§4.3 (see the cross-references in [`docs/CONFIG.md`](CONFIG.md)).
- File an issue: <https://github.com/dmarzzz/searxng-wth-frnds/issues>.
