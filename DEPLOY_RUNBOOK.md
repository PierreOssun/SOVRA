# Deploy runbook — one shard on the Raspberry Pi, demo over the internet

Step-by-step procedure to deploy the 2-of-3 fleet across machines — cosigner 1
on a Raspberry Pi — run the first DKG with the Pi as a live party, and demo
prepare → sign → broadcast on Sepolia with the MPC rounds crossing the
internet. Companion to `RUN.md` (which covers the all-local `cargo xtask up`
dev flow this runbook deliberately does **not** use). For a zero-ceremony
single-machine taste first: `sovra init demo && sovra up` (see the README).

Everything runs from Docker images (`ghcr.io/pierreossun/sovra-*`) driven by
the `sovra` launcher — no Rust toolchain, no binary copying, no glibc
matching on any host.

**No shard migration happens anywhere in this runbook.** The DKG in §6
creates each party's shard *on its own host* — born there, never travels.
The same is true of every private key: TLS keys are born on their host via
CSR enrollment (§2), identity keys at first boot.

## 1. Topology and prerequisites

| Host | Role (`sovra init <role>`) | Runs | Reachability needed |
|---|---|---|---|
| your Mac | `mac` | `sovra-api` (:3000 loopback + relay hub :3100) and cosigner 2 — the **sleeping shard**, woken for ceremonies (`sovra wake`) | cosigners dial `wss://<MAC_TS_IP>:3100/env` |
| always-on box ("cloud") | `cloud` | cosigner 0 — one sealed shard, nothing else | orchestrator dials `https://<CLOUD_TS_IP>:4100` |
| Raspberry Pi | `pi` | cosigner 1 | orchestrator dials `https://<PI_TS_IP>:4101` |

The orchestrator lives on YOUR machine on purpose: it holds no shard, and
signing happens exactly when you are at the keyboard — the rented box holds
nothing but one encrypted shard. Two-machine variant: the cloud role can run
on the Mac too (a second directory) for a Mac + Pi setup.

Reachability is **bidirectional** (control plane in, relay plane out), and
the machines sit behind NAT — so all join a **Tailscale** tailnet. mTLS
stays on as defense in depth; Tailscale only provides the routable path.

Per host, exactly three prerequisites:

- **Docker** (Engine on Linux, Docker Desktop on the Mac).
- **Tailscale**: install, `tailscale up`, then `tailscale ip -4` → note each
  host's `100.x` IP. Verify pings in both directions. Use the IPs everywhere
  below (`.env` **and** cert SANs), not MagicDNS names — IPs are stable per
  node and keep DNS out of the trust path.
- **The launcher**:

  ```bash
  curl -fsSL https://raw.githubusercontent.com/PierreOssun/SOVRA/main/deploy/install.sh | sh
  ```

Then on every host, in a fresh directory:

```bash
sovra init <cloud|pi|mac>     # fetches <role>.yml + a .env template
vi .env                       # fill in the tailscale IPs (and RPC URL on the mac)
```

## 2. Certificates (CSR enrollment — private keys never travel)

Why per-host SANs: hostname verification runs against the *dialed* name, so
each serving leaf must carry its host's tailscale IP. Why CSR enrollment:
each host generates its own keypair locally and sends only the CSR (public);
the CA machine signs and returns only the certificate (public). The CA key
lives on **one** machine — use the Mac — and never leaves it.

On the Mac (once):

```bash
sovra certs new                          # mints certs/ca.{cert,key}.pem
```

On every host (generates the keypair + CSR for that host's role — the mac
role produces two, orchestrator + cosigner2):

```bash
sovra certs csr                          # uses MY_TS_IP from .env as the SAN
```

Move each `*.csr.pem` to the Mac (any channel — CSRs are public), review and
sign, send each `*.cert.pem` back (also public), alongside `ca.cert.pem`:

```bash
sovra certs sign cosigner1.csr.pem
# → prints "signing request: CN sovra-cosigner1, SANs [127.0.0.1, localhost, 100.x.y.z]"
#   — eyeball the CN and SAN before it signs.
```

Each host ends with `certs/` holding `ca.cert.pem` + its own
`<stem>.cert.pem` + `<stem>.key.pem` (the key never moved). `sovra check`
names anything missing.

Shard sealing is ON by default: `sovra init` seeded `certs/sealN.key`, and
every shard is XChaCha20-Poly1305 sealed at rest from the first DKG (it must
exist before then — sealing can't be added to an existing plaintext shard
without a refresh ceremony; `sovra check` verifies it). Keep the seal key
out of the same backup as `data/`, or the seal adds nothing.

## 3. Bring the fleet up (bootstrap mode)

On every host:

```bash
sovra up
# → pulls the image, starts the role's containers
# → prints: this party's identity key (slot N of SOVRA_PARTICIPANTS)
```

First boot is **bootstrap mode** (no roster yet): the cosigner serves
`GET /identity` and 409s everything else. That is correct at this stage. The
Mac's `sovra-api` container will restart-loop until the whole fleet is up —
also correct; it goes quiet once §5 completes.

Policies: `sovra init` seeded `config/policyN.toml` for this party —
**review and edit it** (allowed recipients, value cap); the grammar is
fail-closed and the cosigner refuses to boot without it (see `RUN.md`).

## 4. Configuration is `.env` — there is nothing else

The old file-editing steps are gone: the role ymls translate `.env` into the
processes' `SOVRA_*` variables, and the orchestrator's cosigner list is
derived from the three tailscale IPs (preference order, sleeping shard
last). `sovra check` on any host validates what's filled in so far, with a
named remedy per gap:

```bash
sovra check
#   ✓ docker
#   ✓ leaf cosigner1
#   ✗ SOVRA_PARTICIPANTS empty (bootstrap only — run 'sovra roster' on the mac, paste here)
#   ✓ relay hub reachable (mTLS)
```

**Do not use `cargo xtask up` against this fleet** — it is the all-local dev
flow and would spawn colliding local cosigners with stale identities.

## 5. Roster ceremony (verifying-key exchange)

With all three parties up in bootstrap mode, on the Mac:

```bash
sovra roster
# fetches GET /identity from all three parties over mTLS and prints:
# SOVRA_PARTICIPANTS=<vk0>,<vk1>,<vk2>
```

Paste that **byte-identical** line into `.env` on **every** host — this is
the trust-pinning step, deliberately a human act — then on every host:

```bash
sovra start
# = sovra check (now the roster must parse: 3 keys, 64-hex each)
# + restart with the roster + wait for health
```

A swapped slot fails loudly at the cosigner's boot self-check; `sovra start`
surfaces that named error from the logs instead of hanging.

## 6. DKG ceremony

DKG needs **all three** parties online (`sovra wake` on the Mac if the
sleeping shard is down). On the Mac:

```bash
sovra check      # every party must show "reachable (mTLS)"
sovra dkg
# → { "public_key": "0x02…", "addresses": { "ethereum": "0x…" } }
```

Timing is safe over Tailscale: the MPC ttl is 60 s and the orchestrator's
HTTP timeout 90 s, against tens of milliseconds of added RTT. A `409` means
a shard already exists — to redo: `sovra down && rm -rf data/store` on every
party, then re-run.

Verify the shard was born on the Pi (`data/` is a plain host directory —
your user owns it):

```bash
sovra logs cosigner1                # DKLs23 rounds ran here
ls -la data/store/default/          # (Pi) shard.bin + metadata.json,
                                    #  shard sealed (SVR1 prefix)
curl -s http://127.0.0.1:3000/v1/dkg   # (Mac) same address as the ceremony
```

Then put the sleeping shard back to sleep: `sovra sleep` on the Mac —
**after taking its offline backup** (the `data/` directory: shard +
identity.key — this is the scheme's seedphrase-equivalent; re-take it after
every ceremony, and keep `certs/seal2.key` in a separate location).

## 7. Demo

**Fund first.** Send ~0.05 Sepolia ETH from a faucet to the DKG address and
confirm on sepolia.etherscan.io. Unfunded, a non-zero `--value` fails at
`prepare` with `502 rpc enrichment failed` (the node refuses to estimate gas
for a spend the address can't cover).

The API is loopback-only on the Mac — your machine — so run the CLI right
there: release binary, or the image:

```bash
alias sovra-cli='docker run --rm --network host ghcr.io/pierreossun/sovra-cli:latest'
```

**Happy path** — the shipped policies allow only the burn address, ≤ 1 ETH,
chain 11155111:

```bash
sovra-cli prepare --to 0x000000000000000000000000000000000000dEaD --value 100000000000000 \
  | jq -r .unsigned_transaction \
  | xargs -I{} sovra-cli sign --tx {} \
  | jq -r .signed_transaction \
  | xargs -I{} sovra-cli broadcast --tx {}
```

Worth showing side by side:
- the Pi's `sovra logs -f cosigner1` participating in the DKLs23 rounds;
- the orchestrator log (`sovra logs -f api` on the Mac) selecting
  `participants=[0, 1]`;
- the `tx_hash` landing on sepolia.etherscan.io.

`200 confirmed` and `202 pending` are both success — the receipt window is
30 s; a pending tx just hadn't mined yet.

**Policy deny** — every cosigner vetoes calldata under the shipped policy,
and the veto is attributed per party:

```bash
sovra-cli prepare --to 0x000000000000000000000000000000000000dEaD --value 0 --data 0xdeadbeef \
  | jq -r .unsigned_transaction \
  | xargs -I{} sovra-cli sign --tx {}
# → 403 { "error": "policy denied", "vetoes": [ { "party": 0, ... }, { "party": 1, ... } ] }
```

**Failover (optional)** — kill the Pi mid-demo:

```bash
# Pi:  sovra down
# Mac: sovra wake           # wake the sleeping shard
#      sign again → orchestrator selects participants=[0, 2]
# Pi:  sovra up             # afterwards; Mac: sovra sleep
```

A *lost* Pi shard is not healed in place: keep signing on {0, 2}, then
migrate — `sovra down && rm -rf data/store` on every party, fresh DKG, move
funds (see `RUN.md`, "Recovery runbook").

## 8. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `sovra check` fails | Read the ✗ lines — each names its remedy |
| TLS hostname/`NotValidForName` errors | Dialed IP missing from the peer leaf's SANs → `MY_TS_IP` wrong in `.env` at csr time → re-enroll that leaf (§2; delete the stale `.csr/.key` pair first) |
| api container restart-loops | A configured cosigner unreachable — expected until the whole fleet is up; if it persists, `sovra check` on the Mac names the dead party |
| `dkg`/`sign` return 409 "roster" | `SOVRA_PARTICIPANTS` missing or differing on some host → §5, byte-identical everywhere, `sovra start` |
| Cosigner unhealthy after `sovra start` | Own key not at index `party_id` in the roster — `sovra start` prints the boot self-check error from the logs |
| `prepare` → `502 rpc enrichment failed` | Unfunded signer (non-zero value), or flaky public RPC → fund the address; set a dedicated `SOVRA_RPC_URL` in cloud's `.env` |
| `broadcast` → `202 pending` | Not an error — check the tx hash on Etherscan |
| Host reboot, nothing signs | `restart: unless-stopped` brings the containers back; `sovra check` on the Mac to confirm the fleet, then sign |

Known-tight timings (fine over Tailscale, watch on slow links): MPC ttl 60 s,
orchestrator HTTP timeout 90 s, broadcast receipt window 30 s (hard-coded).
