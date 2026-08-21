# Deploy runbook — one shard on the Raspberry Pi, demo over the internet

> **Backend migration note (2026-08):** the MPC backend moved from sl-dkls23
> to 0xCarbon DKLs23. Any host deployed before that must wipe its shard store
> and take part in a fresh DKG (identity.key, roster, certs and config carry
> over; set `relay_url` to end in `/env`). Funds move to the new address.

Step-by-step procedure to move cosigner 1 onto a Raspberry Pi, run the first
2-of-3 DKG with the Pi as a live party, and demo prepare → sign → broadcast on
Sepolia with the MPC rounds crossing the internet. Companion to `RUN.md`
(which covers the all-local `cargo xtask up` flow this runbook deliberately
does **not** use).

**No shard migration happens anywhere in this runbook.** The 2-of-3 DKG has
never been run, so the ceremony in §6 creates the Pi's shard *on the Pi* —
it is born there and never travels.

## 1. Topology and prerequisites

| Host | Runs | Reachability needed |
|---|---|---|
| Raspberry Pi 4/5 (4 GB+) | `sovra-cosigner` party 1 | orchestrator dials `https://<PI_TS_IP>:4101` |
| MacBook | `sovra-api` (orchestrator, :3000 + relay hub :3100), cosigner 0, cosigner 2 (cold party, stopped after DKG) | Pi dials `wss://<MAC_TS_IP>:3100/ws` |

Reachability is **bidirectional** (control plane in, relay plane out), and both
machines sit behind NAT — so both join a **Tailscale** tailnet. mTLS stays on
as defense in depth; Tailscale only provides the routable path.

- **Pi OS: Ubuntu Server 24.04 LTS (64-bit / arm64)**, flashed with Raspberry
  Pi Imager, SSH enabled. This is not a style choice: the CI binary links the
  build runner's glibc 2.39, and Raspberry Pi OS Bookworm ships 2.36 (symptom:
  `GLIBC_2.39 not found` at startup). If you must run Bookworm, change
  `runs-on` in `.github/workflows/build_arm.yml` to `ubuntu-22.04-arm` and
  rebuild.
- **Tailscale** on both machines:
  - Mac: `brew install tailscale` (or the app), log in, then `tailscale ip -4`
    → note as `MAC_TS_IP`.
  - Pi: `curl -fsSL https://tailscale.com/install.sh | sh && sudo tailscale up`,
    then `tailscale ip -4` → note as `PI_TS_IP`.
  - Verify both directions: `ping <PI_TS_IP>` from the Mac, `ping <MAC_TS_IP>`
    from the Pi.
  - Use the `100.x` IPs everywhere below (configs **and** cert SANs), not
    MagicDNS names — IPs are stable per node and keep DNS out of the trust path.
- **The aarch64 binary**: push to `main`/`fix-ci` (or trigger manually) and the
  `Build ARM Cosigner` workflow produces it. Fetch on the Mac:

  ```bash
  gh run download --name sovra-cosigner-aarch64 --dir /tmp/pi-artifact
  ```

## 2. Certificates (on the Mac, from the workspace root)

Why regeneration is needed: the existing `orchestrator.*` and `cosigner1.*`
leaves carry loopback-only SANs (`127.0.0.1`, `localhost`), and hostname
verification runs against the *dialed* name — the Pi dialing
`wss://<MAC_TS_IP>:3100` and the orchestrator dialing `https://<PI_TS_IP>:4101`
would both fail. Only these two leaves are hostname-checked (client certs are
chain-verified only), so only these two need re-issuing. `ensure_leaf` never
overwrites existing material, hence the explicit `rm` first. The same run also
mints the missing `cosigner2.*` leaf.

```bash
rm certs/orchestrator.cert.pem certs/orchestrator.key.pem \
   certs/cosigner1.cert.pem certs/cosigner1.key.pem
cargo xtask certs --san <MAC_TS_IP> --san <PI_TS_IP>
```

Do **not** delete `ca.cert.pem` / `ca.key.pem` / `cosigner0.*` — surviving
leaves must keep chaining to the same CA.

Ship to the Pi (leaf pair + CA **cert** only; `ca.key.pem` never leaves the
Mac):

```bash
scp certs/cosigner1.cert.pem certs/cosigner1.key.pem certs/ca.cert.pem \
    <user>@<PI_TS_IP>:/tmp/
```

## 3. Pi provisioning

Target layout — `WorkingDirectory=/opt/sovra` anchors every relative path in
the config:

```
/opt/sovra/
├── sovra-cosigner            # CI artifact
├── config/
│   ├── cosigner1.toml        # from deploy/cosigner1.pi.toml
│   └── policy1.toml          # copied verbatim from repo config/policy1.toml
├── certs/
│   ├── ca.cert.pem
│   ├── cosigner1.cert.pem
│   ├── cosigner1.key.pem
│   └── seal1.key             # generated on the Pi, never leaves it
└── data/                     # created by the binary (0700)
```

On the Pi:

```bash
sudo useradd -r -s /usr/sbin/nologin sovra
sudo mkdir -p /opt/sovra/{config,certs,data}
sudo mv /tmp/cosigner1.cert.pem /tmp/cosigner1.key.pem /tmp/ca.cert.pem /opt/sovra/certs/
# shard sealing key — must exist BEFORE the first DKG (enabling sealing on an
# existing shard requires a key-refresh ceremony)
openssl rand -hex 32 | sudo tee /opt/sovra/certs/seal1.key >/dev/null
```

Copy over the binary and the config templates (from the Mac):

```bash
scp /tmp/pi-artifact/sovra-cosigner <user>@<PI_TS_IP>:/tmp/
scp deploy/cosigner1.pi.toml deploy/sovra-cosigner.service config/policy1.toml \
    <user>@<PI_TS_IP>:/tmp/
```

Back on the Pi — install, fill in `<MAC_TS_IP>`, lock down modes:

```bash
sudo mv /tmp/sovra-cosigner /opt/sovra/ && sudo chmod +x /opt/sovra/sovra-cosigner
sudo mv /tmp/cosigner1.pi.toml /opt/sovra/config/cosigner1.toml
sudo mv /tmp/policy1.toml /opt/sovra/config/
sudo sed -i 's/<MAC_TS_IP>/100.x.y.z/' /opt/sovra/config/cosigner1.toml   # real Mac IP
sudo chown -R sovra:sovra /opt/sovra
sudo chmod 600 /opt/sovra/certs/cosigner1.key.pem /opt/sovra/certs/seal1.key
sudo mv /tmp/sovra-cosigner.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now sovra-cosigner
journalctl -u sovra-cosigner -f
```

Expected first boot (bootstrap mode — `participants` is still commented out):
the log prints `verifying_key=<64 hex>` and warns that the roster is not
configured (dkg/sign will 409). That is correct at this stage.

Optional hardening: `sudo ufw allow in on tailscale0 to any port 4101 proto tcp`
and deny 4101 on every other interface.

## 4. Mac-side configuration

Edit `config/sepolia.toml` — two changes, both file edits (the `[[cosigners]]`
table array has **no** env override; the `config` crate's env source cannot
express a table array):

```toml
relay_bind = "0.0.0.0:3100"          # was 127.0.0.1:3100 — the Pi dials in

[[cosigners]]
party_id = 1
url = "https://<PI_TS_IP>:4101"      # was https://127.0.0.1:4101
```

Everything else stays: `rpc_url`, `bind_addr` (:3000 stays loopback — the CLI
is local), threshold, the loopback URLs for cosigners 0 and 2, tls paths.

**Do not use `cargo xtask up`.** Two reasons, both fatal here: it builds the
participants roster from *local* `data/cosignerN/identity.key` files (for
party 1 that is a stale local identity, not the Pi's), and it launches
cosigner 1 in a local tmux pane that would collide with the Pi. Run the local
processes by hand instead (from the workspace root):

```bash
# Terminal 1
cargo run -p sovra-cosigner -- config/cosigner0.toml
# Terminal 2 — cold party, needed online for DKG only
cargo run -p sovra-cosigner -- config/cosigner2.toml
# Terminal 3 — sovra-api: ONLY at §6 step 4, never before
```

`config/cosigner0.toml` and `config/cosigner2.toml` need no networking edits —
they stay loopback. Optionally `rm -rf data/cosigner1` on the Mac: nothing
reads it once `xtask up` is out of the picture, and it removes a confusing
stale identity.

## 5. Roster ceremony (verifying-key exchange)

1. With all three cosigners up and **no** `participants` set anywhere, collect
   the three verifying keys from the boot logs: terminals 1 and 2 on the Mac,
   `journalctl -u sovra-cosigner` on the Pi. (A mTLS-gated `GET /identity`
   also exists on each :410x, but the logs are the easy path.)
2. Add the **byte-identical** line to all three configs —
   `config/cosigner0.toml` and `config/cosigner2.toml` on the Mac,
   `/opt/sovra/config/cosigner1.toml` on the Pi. Order = party id, own key
   included:

   ```toml
   participants = ["<vk0>", "<vk1>", "<vk2>"]
   ```

   A swapped slot fails loudly at boot with a self-check error, not a silent
   DKG stall.
3. Restart all three (Ctrl-C + rerun on the Mac,
   `sudo systemctl restart sovra-cosigner` on the Pi). The roster warning must
   be gone from all three logs.

## 6. DKG ceremony

DKG needs **all three** parties online simultaneously.

1. Probe the Pi from the Mac before anything else (the port is mTLS-only, so
   present the orchestrator's own leaf):

   ```bash
   curl -s --cacert certs/ca.cert.pem \
        --cert certs/orchestrator.cert.pem --key certs/orchestrator.key.pem \
        https://<PI_TS_IP>:4101/health
   ```

   A TLS hostname error here means the SANs are wrong — back to §2.
2. Check cosigners 0 and 2 the same way on `https://127.0.0.1:4100/health` and
   `:4102/health`.
3. **Only now** start the orchestrator — it hard-exits ~10 s after boot if any
   configured cosigner is unreachable, so it always starts last (same rule
   after any reboot):

   ```bash
   cargo run -p sovra-api
   ```

4. Run the ceremony:

   ```bash
   cargo run -p sovra-cli -- dkg
   # → { "public_key": "0x02…", "addresses": { "ethereum": "0x…" } }
   ```

   Timing is safe over Tailscale: the MPC ttl is 60 s and the orchestrator's
   HTTP timeout 90 s, against tens of milliseconds of added RTT. A `409` means
   a shard already exists — to redo, wipe `store/` under all three data dirs
   and restart.
5. Verify the shard was born on the Pi:

   ```bash
   ls -la /opt/sovra/data/cosigner1/store/       # shard.bin + metadata.json
   curl -s http://127.0.0.1:3000/v1/dkg          # (Mac) same address as step 4
   ```

   With `seal1.key` configured, `shard.bin` is XChaCha20-Poly1305 sealed at
   rest.
6. Stop cosigner 2 (Ctrl-C in terminal 2). It is the cold party; from here on
   every signature runs on the {Mac, Pi} pair — i.e. real MPC over the
   internet.

## 7. Demo

**Fund first.** Send ~0.05 Sepolia ETH from a faucet to the DKG address and
confirm on sepolia.etherscan.io. Unfunded, a non-zero `--value` fails at
`prepare` with `502 rpc enrichment failed` (the node refuses to estimate gas
for a spend the address can't cover).

**Happy path** — the shipped policies allow only the burn address, ≤ 1 ETH,
chain 11155111:

```bash
cargo run -p sovra-cli -- prepare --to 0x000000000000000000000000000000000000dEaD --value 100000000000000 \
  | jq -r .unsigned_transaction \
  | xargs -I{} cargo run -p sovra-cli -- sign --tx {} \
  | jq -r .signed_transaction \
  | xargs -I{} cargo run -p sovra-cli -- broadcast --tx {}
```

Worth showing side by side:
- the Pi's `journalctl -u sovra-cosigner -f` participating in the DKLs23
  rounds;
- the orchestrator log selecting `participants=[0, 1]`;
- the `tx_hash` landing on sepolia.etherscan.io.

`200 confirmed` and `202 pending` are both success — the receipt window is
30 s; a pending tx just hadn't mined yet.

**Policy deny** — every cosigner vetoes calldata under the shipped policy, and
the veto is attributed per party:

```bash
cargo run -p sovra-cli -- prepare --to 0x000000000000000000000000000000000000dEaD --value 0 --data 0xdeadbeef \
  | jq -r .unsigned_transaction \
  | xargs -I{} cargo run -p sovra-cli -- sign --tx {}
# → 403 { "error": "policy denied", "vetoes": [ { "party": 0, ... }, { "party": 1, ... } ] }
```

**Failover (optional)** — kill the Pi mid-demo:

```bash
# Pi:  sudo systemctl stop sovra-cosigner
# Mac: restart cosigner 2 (terminal 2), sign again
#      → orchestrator selects participants=[0, 2]
# Pi:  sudo systemctl start sovra-cosigner   # afterwards
```

## 8. Troubleshooting

| Symptom | Cause → fix |
|---|---|
| `GLIBC_2.39 not found` on the Pi | Pi OS older than the CI runner → run Ubuntu 24.04 arm64, or rebuild on `ubuntu-22.04-arm` |
| TLS hostname/`NotValidForName` errors | Dialed name missing from the peer leaf's SANs → §2; if you switch to MagicDNS names later, re-issue with DNS SANs |
| Orchestrator exits ~10 s after start | A configured cosigner was unreachable at boot → start all cosigners first, orchestrator last |
| `dkg`/`sign` return 409 "roster" | `participants` missing or differing on some party → §5, byte-identical everywhere |
| Cosigner fails at boot with self-check error | Own key not at index `party_id` in `participants` → fix the ordering |
| `prepare` → `502 rpc enrichment failed` | Unfunded signer (non-zero value), or flaky public RPC → fund the address; set `SOVRA_RPC_URL` to an Alchemy/Infura Sepolia endpoint before starting `sovra-api` |
| `broadcast` → `202 pending` | Not an error — check the tx hash on Etherscan |
| Pi reboot, nothing signs | Restart order: Pi cosigner up (auto via systemd) → verify `/health` → restart `sovra-api` on the Mac |

Known-tight timings (fine over Tailscale, watch on slow links): MPC ttl 60 s,
orchestrator HTTP timeout 90 s, broadcast receipt window 30 s (hard-coded).
