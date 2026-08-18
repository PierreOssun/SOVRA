How to run:

## One-command local system (tmux)

Spawn the whole system — orchestrator + all three cosigners, wired together —
in a single tmux window:

```bash
cargo xtask up
```

On the **first** run this seeds each cosigner's identity under `data/cosigner{0,1,2}/`
**and the TLS material under `certs/`** (project CA + one leaf per process), pins
the full participant roster (every party's verifying key, in id order) into every
cosigner, starts all four processes, and runs the one-time 2-of-3 DKG so the
signer address is ready. Later runs **load** the existing identities and certs
and detect that DKG has already happened. Layout: `cosigner0` / `cosigner1` /
`cosigner2` on top, the orchestrator full-width below. Tear it down with:

```bash
cargo xtask down
```

Local only. To run the processes individually, see the sections below.

### The cold recovery party (cosigner 2)

The scheme is **2-of-3**: cosigner 2 is the recovery shard (in production it
lives on a cloud host). It must be online for **DKG** (which always needs all
n parties) and for recovery ceremonies — during normal operation it should be
**stopped**. After `cargo xtask up` finishes the DKG, hit `Ctrl-C` in the
cosigner2 pane: signing keeps working through the preferred pair {0, 1}.

Failover demo: with cosigner2 running, `Ctrl-C` cosigner1 instead — signing
still succeeds, now via {0, 2} (the orchestrator log shows
`signing subset selected participants=[0, 2]`). The subset is chosen by
liveness *before* any request; a policy veto from a selected party is final
and never triggers failover to the cold party.

### Recovery runbook (lost shard → re-share ceremony)

When a party's host is lost (disk, theft, fire), the failover above is the
**bridge**: the survivor + cold party keep signing. Real recovery is the
re-share ceremony — it rebuilds the lost shard **at the same address** and
re-randomizes every other shard, so the lost/stolen one becomes useless.
Treat a lost shard as compromised: run the ceremony promptly.

1. **Rebuild the host.** Start the cosigner with an empty `data_dir`; it
   generates a fresh identity and logs its new verifying key (also served on
   `GET /identity`). It will 409 dkg/sign until step 2 — that's expected.
2. **Update the roster everywhere.** Put the new verifying key into
   `participants` (same slot) in *every* cosigner's config — or the
   `SOVRA_COSIGNER_PARTICIPANTS` env — and restart all cosigners, including
   the cold one (the ceremony, like DKG, needs **all n online**).
3. **Run the ceremony.** The orchestrator may be restarted at any point —
   startup tolerates the rebuilt party's empty store ("awaiting recovery").
   Then:

   ```bash
   curl -s -X POST http://127.0.0.1:3000/v1/recover \
     -H 'content-type: application/json' -d '{ "lost_party": 1 }'
   # → { "public_key": "0x02…", "addresses": { … } }   ← public_key MUST equal the existing one
   ```

4. **Verify and stand down.** Sign something (`sovra-cli sign`), confirm the
   address, then stop the cold party again. Old backups of any shard are now
   dead — the ceremony invalidated the entire previous generation.

Notes: the declared-lost party must have an **empty** store (a present shard
409s — delete it first: declaring the wrong party lost is refused, not
absorbed). To rotate shards without a loss event, wipe one party's store
deliberately and run the same ceremony; a rotation where every party keeps
its slot needs `quorum_change` tooling (future milestone).

### Shard sealing at rest (`seal_key_path`)

Optional per cosigner: point `seal_key_path` at a file containing 64 hex
chars (`openssl rand -hex 32 > certs/seal2.key`) and the party's `shard.bin`
is XChaCha20-Poly1305-sealed on disk — recommended for any shard that leaves
your desk (the cloud party, the Pi). Fail-closed on a bad key file, and a
sealed store never falls back to plaintext. Enable it **before** the first
DKG; to enable it on an existing plaintext shard, wipe that party's store
and run the recovery ceremony above (the re-share writes the new shard
sealed). The key file is the at-rest boundary: keep it OUT of the same
backup as the shard, or the seal adds nothing.

### TLS material (`certs/`)

Every internal socket (cosigner control APIs :4100/:4101, relay hub :3100) is
**mTLS-only**: servers require a leaf signed by the project CA, clients pin that
CA and present their own leaf. A process without its material refuses to start,
so hand-running any binary needs one prior:

```bash
cargo xtask certs
```

Re-runs are additive (existing material is never rewritten). The transport now
bounds *who may ask*, demo:

```bash
curl -s  http://127.0.0.1:4100/health   # plaintext → connection error
curl -sk https://127.0.0.1:4100/health  # TLS but no client cert → handshake refused
```

- **Rotation** (leaves are valid 2 years): `rm certs/<name>.*.pem && cargo xtask certs`.
  To rotate the **CA**, delete everything in `certs/` — a fresh CA over surviving
  leaves is refused (they would no longer chain).
- **Deploying a cosigner to another host** (e.g. the Pi): delete its leaf, re-issue
  with the host in the SANs — `cargo xtask certs --san 192.168.x.y` — then ship the
  leaf pair plus `ca.cert.pem` **only**. `ca.key.pem` never leaves the provisioning
  machine.

The public :3000 stays plaintext loopback — the CLI needs no certs.

### Driving the system (prepare / sign)

Once `cargo xtask up` reports the DKG address, the system is sign-ready. Drive it
with `sovra-cli` from another terminal (all commands default to
`http://127.0.0.1:3000`, override with `--api-url` / `SOVRA_API_URL`):

```bash
# Show the active signer address (independently verify the DKG output)
curl -s http://127.0.0.1:3000/v1/dkg

# Build an unsigned tx from intent (from = the DKG key's Ethereum address);
# tx_type: "legacy" | "eip2930" | "eip1559" (default).
# --value 0 works on a freshly created (unfunded) signer — see the funding note below.
cargo run -p sovra-cli -- prepare \
  --to 0x000000000000000000000000000000000000dEaD \
  --value 0
# → { "from": "0x..", "unsigned_transaction": "0x02..", "tx_digest": "0x.." }

# Sign it — the selected pair of cosigners runs the DKLs23 rounds P2P
cargo run -p sovra-cli -- sign --tx 0x02...
# → { "network": "ethereum", "signed_transaction": "0x02..", "signatures": [{ r, s, y_parity }], "signer_address": "0x…", ... }

# Broadcast it — submits to Sepolia via the RPC node, waits up to 30 s for a receipt
cargo run -p sovra-cli -- broadcast --tx 0x02...
# → 200 { "tx_hash": "0x..", "status": "confirmed", "block_number": .., "gas_used": .., "execution_success": true }
# → 202 { "tx_hash": "0x..", "status": "pending" }   # accepted, unmined — check Etherscan by tx_hash
```

A `202` is a success exit for the CLI: the node took the transaction, it just
hadn't mined within the window. A node-level rejection (nonce too low,
insufficient funds) is a `400` with the node's reason; an unreachable RPC node
is a `502`. Re-broadcasting an already-mined transaction returns `200` with its
receipt.

The CLI prints only the response JSON on stdout, so the whole lifecycle pipes
end-to-end:

```bash
cargo run -p sovra-cli -- prepare --to 0x000000000000000000000000000000000000dEaD --value 0 \
  | jq -r .unsigned_transaction \
  | xargs -I{} cargo run -p sovra-cli -- sign --tx {} \
  | jq -r .signed_transaction \
  | xargs -I{} cargo run -p sovra-cli -- broadcast --tx {}
```

Optional calldata goes through `--data` (defaults to `0x`) — note the sample
signing policy refuses calldata at *sign* time (see the policy section below):

```bash
cargo run -p sovra-cli -- prepare --to 0x... --value 0 --data 0xdeadbeef
```

**Funding:** a non-zero `--value` requires the signer address to hold Sepolia ETH —
`prepare` asks the RPC node to simulate the transaction (`eth_estimateGas`), and the
node rejects a spend the address can't cover. The symptom is a
`502 { "error": "rpc enrichment failed" }` from `prepare`; the underlying
`insufficient funds` reason is in the orchestrator's log. Fund the DKG address from
any Sepolia faucet, then non-zero values work end-to-end through `broadcast`.

### Signing policy (per cosigner)

Each cosigner loads its own policy at startup (`policy_path` in
`config/cosigner{0,1,2}.toml` → `config/policy{0,1,2}.toml`) and evaluates
every sign request against it — after decoding the unsigned tx itself, before
joining any MPC round. A missing or unparsable policy file means the cosigner
**refuses to start** (fail-closed). Any *selected* party alone vetoes — but
note that under t-of-n the effective policy is what any t parties jointly
allow, so **all three files (including the cold party's) must carry the same
baseline**; a permissive recovery shard would weaken the whole scheme.

All keys are required: `allowed_chain_ids`, `allowed_recipients` (addresses,
`["*"]` = any, `[]` = deny all), `max_value_wei` (**decimal string** — a TOML
integer caps at ~9.2 ETH), `allow_calldata`. The shipped samples allow only
the demo burn address on Sepolia, up to 1 ETH, no calldata.

Deny demo — the sample policy refuses calldata, so signing the `--data`
example above 403s with both vetoes attributed:

```bash
cargo run -p sovra-cli -- prepare --to 0x000000000000000000000000000000000000dEaD --value 0 --data 0xdeadbeef \
  | jq -r .unsigned_transaction \
  | xargs -I{} cargo run -p sovra-cli -- sign --tx {}
# → 403 { "error": "policy denied",
#         "vetoes": [ { "party": 0, "reason": "calldata not allowed" },
#                     { "party": 1, "reason": "calldata not allowed" } ] }
```

Nothing was signed and no lock stays held — the same command without `--data`
succeeds immediately afterwards. For a single-party veto, tighten only
`config/policy0.toml` (e.g. `max_value_wei = "0"`), restart cosigner 0, and
sign a non-zero value: the 403 then names party 0 alone (the response arrives
after the allowing party's MPC timeout, ~60s by default).

---

## API server

```bash
cargo xtask certs   # first time only — TLS material must exist
cargo run -p sovra-api
```

Listens on `127.0.0.1:3000` by default.

Override via environment:
```bash
SOVRA_BIND_ADDR=0.0.0.0:8080 cargo run -p sovra-api
SOVRA_RPC_URL=https://your-node.example.com cargo run -p sovra-api
```

Swagger UI available at: `http://localhost:3000/swagger-ui`

---

## Logging

Pretty output (default, local dev):
```bash
RUST_LOG=debug cargo run -p sovra-api
```

Structured JSON (production / log aggregators):
```bash
SOVRA_LOG_JSON=1 RUST_LOG=info cargo run -p sovra-api
```

---

## Unit tests

```bash
cargo test
```

Runs all unit tests across the workspace. Does not require a network connection.

---

## Pre-commit check

```bash
cargo ci-check
```

Runs the same checks as the `Build Check` GitHub workflow, in sequence, stopping
at the first failure (`&&` semantics): `cargo fmt --all --check`,
`taplo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, and `cargo deny check`. Green locally means CI passes.

Needs `taplo-cli` and `cargo-deny` installed (the command prints the exact
`cargo install` line if one is missing). Works from any directory in the repo.

---

## Integration tests

Integration tests hit a live Sepolia RPC and are gated behind `#[ignore]`.

Using the default public RPC from `config/sepolia.toml`:
```bash
cargo test -p sovra-eth -- --ignored
```

Using your own RPC endpoint:
```bash
SEPOLIA_RPC_URL=https://your-node.example.com cargo test -p sovra-eth -- --ignored
```

---

## Production build

```bash
cargo xtask certs   # mTLS material must exist — the binary refuses to start without it
cargo build --release -p sovra-api
./target/release/sovra-api
```

With JSON logs and a custom bind address:
```bash
SOVRA_LOG_JSON=1 RUST_LOG=info SOVRA_BIND_ADDR=0.0.0.0:3000 ./target/release/sovra-api
```

---

## Config reference

| Variable          | Default                                        | Description                        |
|-------------------|------------------------------------------------|------------------------------------|
| `RUST_LOG`        | `info`                                         | Log level / filter directive       |
| `SOVRA_LOG_JSON`  | unset                                          | Set to any value to enable JSON logs |
| `SOVRA_RPC_URL`   | value from `config/sepolia.toml`               | Ethereum RPC endpoint              |
| `SOVRA_BIND_ADDR` | `127.0.0.1:3000`                               | TCP address the API listens on     |
| `SOVRA_TLS_CA_PATH` / `_CERT_PATH` / `_KEY_PATH` | values from `config/sepolia.toml` | Orchestrator mTLS material (the deployment knob) |
| `SOVRA_COSIGNER_TLS_CA_PATH` / `_CERT_PATH` / `_KEY_PATH` | values from `config/cosigner{0,1,2}.toml` | Cosigner mTLS material |
| `SOVRA_COSIGNER_PARTICIPANTS` | values from `config/cosigner{0,1,2}.toml` | Comma-separated hex roster (all parties' verifying keys, id order) — how xtask injects it |