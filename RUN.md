How to run:

## One-command local system (tmux)

Spawn the whole system — orchestrator + both cosigners, wired together — in a
single tmux window:

```bash
cargo xtask up
```

On the **first** run this seeds each cosigner's identity under `data/cosigner{0,1}/`
**and the TLS material under `certs/`** (project CA + one leaf per process), pins
each peer's verifying key, starts all three processes, and runs the one-time
DKG so the signer address is ready. Later runs **load** the existing identities and
certs and detect that DKG has already happened. Layout: `cosigner0` / `cosigner1`
on top, the orchestrator full-width below. Tear it down with:

```bash
cargo xtask down
```

Local only. To run the processes individually, see the sections below.

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

# Build an unsigned EIP-1559 tx from intent (from = the DKG address).
# --value 0 works on a freshly created (unfunded) signer — see the funding note below.
cargo run -p sovra-cli -- prepare \
  --to 0x000000000000000000000000000000000000dEaD \
  --value 0
# → { "from": "0x..", "unsigned_transaction": "0x02..", "tx_digest": "0x.." }

# Sign it — both cosigners run the DKLs23 rounds P2P
cargo run -p sovra-cli -- sign --tx 0x02...
# → { "signed_transaction": "0x02..", "signature": { r, s, y_parity }, ... }
```

The CLI prints only the response JSON on stdout, so prepare pipes straight into
sign:

```bash
cargo run -p sovra-cli -- prepare --to 0x000000000000000000000000000000000000dEaD --value 0 \
  | jq -r .unsigned_transaction \
  | xargs -I{} cargo run -p sovra-cli -- sign --tx {}
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
any Sepolia faucet, then non-zero values (and `POST /v1/broadcast`, not yet in the
CLI) work.

### Signing policy (per cosigner)

Each cosigner loads its own policy at startup (`policy_path` in
`config/cosigner{0,1}.toml` → `config/policy{0,1}.toml`) and evaluates every
sign request against it — after decoding the unsigned tx itself, before
joining any MPC round. A missing or unparsable policy file means the cosigner
**refuses to start** (fail-closed). The two files may differ; in 2-of-2
either party alone vetoes.

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
| `SOVRA_COSIGNER_TLS_CA_PATH` / `_CERT_PATH` / `_KEY_PATH` | values from `config/cosigner{0,1}.toml` | Cosigner mTLS material |