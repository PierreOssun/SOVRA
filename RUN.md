How to run:

## One-command local system (tmux)

Spawn the whole system — orchestrator + both cosigners, wired together — in a
single tmux window:

```bash
cargo xtask up
```

On the **first** run this seeds each cosigner's identity under `data/cosigner{0,1}/`,
pins each peer's verifying key, starts all three processes, and runs the one-time
DKG so the signer address is ready. Later runs **load** the existing identities and
detect that DKG has already happened. Layout: `cosigner0` / `cosigner1` on top, the
orchestrator full-width below. Tear it down with:

```bash
cargo xtask down
```

Local only. To run the processes individually, see the sections below.

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

Optional calldata goes through `--data` (defaults to `0x`):

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

---

## API server

```bash
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