How to run:

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