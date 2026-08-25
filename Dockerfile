# syntax=docker/dockerfile:1
# One multi-stage build, three images: --target cosigner | api | cli.
# Build and runtime share bookworm's glibc, which is the whole point — the
# sl-era runbook's "the binary needs the CI runner's exact glibc" saga cannot
# happen inside an image.

########## builder ##########
FROM rust:1-bookworm AS builder
# aws-lc-sys (rustls' crypto provider) compiles C and assembly.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# rust-toolchain.toml is deliberately .dockerignored: the workspace uses no
# nightly feature, and the image's pinned stable keeps builds reproducible.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# --locked: the committed lockfile carries the RustCrypto rc pins the MPC
# backend depends on — a resolver re-run inside the build would break it.
# Cache mounts don't persist into layers, so binaries move to /out in-RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p sovra-cosigner -p sovra-api -p sovra-cli \
    && install -D target/release/sovra-cosigner /out/sovra-cosigner \
    && install -D target/release/sovra-api /out/sovra-api \
    && install -D target/release/sovra-cli /out/sovra-cli

########## shared runtime ##########
FROM debian:bookworm-slim AS runtime
LABEL org.opencontainers.image.source="https://github.com/PierreOssun/SOVRA"
LABEL org.opencontainers.image.description="Sovra — self-hosted MPC signer for ECDSA"
# ca-certificates: the orchestrator dials the Ethereum RPC over public TLS.
# curl: compose healthchecks. Everything internal is the project CA, mounted.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home-dir /opt/sovra --shell /usr/sbin/nologin sovra \
    && install -d -o sovra -g sovra /opt/sovra /opt/sovra/config /opt/sovra/certs /opt/sovra/data
# Relative config/cert paths resolve from here — same load-bearing
# WorkingDirectory the systemd unit had.
WORKDIR /opt/sovra
USER sovra

########## images ##########
FROM runtime AS cosigner
COPY --from=builder /out/sovra-cosigner /usr/local/bin/
EXPOSE 4100
ENTRYPOINT ["sovra-cosigner"]

FROM runtime AS api
COPY --from=builder /out/sovra-api /usr/local/bin/
EXPOSE 3000 3100
ENTRYPOINT ["sovra-api"]

FROM runtime AS cli
COPY --from=builder /out/sovra-cli /usr/local/bin/
ENTRYPOINT ["sovra-cli"]
