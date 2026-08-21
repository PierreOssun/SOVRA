![Sovra](docs/images/SOVRA-banner.png)

# Sovra — Self-Hosted MPC Signer for ECDSA

**[sovra.ink](https://sovra.ink/)**

Sovra is a t-of-n MPC signer, deployed as 2-of-3: two active cosigners plus a cold recovery shard. 

The private key never exists in one place, not at generation, not at signing. A Malware, a rogue AI agent, or full penetration of any single machine yields at most one share: never enough to sign. Lose a cosigner and the cold shard restores the quorum.

Every component runs on hardware you own. No SaaS, no vendor lock-in.

MPC TSS is the industry standard for institutional key custody: the technology behind Fireblocks, Copper, and Taurus. Sovra is the open-source, self-hosted alternative: the same signing scheme, on hardware you own.

Built for Ethereum (for now :) ).

## 1. Architecture

### 1.1 Component scope

The Orchestrator holds no shares; each cosigner holds exactly one.

External actors (calls to the public API, and the Sepolia RPC node) are not components.

![svgviewer-png-output (1).png](docs/images/svgviewer-png-output_(1).png)

### 1.2 DKG workflow

A one-time ceremony. The Orchestrator triggers DKG on all n cosigners (all must be online). Then the cosigners run the DKLs23 DKG rounds directly P2P and each persists its own share.

The derived address is reported back and independently verified by the operator.

![svgviewer-png-output (2).png](docs/images/svgviewer-png-output_(2).png)

### 1.3 Signing and broadcast workflow

The runtime path. The client calls the Orchestrator (sovra-api) to prepare and sign. Then the Orchestrator selects t ready cosigners (config preference order, cold party last) and triggers signing on exactly those.

The cosigners run the DKLs23 rounds directly P2P and return the final signature.

The Orchestrator assembles and verifies the signature, then broadcasts to Sepolia.

![svgviewer-png-output.png](docs/images/svgviewer-png-output.png)

---

## 2. Public HTTP API

Three transaction-lifecycle endpoints (`prepare`, `sign`, `broadcast`), plus operator endpoints for DKG.

### `POST /v1/prepare`

Build an unsigned transaction from intent (legacy, EIP-2930, or EIP-1559 — default).
Request: `{ to, value, data? }` (`data` defaults to `0x`).
`from` is always the active DKG address (`409` if DKG has not run).

Response: `{ from, unsigned_transaction, tx_digest }`.

### `POST /v1/dkg`

Operator endpoint. Runs the one-time DKG ceremony, persists one shard per party,
and returns the derived signer address.
Response: `{ address }`. A second call returns `409` — no key rotation in the PoC.

### `GET /v1/dkg`

Returns the active signer address (`{ address }`, or `404` if DKG has not run),
so the operator can independently verify the derived address.

### `POST /v1/sign`

Execute signing across the selected t cosigners over the supplied unsigned transaction.
Request: `{ unsigned_transaction }` — the `0x02…`-prefixed bytes from `prepare`

Response: `{ network, signed_transaction, signatures: [{ r, s, y_parity }], signer_address, tx_digest }`.

### `POST /v1/broadcast`

Submit the signed transaction to Sepolia and wait up to 30 seconds for a receipt.
Request: `{ signed_transaction }` — the `0x02…`-prefixed bytes from `sign`. The
signer is recovered from the bytes and must match the active DKG address.

Response: `200 { tx_hash, status: "confirmed", block_number, gas_used, execution_success }`

---

## Goal of this repository:

- DKG (Distributed Key Generation) sets up 3 shards (2-of-3) - DKLs23 DKG
- Take a tx hash to sign a Sepolia transaction - DKLs23 rounds
- Broadcast it – using a public RPC
- Be verifiable on Etherscan
- Shards on different machines: one on a raspberry pi, one local, and the cold recovery shard hosted on cloud (for demo purposes)

## Out of scope, for now

These are deliberate deferrals, not gaps:

- API authentication, authorization, rate limiting
- Share encryption at rest (filesystem permissions only for PoC)
- TLS certificate lifecycle (rotation, revocation)
- Concurrent signing sessions (global lock for PoC)
- Observability backend (local JSON logs only)
- Multi-chain support (the `Network` seam exists — `sovra-network` — but Ethereum/Sepolia is the only implementation)
- Automated backup and restore (manual archive only)
- Quorum changes (`quorum_change`)

/!\ This repo is for demo purposes only.

It uses the [0xCarbon DKLs23](https://github.com/0xCarbon/DKLs23) crate (Apache-2.0/MIT) as the MPC TSS implementation; message transport security (ed25519-signed, per-recipient-sealed round envelopes) is Sovra's own layer. No third-party audit of either is published — do not hold real value with this.

## Recovery model

2-of-3 = two active shards plus one sleeping shard. Recovery is a product flow, not a protocol operation:

- **Proactive refresh** (`POST /v1/recover`): all three cosigners online, every shard re-randomizes under the SAME address; old shards become useless.
- **Lost shard**: signing continues on the surviving pair (selection skips dead/unprovisioned parties automatically). You are now effectively 2-of-2 with zero redundancy — migrate promptly: wipe all shard stores, run a fresh DKG, move funds to the new address.
- **Seedphrase-equivalent**: an offline encrypted backup of the sleeping shard's `data_dir` (shard + `identity.key`; keep the seal key in a separate location). Restoring the sleeping party's own files is plain state restore — no ceremony needed — and re-arms the redundancy.

## Migrating a deployment from the sl-dkls23 era

Shard formats are incompatible: **wipe every cosigner's shard store and run a fresh DKG** (then move funds from the old address). Everything else carries over unchanged: `identity.key`, pinned rosters, certificates, and configs — except `relay_url`, which now ends in `/env` instead of `/ws`.
