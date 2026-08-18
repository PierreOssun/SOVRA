# Architecture

## 1. Architecture diagrams

Three single-purpose diagrams:
- The first shows component scope and ownership (no flow). 
- The second: the DKG workflow
- The third: Signing and broadcast workflow

In all three, the CLI only talks to the Orchestrator, and the Orchestrator is the only thing that reaches the cosigners.

### 1.1 Component scope

The Orchestrator holds no shares; each cosigner holds exactly one.

External actors (calls to the public API, and the Sepolia RPC node) are not components.

![svgviewer-png-output (1).png](images/svgviewer-png-output_(1).png)

### 1.2 DKG workflow

A one-time ceremony. The Orchestrator triggers DKG on all n cosigners (all must be online). Then the cosigners run the DKLs23 DKG rounds directly P2P and each persists its own share.    

The derived address is reported back and independently verified by the operator.    

![svgviewer-png-output (2).png](images/svgviewer-png-output_(2).png)

### 1.3 Signing and broadcast workflow

The runtime path. The client calls the Orchestrator to prepare and sign. Then the Orchestrator selects t ready cosigners (preference order, cold party last) and triggers signing on exactly those.    

The cosigners run the DKLs23 rounds directly P2P and return the final signature.    

The Orchestrator assembles and verifies the signature, then broadcasts to Sepolia.

![svgviewer-png-output.png](images/svgviewer-png-output.png)

---

## 2. Public HTTP API

Three transaction-lifecycle endpoints (`prepare`, `sign`, `broadcast`), plus operator endpoints for DKG.

### `POST /v1/prepare`

Build an unsigned transaction from intent (legacy, EIP-2930, or EIP-1559 — default).

### `POST /v1/sign`

Execute signing across the selected t cosigners over the supplied unsigned transaction.

### `POST /v1/broadcast`

Submit the signed transaction to Sepolia and wait up to 30 seconds for a receipt.

---

## 3. Workspace structure

```
sovra-mpc-poc/
├── crates/
│   ├── sovra-api/           # Orchestrator (API Host) binary
│   ├── sovra-cosigner/      # Cosigner binary (one process per party)
│   ├── sovra-cli/           # Operator CLI (talks to Orchestrator only)
│   ├── sovra-types/         # Shared identifiers, session states, errors
│   ├── sovra-ipc/           # HTTP/JSON control + WS relay, mTLS transport
│   ├── sovra-mpc/           # MpcBackend trait (chain-neutral seam)
│   ├── sovra-mpc-dkls23-silence/  # Silence Labs DKLs23 adapter
│   ├── sovra-network/       # Network trait + tagged TxView/TxError
│   ├── sovra-eth/           # Ethereum impl: tx prep, encoding, finalize, broadcast
│   ├── sovra-state/         # Filesystem repositories
│   └── sovra-observability/ # Structured logging
├── config/
├── data/        # Runtime state. Gitignored.
├── certs/       # Local mTLS certs. Gitignored.
├── docs/
└── scripts/
```

## 4. Adding a network

The key identity is the 33-byte compressed SEC1 pubkey (`PubkeySec1`);
addresses are per-network derivations. ECDSA/secp256k1 is the only signature
scheme. To add a network (e.g. Bitcoin):

1. New crate implementing `sovra_network::Network` (associated `Unsigned`
   type; `signing_digests` may return several digests — one MPC ceremony runs
   per digest on a derived `sub_instance`).
2. Add the `NetworkId` variant. The compiler then forces every decision
   point: `Policy::evaluate` (its rules), the cosigner's `vet` dispatch, the
   orchestrator's `sign` dispatch, and the concrete `prepare`/`broadcast`
   arms (enrichment I/O is deliberately outside the trait).
3. Add a `TxView` variant + policy grammar for the network (absent policy
   table = deny).

Cosigners always receive full self-describing tx bytes, never digests, and
re-derive everything they sign — any new network must keep that invariant.
