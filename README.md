# 2-of-2 MPC Signer – DLKs23

This repo showcases a 2-of-2 MPC signer.

It prepares an Ethereum tx, signs it using MPC TSS, and broadcasts it.

Overall architecture diagram:
![svgviewer-png-output.png](docs/images/svgviewer-png-output.png)

## This repository contains:

- DKG (Distributed Key Generation) sets up 2 shards - DKLs23 DKG
- Take a tx hash to sign a Sepolia transaction - DKLs23 rounds
- Broadcast it – using a public RPC
- Be verifiable on Etherscan
- Two shards on different machines: one in a raspberry pi & one hosted on cloud (for demo purposes)

## Out of scope, for now

These are deliberate deferrals, not gaps:

- API authentication, authorization, rate limiting
- Share encryption at rest (filesystem permissions only for PoC)
- TLS certificate lifecycle (rotation, revocation)
- Concurrent signing sessions (global lock for PoC)
- Observability backend (local JSON logs only)
- Multi-chain support (Sepolia only)
- Automated backup and restore (manual archive only)
- Recovery beyond 2-of-2 threshold

/!\ This repo is for demo purposes only.     
It uses the (silence-laboratories DKLs23)[https://github.com/silence-laboratories/dkls23] as MPC TSS crypto implementation that has been audited but that is under commercial license.