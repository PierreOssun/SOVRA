//! M1 end-to-end: a 2-of-2 DKLs23 signature, produced in-process, must recover
//! to the DKG-derived address and be accepted by `sovra_eth::finalize`.

use sovra_eth::{TxIntent, finalize, prepare};
use sovra_mpc::MpcBackend;
use sovra_mpc_dkls23_silence::SilenceBackend;

fn base_intent() -> TxIntent {
    TxIntent {
        chain_id: 11155111, // Sepolia
        nonce: 0,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_sign_finalize_roundtrip() {
    let backend = SilenceBackend;

    // 1. Provision a signer: 2-of-2 DKG → two shards + derived address.
    let dkg = backend.dkg().await.expect("dkg");

    // 2. Build the EIP-1559 signing hash from a tx intent.
    let prepared = prepare(base_intent()).expect("prepare");

    // 3. Produce (r, s, y_parity) via the 2-of-2 DSG over that hash.
    let parts = backend
        .sign(prepared.signing_hash, &dkg.shares)
        .await
        .expect("sign");

    // 4. Assemble + verify: finalize recovers the signer and checks it matches.
    let signed =
        finalize(prepared, parts.r, parts.s, parts.y_parity, dkg.address).expect("finalize");

    // finalize already enforces recovered == expected; assert it explicitly too.
    assert_eq!(signed.from, dkg.address);
}
