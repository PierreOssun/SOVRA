use sovra_eth::{TxIntent, encode_unsigned, finalize, prepare};
use sovra_mpc::MpcBackend;
use sovra_mpc_dkls23_silence::InProcessBackend;
use sovra_state::SignerStore;

fn base_intent() -> TxIntent {
    TxIntent {
        chain_id: 11155111,
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
    let dir = tempfile::tempdir().expect("tempdir");
    let backend = InProcessBackend::new([
        SignerStore::open(dir.path().join("party0")).expect("store 0"),
        SignerStore::open(dir.path().join("party1")).expect("store 1"),
    ]);

    let address = backend.dkg().await.expect("dkg");

    let prepared = prepare(base_intent()).expect("prepare");

    let parts = backend
        .sign(encode_unsigned(&prepared.tx), prepared.signing_hash)
        .await
        .expect("sign");

    let signed = finalize(prepared, parts.r, parts.s, parts.y_parity, address).expect("finalize");

    assert_eq!(signed.from, address);
}
