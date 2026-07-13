//! End-to-end API flow over the in-process router — no network, no RPC:
//! dkg lifecycle, content-addressed signing, idempotency, restart recovery.

mod test_helpers;
use std::{str::FromStr, time::Duration};

use alloy_consensus::{
    TxEip1559, TxEnvelope, private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, B256, Bytes, TxKind};
use alloy_provider::Provider;
use axum::{Router, http::StatusCode};
use sovra_api::{run::build_router, state::AppState};
use sovra_eth::encode_unsigned;
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError};
use sovra_mpc_dkls23_silence::InProcessBackend;
use sovra_state::SignerStore;
use sovra_types::{ACTIVE_SIGNER_ID, KeyShare, SignerId, SignerMetadata};
use test_helpers::*;

fn test_router(dir0: &std::path::Path, dir1: &std::path::Path) -> Router {
    let stores = [
        SignerStore::open(dir0).unwrap(),
        SignerStore::open(dir1).unwrap(),
    ];
    let backend = InProcessBackend::new(stores);
    let active = backend.recover_active().unwrap();
    let provider = sovra_eth::http_provider("http://127.0.0.1:9")
        .unwrap()
        .erased();
    build_router(AppState::new(provider, backend, active))
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_lifecycle() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    // Nothing provisioned yet.
    let (status, _) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let body = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", body)).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // Provision.
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address = json(&body)["address"].as_str().unwrap().to_string();

    // No rotation in the PoC.
    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["address"].as_str().unwrap(), address);
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_flow_and_idempotency() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address = Address::from_str(json(&body)["address"].as_str().unwrap()).unwrap();

    let (raw, expected_digest) = unsigned_tx(1_000_000_000u64);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });

    let (status, body) = call(&router, post_json("/v1/sign", req.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let resp = json(&body);

    // The server recomputed the digest we computed independently.
    assert_eq!(
        resp["tx_digest"].as_str().unwrap(),
        expected_digest.to_string()
    );
    assert_eq!(
        Address::from_str(resp["recovered_address"].as_str().unwrap()).unwrap(),
        address
    );

    // The broadcast bytes decode and recover to the dkg address.
    let signed = Bytes::from_str(resp["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // Idempotency: byte-identical response, no second MPC run.
    let (status, body2) = call(&router, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, body2);
}

#[tokio::test]
async fn sign_rejects_invalid_bytes() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let mut wrong_type = raw.to_vec();
    wrong_type[0] = 0x01;
    let mut trailing = raw.to_vec();
    trailing.push(0x00);

    for bad in [
        Bytes::from(wrong_type).to_string(),
        "0xdeadbeef".to_string(),
        Bytes::from(trailing).to_string(),
    ] {
        let body = serde_json::json!({ "unsigned_transaction": bad });
        let (status, _) = call(&router, post_json("/v1/sign", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "input: {bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn restart_recovers_active_generation() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());

    let router = test_router(d0.path(), d1.path());
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address = json(&body)["address"].as_str().unwrap().to_string();
    drop(router);

    // "Restart": a fresh AppState over the same store dirs.
    let router = test_router(d0.path(), d1.path());
    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body)["address"].as_str().unwrap(), address);

    // The reloaded shards actually sign.
    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn prepare_requires_dkg() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let body =
        serde_json::json!({ "to": format!("{:?}", Address::from([0x11; 20])), "value": "0" });
    let (status, _) = call(&router, post_json("/v1/prepare", body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[test]
fn recover_rejects_metadata_without_shard() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let stores = [
        SignerStore::open(d0.path()).unwrap(),
        SignerStore::open(d1.path()).unwrap(),
    ];

    let meta = SignerMetadata {
        signer_id: SignerId::new(ACTIVE_SIGNER_ID),
        address: Address::from([0xaa; 20]),
    };
    let shard = KeyShare::from(vec![1, 2, 3]);
    stores[0].save_shard(&meta, &shard).unwrap();
    stores[1].save_shard(&meta, &shard).unwrap();

    // Simulate a crash between save_shard's metadata write and shard write.
    std::fs::remove_file(d1.path().join(ACTIVE_SIGNER_ID).join("shard.bin")).unwrap();

    assert!(InProcessBackend::new(stores).recover_active().is_err());
}

#[tokio::test]
async fn sign_rejects_invalid_tx_invariants() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let tx = TxEip1559 {
        chain_id: 0, // prepare could never produce this
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        to: TxKind::Call(Address::from([0x11; 20])),
        ..Default::default()
    };
    let body = serde_json::json!({ "unsigned_transaction": encode_unsigned(&tx).to_string() });
    let (status, resp) = call(&router, post_json("/v1/sign", body)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json(&resp)["error"].as_str().unwrap().contains("chain id"));
}

#[tokio::test(flavor = "multi_thread")]
async fn server_errors_do_not_leak_paths() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    // Break party 1's storage after provisioning.
    std::fs::remove_file(d1.path().join(ACTIVE_SIGNER_ID).join("shard.bin")).unwrap();

    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let body = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, resp) = call(&router, post_json("/v1/sign", body)).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let error = json(&resp)["error"].as_str().unwrap().to_string();
    assert_eq!(error, "mpc protocol failed");
    assert!(!error.contains(d1.path().to_str().unwrap()));
}

// Delegation, not fakery: the winner gets a real signature back, so it passes
// finalize's recovered-address check — clean {200, 409}, no accidental 500.
struct SlowBackend(InProcessBackend);

impl MpcBackend for SlowBackend {
    async fn dkg(&self) -> Result<Address, MpcError> {
        self.0.dkg().await
    }
    async fn sign(&self, signing_hash: B256) -> Result<EcdsaParts, MpcError> {
        tokio::time::sleep(Duration::from_millis(300)).await; // widen the race window
        self.0.sign(signing_hash).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_signs_one_wins_one_conflicts() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let stores = [
        SignerStore::open(d0.path()).unwrap(),
        SignerStore::open(d1.path()).unwrap(),
    ];
    let provider = sovra_eth::http_provider("http://127.0.0.1:9")
        .unwrap()
        .erased();
    let router = build_router(AppState::new(
        provider,
        SlowBackend(InProcessBackend::new(stores)),
        None,
    ));

    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    // two DIFFERENT digests — the same digest could resolve through the
    // idempotency cache instead of the op lock, which is what's under test
    let (raw_a, _) = unsigned_tx(1_000_000_000);
    let (raw_b, _) = unsigned_tx(2_000_000_000);
    let req_a = serde_json::json!({ "unsigned_transaction": raw_a.to_string() });
    let req_b = serde_json::json!({ "unsigned_transaction": raw_b.to_string() });

    let (a, b) = tokio::join!(
        call(&router, post_json("/v1/sign", req_a)),
        call(&router, post_json("/v1/sign", req_b)),
    );
    let mut statuses = [a.0, b.0];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]); // 200 < 409
}
