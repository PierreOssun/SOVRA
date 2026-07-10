//! End-to-end API flow over the in-process router — no network, no RPC:
//! dkg lifecycle, content-addressed signing, idempotency, restart recovery.

use std::str::FromStr;

use alloy_consensus::{
    TxEip1559, TxEnvelope, private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, Bytes, TxKind, U256, bytes};
use alloy_provider::Provider;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sovra_api::{run::build_router, state::AppState};
use sovra_eth::{TxIntent, encode_unsigned, prepare};
use sovra_mpc_dkls23_silence::InProcessBackend;
use sovra_state::SignerStore;
use sovra_types::{ACTIVE_SIGNER_ID, KeyShare, SignerId, SignerMetadata};
use tower::ServiceExt;

fn test_router(dir0: &std::path::Path, dir1: &std::path::Path) -> Router {
    let stores = [
        SignerStore::open(dir0).unwrap(), // context
        SignerStore::open(dir1).unwrap(), // context
    ];
    let backend = InProcessBackend::new(stores); // NEW: backend owns the stores now
    let active = backend.recover_active().unwrap(); // was: orchestrator::recover_active(&stores)
    let provider = sovra_eth::http_provider("http://127.0.0.1:9")
        .unwrap()
        .erased();
    build_router(AppState::new(provider, backend, active)) // was: AppState::new(provider, stores, active)
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn call(router: &Router, req: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

fn unsigned_tx() -> (Bytes, alloy_primitives::B256) {
    let prepared = prepare(TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Address::from([0x11; 20]),
        value: U256::from(1_000_000_000u64),
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    })
    .unwrap();
    (encode_unsigned(&prepared.tx), prepared.signing_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_lifecycle() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    // Nothing provisioned yet.
    let (status, _) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (raw, _) = unsigned_tx();
    let body = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", body)).await;
    assert_eq!(status, StatusCode::CONFLICT); // dkg not initialized

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

    let (raw, expected_digest) = unsigned_tx();
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

    let (raw, _) = unsigned_tx();
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
    let (raw, _) = unsigned_tx();
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

    let (raw, _) = unsigned_tx();
    let body = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, resp) = call(&router, post_json("/v1/sign", body)).await;

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let error = json(&resp)["error"].as_str().unwrap().to_string();
    assert_eq!(error, "mpc protocol failed");
    assert!(!error.contains(d1.path().to_str().unwrap()));
}
