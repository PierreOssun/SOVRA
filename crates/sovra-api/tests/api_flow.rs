//! End-to-end API flow over the in-process router — no network, no live RPC
//! (broadcast tests use alloy's FIFO mock transport): dkg lifecycle,
//! content-addressed signing, idempotency, restart recovery, broadcast.

mod test_helpers;
use std::{str::FromStr, time::Duration};

use alloy_consensus::{
    Receipt, ReceiptEnvelope, ReceiptWithBloom, TxEip1559, TxEnvelope,
    private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, B256, Bytes, TxKind, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionReceipt;
use alloy_transport::mock::Asserter;
use axum::{Router, http::StatusCode};
use sovra_api::{
    run::build_router,
    state::{AppState, BroadcastTiming},
};
use sovra_eth::encode_unsigned;
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError};
use sovra_mpc_dkls23_carbon::InProcessBackend;
use sovra_state::SignerStore;
use sovra_types::{ACTIVE_SIGNER_ID, KeyShare, PubkeySec1, SignerId, SignerMetadata};
use test_helpers::*;

fn router_with(
    dir0: &std::path::Path,
    dir1: &std::path::Path,
    provider: DynProvider,
    timing: BroadcastTiming,
) -> Router {
    let stores = vec![
        SignerStore::open(dir0).unwrap(),
        SignerStore::open(dir1).unwrap(),
    ];
    let backend = InProcessBackend::new(stores, 2);
    let active = backend.recover_active().unwrap();
    let mut state = AppState::new(provider, backend, active);
    state.broadcast = timing;
    build_router(state)
}

fn test_router(dir0: &std::path::Path, dir1: &std::path::Path) -> Router {
    let provider = sovra_eth::http_provider("http://127.0.0.1:9")
        .unwrap()
        .erased();
    router_with(dir0, dir1, provider, BroadcastTiming::default())
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_lifecycle() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    // Liveness is up before any provisioning — compose healthchecks and
    // `sovra check` rely on that.
    let (status, body) = call(&router, get("/health")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"ok");

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
    let address = json(&body)["addresses"]["ethereum"]
        .as_str()
        .unwrap()
        .to_string();

    // No rotation in the PoC.
    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body)["addresses"]["ethereum"].as_str().unwrap(),
        address
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_flow_and_idempotency() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address =
        Address::from_str(json(&body)["addresses"]["ethereum"].as_str().unwrap()).unwrap();

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
        Address::from_str(resp["signer_address"].as_str().unwrap()).unwrap(),
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
    let address = json(&body)["addresses"]["ethereum"]
        .as_str()
        .unwrap()
        .to_string();
    drop(router);

    // "Restart": a fresh AppState over the same store dirs.
    let router = test_router(d0.path(), d1.path());
    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&body)["addresses"]["ethereum"].as_str().unwrap(),
        address
    );

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
    let stores = vec![
        SignerStore::open(d0.path()).unwrap(),
        SignerStore::open(d1.path()).unwrap(),
    ];

    let meta = SignerMetadata {
        signer_id: SignerId::new(ACTIVE_SIGNER_ID),
        public_key: {
            let mut b = [0xaa; 33];
            b[0] = 0x02;
            PubkeySec1::from_slice(&b).unwrap()
        },
    };
    let shard = KeyShare::from(vec![1, 2, 3]);
    stores[0].save_shard(&meta, &shard).unwrap();
    stores[1].save_shard(&meta, &shard).unwrap();

    // Simulate a crash between save_shard's metadata write and shard write.
    std::fs::remove_file(d1.path().join(ACTIVE_SIGNER_ID).join("shard.bin")).unwrap();

    assert!(InProcessBackend::new(stores, 2).recover_active().is_err());
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
    let body = serde_json::json!({ "unsigned_transaction": encode_unsigned(&sovra_eth::EthTx::Eip1559(tx)).to_string() });
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

/// /v1/recover pins the HTTP contract of the all-parties proactive refresh:
/// 409 before dkg, 200 with the UNCHANGED address after, and the refreshed
/// shards keep signing. Works on the plain 2-of-2 `test_router` — with no
/// lost-party role, a t == n scheme refreshes fine.
#[tokio::test(flavor = "multi_thread")]
async fn recover_requires_dkg_then_preserves_address_and_signs() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    // Nothing to refresh before dkg.
    let (status, _) = call(&router, post_json("/v1/recover", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, resp) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address = json(&resp)["addresses"]["ethereum"]
        .as_str()
        .unwrap()
        .to_string();

    let (status, resp) = call(&router, post_json("/v1/recover", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json(&resp)["addresses"]["ethereum"].as_str().unwrap(),
        address
    );

    // The refreshed generation signs.
    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, resp) = call(&router, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&resp)["signer_address"].as_str().unwrap(), address);
}

// Delegation, not fakery: the winner gets a real signature back, so it passes
// finalize's recovered-address check — clean {200, 409}, no accidental 500.
struct SlowBackend(InProcessBackend);

impl MpcBackend for SlowBackend {
    async fn dkg(&self) -> Result<PubkeySec1, MpcError> {
        self.0.dkg().await
    }
    async fn sign(
        &self,
        network: sovra_types::NetworkId,
        unsigned_tx: &[u8],
    ) -> Result<Vec<EcdsaParts>, MpcError> {
        tokio::time::sleep(Duration::from_millis(300)).await; // widen the race window
        self.0.sign(network, unsigned_tx).await
    }
    async fn refresh(&self) -> Result<PubkeySec1, MpcError> {
        self.0.refresh().await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_signs_one_wins_one_conflicts() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let stores = vec![
        SignerStore::open(d0.path()).unwrap(),
        SignerStore::open(d1.path()).unwrap(),
    ];
    let provider = sovra_eth::http_provider("http://127.0.0.1:9")
        .unwrap()
        .erased();
    let router = build_router(AppState::new(
        provider,
        SlowBackend(InProcessBackend::new(stores, 2)),
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

// ---------------------------------------------------------------------------
// /v1/broadcast — driven through alloy's FIFO mock transport (Asserter), so
// every RPC response is scripted and the two-call poll loop stays
// deterministic. Timings are shrunk per-test via `BroadcastTiming`.

fn mocked_router(
    dir0: &std::path::Path,
    dir1: &std::path::Path,
    asserter: Asserter,
    timing: BroadcastTiming,
) -> Router {
    let provider = ProviderBuilder::new()
        .connect_mocked_client(asserter)
        .erased();
    router_with(dir0, dir1, provider, timing)
}

/// dkg + sign on `router`, returning the signed bytes and their tx hash
/// (keccak of the raw envelope — what the node would echo back).
async fn provision_and_sign(router: &Router) -> (Bytes, B256) {
    let (status, _) = call(router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let (raw, _) = unsigned_tx(1_000_000_000u64);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, body) = call(router, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);
    let signed = Bytes::from_str(json(&body)["signed_transaction"].as_str().unwrap()).unwrap();
    let tx_hash = keccak256(&signed);
    (signed, tx_hash)
}

fn receipt_for(tx_hash: B256, success: bool) -> TransactionReceipt {
    TransactionReceipt {
        inner: ReceiptEnvelope::Eip1559(ReceiptWithBloom {
            receipt: Receipt {
                status: success.into(),
                cumulative_gas_used: 21_000,
                logs: vec![],
            },
            logs_bloom: Default::default(),
        }),
        transaction_hash: tx_hash,
        transaction_index: Some(0),
        block_hash: Some(B256::from([0x22; 32])),
        block_number: Some(123),
        gas_used: 21_000,
        effective_gas_price: 3,
        blob_gas_used: None,
        blob_gas_price: None,
        from: Address::from([0x33; 20]),
        to: Some(Address::from([0x11; 20])),
        contract_address: None,
    }
}

fn fast_timing() -> BroadcastTiming {
    BroadcastTiming {
        timeout: Duration::from_secs(5),
        poll: Duration::from_millis(1),
    }
}

#[tokio::test]
async fn broadcast_requires_dkg() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());

    // The dkg guard runs before any byte is parsed, so the payload is moot.
    let body = serde_json::json!({ "signed_transaction": "0xdeadbeef" });
    let (status, _) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_rejects_invalid_bytes() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path());
    let (signed, _) = provision_and_sign(&router).await;

    let mut wrong_type = signed.to_vec();
    wrong_type[0] = 0x01;
    let mut trailing = signed.to_vec();
    trailing.push(0x00);
    let unsigned = unsigned_tx(1_000_000_000u64).0; // no signature list

    for bad in [
        Bytes::from(wrong_type).to_string(),
        "0xdeadbeef".to_string(),
        Bytes::from(trailing).to_string(),
        unsigned.to_string(),
    ] {
        let body = serde_json::json!({ "signed_transaction": bad });
        let (status, _) = call(&router, post_json("/v1/broadcast", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "input: {bad}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_rejects_foreign_signer() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (d2, d3) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router_a = test_router(d0.path(), d1.path());
    let router_b = test_router(d2.path(), d3.path());
    let (signed, _) = provision_and_sign(&router_a).await;
    // router_b has its own (different) active address.
    let (status, _) = call(&router_b, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router_b, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json(&resp)["error"]
            .as_str()
            .unwrap()
            .contains("active signer")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_confirmed() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let asserter = Asserter::new();
    let router = mocked_router(d0.path(), d1.path(), asserter.clone(), fast_timing());
    let (signed, tx_hash) = provision_and_sign(&router).await;

    asserter.push_success(&tx_hash); // eth_sendRawTransaction echoes the hash
    asserter.push_success(&receipt_for(tx_hash, true)); // first poll hits

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::OK);
    let resp = json(&resp);
    assert_eq!(resp["status"], "confirmed");
    assert_eq!(resp["tx_hash"].as_str().unwrap(), tx_hash.to_string());
    assert_eq!(resp["block_number"], 123);
    assert_eq!(resp["gas_used"], 21_000);
    assert_eq!(resp["execution_success"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_pending_202() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let asserter = Asserter::new();
    let timing = BroadcastTiming {
        timeout: Duration::ZERO, // exactly one receipt check, then pending
        poll: Duration::from_millis(1),
    };
    let router = mocked_router(d0.path(), d1.path(), asserter.clone(), timing);
    let (signed, tx_hash) = provision_and_sign(&router).await;

    asserter.push_success(&tx_hash);
    asserter.push_success(&serde_json::Value::Null); // no receipt yet

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let resp = json(&resp);
    assert_eq!(resp["status"], "pending");
    assert_eq!(resp["tx_hash"].as_str().unwrap(), tx_hash.to_string());
    assert!(resp.get("block_number").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_node_rejection_maps_400() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let asserter = Asserter::new();
    let router = mocked_router(d0.path(), d1.path(), asserter.clone(), fast_timing());
    let (signed, _) = provision_and_sign(&router).await;

    asserter.push_failure_msg("nonce too low");
    asserter.push_success(&serde_json::Value::Null); // recheck: never mined

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        json(&resp)["error"]
            .as_str()
            .unwrap()
            .contains("nonce too low")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_rejection_after_mined_is_confirmed() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let asserter = Asserter::new();
    let router = mocked_router(d0.path(), d1.path(), asserter.clone(), fast_timing());
    let (signed, tx_hash) = provision_and_sign(&router).await;

    asserter.push_failure_msg("already known"); // idempotent re-broadcast
    asserter.push_success(&receipt_for(tx_hash, true)); // …because it mined

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&resp)["status"], "confirmed");
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_rpc_unreachable_502() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let router = test_router(d0.path(), d1.path()); // dead RPC URL
    let (signed, _) = provision_and_sign(&router).await;

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(json(&resp)["error"], "rpc broadcast failed"); // no leak
}

#[tokio::test(flavor = "multi_thread")]
async fn broadcast_wrong_node_hash_500() {
    let (d0, d1) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let asserter = Asserter::new();
    let router = mocked_router(d0.path(), d1.path(), asserter.clone(), fast_timing());
    let (signed, _) = provision_and_sign(&router).await;

    asserter.push_success(&B256::from([0xee; 32])); // node lies about the hash

    let body = serde_json::json!({ "signed_transaction": signed.to_string() });
    let (status, resp) = call(&router, post_json("/v1/broadcast", body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json(&resp)["error"], "broadcast verification failed");
}
