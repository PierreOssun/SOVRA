//! RemoteBackend → HTTP → two cosigner routers → WsRelay → hub, plus remote
//! startup recovery and the cosigner-down 502 path.

mod test_helpers;
use std::{str::FromStr, sync::Arc, time::Duration};

use alloy_consensus::{
    TxEnvelope, private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, B256, Bytes, U256, bytes};
use alloy_provider::Provider;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use sovra_api::{
    orchestrator::{self, RecoverError},
    run::build_router as api_router_fn,
    state::AppState,
};
use sovra_cosigner::{run::build_router as cosigner_router, state::CosignerState};
use sovra_eth::{TxIntent, encode_unsigned, prepare};
use sovra_ipc::{
    hub::{RelayHub, ws_router},
    remote::RemoteBackend,
};
use sovra_state::SignerStore;
use test_helpers::*;
use tower::ServiceExt;
use url::Url;

// copied from cosigner_flow.rs
async fn start_hub() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, ws_router(RelayHub::default()))
            .await
            .unwrap()
    });
    format!("ws://{addr}/ws")
}

// adapted from cosigner_flow.rs::two_cosigners — one state, not a pair
fn cosigner_state(
    party_id: u8,
    sk: &SigningKey,
    peer: &SigningKey,
    dir: &std::path::Path,
    relay_url: &str,
) -> Arc<CosignerState> {
    Arc::new(CosignerState {
        party_id,
        signing_key: sk.clone(),
        peer_vk: Some(peer.verifying_key()),
        store: SignerStore::open(dir.join(format!("party{party_id}"))).unwrap(),
        relay_url: relay_url.to_owned(),
        ttl: Duration::from_secs(10),
        op: tokio::sync::Mutex::new(()),
    })
}

// The JoinHandle is the kill switch for the cosigner-down step.
async fn spawn_cosigner(state: Arc<CosignerState>) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle =
        tokio::spawn(async move { axum::serve(listener, cosigner_router(state)).await.unwrap() });
    // trailing slash: RemoteBackend joins "dkg"/"sign" onto this base (remote.rs)
    (Url::parse(&format!("http://{addr}/")).unwrap(), handle)
}

fn api_router(urls: &[Url; 2], active: Option<Address>) -> Router {
    let provider = sovra_eth::http_provider("http://127.0.0.1:9") // dummy, sign never touches RPC
        .unwrap()
        .erased();
    api_router_fn(AppState::new(
        provider,
        RemoteBackend::new(urls[0].clone(), urls[1].clone()),
        active,
    ))
}

async fn call(router: &Router, req: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}

fn unsigned_tx(value: u64) -> (Bytes, B256) {
    let prepared = prepare(TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Address::from([0x11; 20]),
        value: U256::from(value),
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    })
    .unwrap();
    (encode_unsigned(&prepared.tx), prepared.signing_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn split_flow() {
    let dir = tempfile::tempdir().unwrap();
    let relay_url = start_hub().await;

    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    // party_vks is positional by party id (cosigner state.rs) — 0 gets 1's vk and vice versa
    let (url0, _h0) = spawn_cosigner(cosigner_state(0, &sk0, &sk1, dir.path(), &relay_url)).await;
    let (url1, h1) = spawn_cosigner(cosigner_state(1, &sk1, &sk0, dir.path(), &relay_url)).await;
    let urls = [url0, url1];

    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // 1. fresh recover: nothing provisioned on either cosigner
    let active = orchestrator::recover_active(&probe, &urls).await.unwrap();
    assert_eq!(active, None);
    let router = api_router(&urls, active);

    // 2. dkg through the full stack; the address cross-check runs inside RemoteBackend
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let address = Address::from_str(json(&body)["address"].as_str().unwrap()).unwrap();

    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Address::from_str(json(&body)["address"].as_str().unwrap()).unwrap(),
        address
    );

    // 3. sign; finalize gate: recovered address == dkg address
    let (raw, expected_digest) = unsigned_tx(1_000_000_000);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, body) = call(&router, post_json("/v1/sign", req.clone())).await;
    assert_eq!(status, StatusCode::OK);
    let resp = json(&body);
    assert_eq!(
        resp["tx_digest"].as_str().unwrap(),
        expected_digest.to_string()
    );
    assert_eq!(
        Address::from_str(resp["recovered_address"].as_str().unwrap()).unwrap(),
        address
    );
    let signed = Bytes::from_str(resp["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // 4. idempotent re-sign: byte-identical body, no second MPC run
    let (status, body2) = call(&router, post_json("/v1/sign", req.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, body2);

    // 5. "restart": fresh recover over live cosigners == both shards retained,
    //    addresses agree (it GETs /signer on both and demands consensus)
    let active = orchestrator::recover_active(&probe, &urls).await.unwrap();
    assert_eq!(active, Some(address));
    let router2 = api_router(&urls, active);
    let (status, body) = call(&router2, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Address::from_str(json(&body)["address"].as_str().unwrap()).unwrap(),
        address
    );
    // fresh idempotency cache -> MPC re-runs through the split path on reloaded shards
    let (status, _) = call(&router2, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);

    // 6. kill cosigner 1 and wait for the accept loop (and its listener) to be gone
    h1.abort();
    let _ = h1.await;

    // recovery refuses to answer with a cosigner unreachable.
    // Fresh client on purpose: `probe`'s keep-alive pool still holds live
    // connections to cosigner 1 (axum's per-connection tasks outlive the abort).
    let probe2 = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let err = orchestrator::recover_active(&probe2, &urls)
        .await
        .unwrap_err();
    assert!(matches!(err, RecoverError::Transport(_)));

    // 7. cosigner-down sign -> 502 with the generic no-leak body.
    //    Fresh router == fresh RemoteBackend == fresh reqwest pool (same reason),
    //    and a different tx so the digest can't hit any idempotency path.
    let router3 = api_router(&urls, Some(address));
    let (raw2, _) = unsigned_tx(2_000_000_000);
    let req2 = serde_json::json!({ "unsigned_transaction": raw2.to_string() });
    let (status, body) = call(&router3, post_json("/v1/sign", req2)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        json(&body)["error"].as_str().unwrap(),
        "mpc protocol failed"
    );
}
