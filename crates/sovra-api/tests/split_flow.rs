//! RemoteBackend → HTTP → two cosigner routers → WsRelay → hub, plus remote
//! startup recovery and the cosigner-down 502 path.

mod test_helpers;
use std::{str::FromStr, sync::Arc, time::Duration};

use alloy_consensus::{
    TxEnvelope, private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use axum::{Router, http::StatusCode};
use ed25519_dalek::SigningKey;
use sovra_api::{
    orchestrator::{self, RecoverError},
    run::build_router as api_router_fn,
    state::AppState,
};
use sovra_cosigner::{run::build_router as cosigner_router, state::CosignerState};
use sovra_ipc::{
    hub::{RelayHub, ws_router},
    remote::RemoteBackend,
    tls::{TlsMaterials, serve_mtls},
};
use sovra_state::SignerStore;
use test_helpers::*;
use url::Url;

// copied from cosigner_flow.rs; the hub rides the orchestrator's materials,
// mirroring run.rs
async fn start_hub(tls: Arc<TlsMaterials>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_mtls(listener, ws_router(RelayHub::default()), &tls)
            .await
            .unwrap()
    });
    format!("wss://{addr}/ws")
}

/// Wide-open policy for the pre-M7 scenarios; deny cases build their own.
fn permissive_policy() -> sovra_policy::Policy {
    sovra_policy::Policy {
        allowed_chain_ids: vec![11155111],
        allowed_recipients: sovra_policy::Recipients::Any,
        max_value_wei: U256::MAX,
        allow_calldata: false,
    }
}

// adapted from cosigner_flow.rs::two_cosigners — one state, not a pair
fn cosigner_state(
    party_id: u8,
    sk: &SigningKey,
    peer: &SigningKey,
    dir: &std::path::Path,
    relay_url: &str,
    tls: &TlsMaterials,
) -> Arc<CosignerState> {
    cosigner_state_with_policy(party_id, sk, peer, dir, relay_url, tls, permissive_policy())
}

#[allow(clippy::too_many_arguments)]
fn cosigner_state_with_policy(
    party_id: u8,
    sk: &SigningKey,
    peer: &SigningKey,
    dir: &std::path::Path,
    relay_url: &str,
    tls: &TlsMaterials,
    policy: sovra_policy::Policy,
) -> Arc<CosignerState> {
    Arc::new(CosignerState {
        party_id,
        signing_key: sk.clone(),
        peer_vk: Some(peer.verifying_key()),
        store: SignerStore::open(dir.join(format!("party{party_id}"))).unwrap(),
        relay_url: relay_url.to_owned(),
        relay_tls: tls.ws_client_config().unwrap(),
        ttl: Duration::from_secs(10),
        op: tokio::sync::Mutex::new(()),
        policy,
    })
}

// The JoinHandle is the kill switch for the cosigner-down step. mTLS since M8:
// the task owns its Arc'd materials (serve_mtls borrows across an await).
async fn spawn_cosigner(
    state: Arc<CosignerState>,
    tls: Arc<TlsMaterials>,
) -> (Url, tokio::task::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        serve_mtls(listener, cosigner_router(state), &tls)
            .await
            .unwrap()
    });
    // trailing slash: RemoteBackend joins "dkg"/"sign" onto this base (remote.rs)
    (Url::parse(&format!("https://{addr}/")).unwrap(), handle)
}

fn api_router(urls: &[Url; 2], active: Option<Address>, tls: &TlsMaterials) -> Router {
    let provider = sovra_eth::http_provider("http://127.0.0.1:9") // dummy, sign never touches RPC
        .unwrap()
        .erased();
    api_router_fn(AppState::new(
        provider,
        RemoteBackend::new(urls[0].clone(), urls[1].clone(), tls).unwrap(),
        active,
    ))
}

// `call`, `unsigned_tx`, `post_json`, `get`, `json` come from test_helpers.

#[tokio::test(flavor = "multi_thread")]
async fn split_flow() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls();
    let relay_url = start_hub(tls.orchestrator.clone()).await;

    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    // party_vks is positional by party id (cosigner state.rs) — 0 gets 1's vk and vice versa
    let (url0, _h0) = spawn_cosigner(
        cosigner_state(0, &sk0, &sk1, dir.path(), &relay_url, &tls.cosigners[0]),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, h1) = spawn_cosigner(
        cosigner_state(1, &sk1, &sk0, dir.path(), &relay_url, &tls.cosigners[1]),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = [url0, url1];

    let probe = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();

    // 1. fresh recover: nothing provisioned on either cosigner
    let active = orchestrator::recover_active(&probe, &urls).await.unwrap();
    assert_eq!(active, None);
    let router = api_router(&urls, active, &tls.orchestrator);

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
    let router2 = api_router(&urls, active, &tls.orchestrator);
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
    // connections to cosigner 1 (per-connection tasks outlive the abort).
    let probe2 = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();
    let err = orchestrator::recover_active(&probe2, &urls)
        .await
        .unwrap_err();
    assert!(matches!(err, RecoverError::Transport(_)));

    // 7. cosigner-down sign -> 502 with the generic no-leak body.
    //    Fresh router == fresh RemoteBackend == fresh reqwest pool (same reason),
    //    and a different tx so the digest can't hit any idempotency path.
    let router3 = api_router(&urls, Some(address), &tls.orchestrator);
    let (raw2, _) = unsigned_tx(2_000_000_000);
    let req2 = serde_json::json!({ "unsigned_transaction": raw2.to_string() });
    let (status, body) = call(&router3, post_json("/v1/sign", req2)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        json(&body)["error"].as_str().unwrap(),
        "mpc protocol failed"
    );
}

/// M8 gate: a client that trusts the CA but presents **no identity** is
/// refused at the TLS handshake — a transport error, never an HTTP status —
/// and nothing server-side is touched: the full sign path runs clean right
/// after, proving rejection happened before any handler or op lock.
#[tokio::test(flavor = "multi_thread")]
async fn no_client_cert_is_refused_at_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls();
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let (url0, _h0) = spawn_cosigner(
        cosigner_state(0, &sk0, &sk1, dir.path(), &relay_url, &tls.cosigners[0]),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, _h1) = spawn_cosigner(
        cosigner_state(1, &sk1, &sk0, dir.path(), &relay_url, &tls.cosigners[1]),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = [url0, url1];
    let router = api_router(&urls, None, &tls.orchestrator);

    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    // CA-pinning but identity-less: the handshake itself must fail.
    let ca_pem = std::fs::read(tls.ca_path()).unwrap();
    let anon = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .tls_certs_only([reqwest::Certificate::from_pem(&ca_pem).unwrap()])
        .build()
        .unwrap();
    let refused = anon
        .post(urls[0].join("sign").unwrap())
        .json(&serde_json::json!({}))
        .send()
        .await;
    assert!(
        refused.is_err(),
        "expected a transport error, got {refused:?}"
    );

    // Server untouched by the refused caller: a legitimate sign runs clean.
    let (raw, _) = unsigned_tx(1_000_000_000);
    let req = serde_json::json!({ "unsigned_transaction": raw.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);
}

/// M7 gate, both parties deny: a tx over the value ceiling gets a fast 403
/// attributing the veto to BOTH parties, nothing is signed or cached, and a
/// compliant tx signs right afterwards (every op lock was freed).
#[tokio::test(flavor = "multi_thread")]
async fn policy_deny_names_both_parties_then_compliant_sign_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls();
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);

    // Ceiling between the two test values: 1 gwei passes, 2 gwei violates.
    let ceiling = sovra_policy::Policy {
        max_value_wei: U256::from(1_500_000_000u64),
        ..permissive_policy()
    };
    let (url0, _h0) = spawn_cosigner(
        cosigner_state_with_policy(
            0,
            &sk0,
            &sk1,
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
            ceiling.clone(),
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, _h1) = spawn_cosigner(
        cosigner_state_with_policy(
            1,
            &sk1,
            &sk0,
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
            ceiling,
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = [url0, url1];
    let router = api_router(&urls, None, &tls.orchestrator);

    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    let (raw_over, _) = unsigned_tx(2_000_000_000);
    let req_over = serde_json::json!({ "unsigned_transaction": raw_over.to_string() });
    let (status, body) = call(&router, post_json("/v1/sign", req_over.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let resp = json(&body);
    assert_eq!(resp["error"].as_str().unwrap(), "policy denied");
    let vetoes = resp["vetoes"].as_array().unwrap();
    assert_eq!(vetoes.len(), 2);
    assert_eq!(vetoes[0]["party"], 0);
    assert_eq!(vetoes[1]["party"], 1);
    assert!(
        vetoes[0]["reason"]
            .as_str()
            .unwrap()
            .contains("exceeds ceiling")
    );

    // Nothing was cached for the denied digest: same body, same 403.
    let (status, _) = call(&router, post_json("/v1/sign", req_over)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Locks freed on both parties: a compliant tx signs immediately.
    let (raw_ok, _) = unsigned_tx(1_000_000_000);
    let req_ok = serde_json::json!({ "unsigned_transaction": raw_ok.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", req_ok)).await;
    assert_eq!(status, StatusCode::OK);
}

/// M7 gate, heterogeneous policies: party 0 allows and waits alone in the
/// hub until its ttl runs out; party 1 vetoes. The 403 must blame exactly
/// party 1 — the allowing party's timeout must not mask the veto — and both
/// op locks are free once the response lands.
#[tokio::test(flavor = "multi_thread")]
async fn heterogeneous_policy_veto_names_the_denier() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls();
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);

    let strict = sovra_policy::Policy {
        max_value_wei: U256::from(1_500_000_000u64),
        ..permissive_policy()
    };
    let (url0, _h0) = spawn_cosigner(
        cosigner_state_with_policy(
            0,
            &sk0,
            &sk1,
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
            permissive_policy(), // party 0 allows
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, _h1) = spawn_cosigner(
        cosigner_state_with_policy(
            1,
            &sk1,
            &sk0,
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
            strict, // party 1 vetoes
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = [url0, url1];
    let router = api_router(&urls, None, &tls.orchestrator);

    let (status, _) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);

    // ~10s: the response waits for party 0's ttl expiry (cosigner_state ttl).
    let (raw_over, _) = unsigned_tx(2_000_000_000);
    let req_over = serde_json::json!({ "unsigned_transaction": raw_over.to_string() });
    let (status, body) = call(&router, post_json("/v1/sign", req_over)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let resp = json(&body);
    let vetoes = resp["vetoes"].as_array().unwrap();
    assert_eq!(vetoes.len(), 1);
    assert_eq!(vetoes[0]["party"], 1);

    // Party 0 timed out of its lonely MPC run and freed its lock; party 1
    // freed on deny — a compliant tx now runs the full path on both.
    let (raw_ok, _) = unsigned_tx(1_000_000_000);
    let req_ok = serde_json::json!({ "unsigned_transaction": raw_ok.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", req_ok)).await;
    assert_eq!(status, StatusCode::OK);
}
