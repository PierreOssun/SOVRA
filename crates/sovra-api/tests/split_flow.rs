//! RemoteBackend → HTTP → cosigner routers → WsEnvelopeRelay → hub, plus remote
//! startup recovery and the cosigner-down 502 path. The M9 gate
//! (`split_flow_2of3`) adds subset signing: failover to the cold party,
//! veto-is-never-failover, and cold-party-down restart recovery.

mod test_helpers;
use std::{str::FromStr, sync::Arc, time::Duration};

use alloy_consensus::{
    TxEnvelope, private::alloy_eips::Decodable2718, transaction::SignerRecoverable,
};
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use axum::{Router, http::StatusCode};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sovra_api::{
    orchestrator::{self, RecoverError},
    run::build_router as api_router_fn,
    state::AppState,
};
use sovra_cosigner::{run::build_router as cosigner_router, state::CosignerState};
use sovra_ipc::{
    remote::RemoteBackend,
    tls::{TlsMaterials, serve_mtls},
};
use sovra_state::SignerStore;
use sovra_types::PubkeySec1;
use test_helpers::*;
use url::Url;

/// Both identities of a fresh DKG response: the chain-neutral key (what
/// consensus and recovery compare) and its Ethereum address (what signatures
/// recover to).
fn dkg_identities(body: &[u8]) -> (PubkeySec1, Address) {
    let v = json(body);
    (
        PubkeySec1::from_str(v["public_key"].as_str().unwrap()).unwrap(),
        Address::from_str(v["addresses"]["ethereum"].as_str().unwrap()).unwrap(),
    )
}

// copied from cosigner_flow.rs; the hub rides the orchestrator's materials,
// mirroring run.rs
async fn start_hub(tls: Arc<TlsMaterials>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let router = sovra_ipc::hub::env_router(sovra_ipc::hub::EnvelopeHub::default());
        serve_mtls(listener, router, &tls).await.unwrap()
    });
    format!("wss://{addr}/env")
}

/// Wide-open policy for the pre-M7 scenarios; deny cases build their own.
fn permissive_policy() -> sovra_policy::Policy {
    sovra_policy::Policy {
        allowed_chain_ids: vec![11155111],
        allowed_recipients: sovra_policy::Recipients::Any,
        max_value_wei: U256::MAX,
        allow_calldata: false,
        allow_contract_creation: false,
    }
}

// adapted from cosigner_flow.rs::two_cosigners — one state, not a pair; the
// full roster is shared, so the same helper serves 2-of-2 and 2-of-3
fn cosigner_state(
    party_id: u8,
    roster: &[VerifyingKey],
    sk: &SigningKey,
    dir: &std::path::Path,
    relay_url: &str,
    tls: &TlsMaterials,
) -> Arc<CosignerState> {
    cosigner_state_with_policy(
        party_id,
        roster,
        sk,
        dir,
        relay_url,
        tls,
        permissive_policy(),
    )
}

#[allow(clippy::too_many_arguments)]
fn cosigner_state_with_policy(
    party_id: u8,
    roster: &[VerifyingKey],
    sk: &SigningKey,
    dir: &std::path::Path,
    relay_url: &str,
    tls: &TlsMaterials,
    policy: sovra_policy::Policy,
) -> Arc<CosignerState> {
    Arc::new(CosignerState {
        party_id,
        signing_key: sk.clone(),
        roster: Some(roster.to_vec()),
        threshold: 2,
        store: SignerStore::open(dir.join(format!("party{party_id}"))).unwrap(),
        relay_url: relay_url.to_owned(),
        relay_tls: tls.ws_client_config().unwrap(),
        ttl: Duration::from_secs(10),
        op: tokio::sync::Mutex::new(()),
        policy,
    })
}

// The JoinHandle is the kill switch for the cosigner-down steps. mTLS since M8:
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

fn api_router(cosigners: &[(u8, Url)], active: Option<PubkeySec1>, tls: &TlsMaterials) -> Router {
    let provider = sovra_eth::http_provider("http://127.0.0.1:9") // dummy, sign never touches RPC
        .unwrap()
        .erased();
    api_router_fn(AppState::new(
        provider,
        RemoteBackend::new(cosigners.to_vec(), 2, tls).unwrap(),
        active,
    ))
}

fn keys(n: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let sks: Vec<SigningKey> = (0..n)
        .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
        .collect();
    let vks = sks.iter().map(|sk| sk.verifying_key()).collect();
    (sks, vks)
}

// `call`, `unsigned_tx`, `post_json`, `get`, `json` come from test_helpers.

#[tokio::test(flavor = "multi_thread")]
async fn split_flow() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls(2);
    let relay_url = start_hub(tls.orchestrator.clone()).await;

    let (sks, roster) = keys(2);
    let (url0, _h0) = spawn_cosigner(
        cosigner_state(
            0,
            &roster,
            &sks[0],
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, h1) = spawn_cosigner(
        cosigner_state(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = vec![(0u8, url0), (1u8, url1)];

    let probe = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();

    // 1. fresh recover: nothing provisioned on either cosigner
    let active = orchestrator::recover_active(&probe, &urls, 2)
        .await
        .unwrap();
    assert_eq!(active, None);
    let router = api_router(&urls, active, &tls.orchestrator);

    // 2. dkg through the full stack; the pubkey cross-check runs inside RemoteBackend
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let (public_key, address) = dkg_identities(&body);

    let (status, body) = call(&router, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Address::from_str(json(&body)["addresses"]["ethereum"].as_str().unwrap()).unwrap(),
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
        Address::from_str(resp["signer_address"].as_str().unwrap()).unwrap(),
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
    let active = orchestrator::recover_active(&probe, &urls, 2)
        .await
        .unwrap();
    assert_eq!(active, Some(public_key));
    let router2 = api_router(&urls, active, &tls.orchestrator);
    let (status, body) = call(&router2, get("/v1/dkg")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        Address::from_str(json(&body)["addresses"]["ethereum"].as_str().unwrap()).unwrap(),
        address
    );
    // fresh idempotency cache -> MPC re-runs through the split path on reloaded shards
    let (status, _) = call(&router2, post_json("/v1/sign", req)).await;
    assert_eq!(status, StatusCode::OK);

    // 6. kill cosigner 1 and wait for the accept loop (and its listener) to be gone
    h1.abort();
    let _ = h1.await;

    // recovery refuses to answer below the threshold (n=2, t=2: one party
    // down IS below threshold — no cold party to fall back on).
    // Fresh client on purpose: `probe`'s keep-alive pool still holds live
    // connections to cosigner 1 (per-connection tasks outlive the abort).
    let probe2 = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();
    let err = orchestrator::recover_active(&probe2, &urls, 2)
        .await
        .unwrap_err();
    assert!(matches!(err, RecoverError::Transport { .. }));

    // 7. cosigner-down sign -> 502 with the generic no-leak body.
    //    Fresh router == fresh RemoteBackend == fresh reqwest pool (same reason),
    //    and a different tx so the digest can't hit any idempotency path.
    let router3 = api_router(&urls, Some(public_key), &tls.orchestrator);
    let (raw2, _) = unsigned_tx(2_000_000_000);
    let req2 = serde_json::json!({ "unsigned_transaction": raw2.to_string() });
    let (status, body) = call(&router3, post_json("/v1/sign", req2)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        json(&body)["error"].as_str().unwrap(),
        "mpc protocol failed"
    );
}

/// M9 gate: 2-of-3 with the cold recovery party. One narrative flow:
/// dkg over all three → sign via the preferred pair → cosigner1 dies →
/// failover signs via {0, 2} → a respawned cosigner1's veto is final (no
/// re-selection around a policy denial) → restart recovery tolerates the
/// cold party being down but refuses below threshold.
#[tokio::test(flavor = "multi_thread")]
async fn split_flow_2of3() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls(3);
    let relay_url = start_hub(tls.orchestrator.clone()).await;

    let (sks, roster) = keys(3);
    let (url0, _h0) = spawn_cosigner(
        cosigner_state(
            0,
            &roster,
            &sks[0],
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, h1) = spawn_cosigner(
        cosigner_state(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let (url2, h2) = spawn_cosigner(
        cosigner_state(
            2,
            &roster,
            &sks[2],
            dir.path(),
            &relay_url,
            &tls.cosigners[2],
        ),
        tls.cosigners[2].clone(),
    )
    .await;
    let urls = vec![(0u8, url0), (1u8, url1), (2u8, url2)];

    let probe = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();

    // 1. fresh recover: nothing provisioned anywhere
    let active = orchestrator::recover_active(&probe, &urls, 2)
        .await
        .unwrap();
    assert_eq!(active, None);
    let router = api_router(&urls, active, &tls.orchestrator);

    // 2. dkg needs ALL THREE parties (and passes the /roster pre-flight);
    //    RemoteBackend enforces three-way pubkey consensus
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let (public_key, address) = dkg_identities(&body);

    // 3. all parties up: the preferred pair {0, 1} signs
    let (raw1, _) = unsigned_tx(1_000_000_000);
    let req1 = serde_json::json!({ "unsigned_transaction": raw1.to_string() });
    let (status, body) = call(&router, post_json("/v1/sign", req1)).await;
    assert_eq!(status, StatusCode::OK);
    let signed = Bytes::from_str(json(&body)["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // 4. failover: cosigner1 dies, the cold party is drawn in — only {0, 2}
    //    can have produced this signature. Fresh router = fresh reqwest pool
    //    (keep-alive connections outlive the abort).
    h1.abort();
    let _ = h1.await;
    let router2 = api_router(&urls, Some(public_key), &tls.orchestrator);
    let (raw2, _) = unsigned_tx(2_000_000_000);
    let req2 = serde_json::json!({ "unsigned_transaction": raw2.to_string() });
    let (status, body) = call(&router2, post_json("/v1/sign", req2)).await;
    assert_eq!(status, StatusCode::OK);
    let signed = Bytes::from_str(json(&body)["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // 5. veto is never failover (the M9 security gate): cosigner1 comes back
    //    on a new port, same store, but with a value ceiling; 0 and 2 stay
    //    permissive. The over-ceiling tx MUST 403 blaming exactly party 1 —
    //    a 200 here would mean the orchestrator re-selected {0, 2} to route
    //    around the veto, which is a policy bypass.
    let ceiling = sovra_policy::Policy {
        max_value_wei: U256::from(2_500_000_000u64),
        ..permissive_policy()
    };
    let (url1b, h1b) = spawn_cosigner(
        cosigner_state_with_policy(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
            ceiling,
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls_b = vec![
        (0u8, urls[0].1.clone()),
        (1u8, url1b),
        (2u8, urls[2].1.clone()),
    ];
    let router3 = api_router(&urls_b, Some(public_key), &tls.orchestrator);
    // ~10s: party 0 allows and waits out its lonely run's ttl; party 1 vetoes.
    let (raw3, _) = unsigned_tx(3_000_000_000);
    let req3 = serde_json::json!({ "unsigned_transaction": raw3.to_string() });
    let (status, body) = call(&router3, post_json("/v1/sign", req3)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let resp = json(&body);
    assert_eq!(resp["error"].as_str().unwrap(), "policy denied");
    let vetoes = resp["vetoes"].as_array().unwrap();
    assert_eq!(vetoes.len(), 1);
    assert_eq!(vetoes[0]["party"], 1);

    // Locks freed everywhere: an under-ceiling tx signs via {0, 1} again.
    let (raw4, _) = unsigned_tx(2_000_000_000);
    let req4 = serde_json::json!({ "unsigned_transaction": raw4.to_string() });
    let (status, _) = call(&router3, post_json("/v1/sign", req4)).await;
    assert_eq!(status, StatusCode::OK);

    // 6. restart recovery tolerates the cold party being down (any t
    //    reachable + consistent), refuses below threshold.
    h2.abort();
    let _ = h2.await;
    let probe2 = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();
    let active = orchestrator::recover_active(&probe2, &urls_b, 2)
        .await
        .unwrap();
    assert_eq!(active, Some(public_key));

    h1b.abort();
    let _ = h1b.await;
    let probe3 = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();
    let err = orchestrator::recover_active(&probe3, &urls_b, 2)
        .await
        .unwrap_err();
    assert!(matches!(err, RecoverError::Transport { .. }));
}

/// M10 gate: full-stack recovery re-share with a cold, SEALED cloud shard.
/// One narrative flow: dkg-3 (cosigner2's store is XChaCha-sealed) → sign →
/// party 1's host is destroyed → rebuilt with a NEW identity → rosters
/// updated everywhere (config + restart, played by respawning) → startup
/// The recovery model end-to-end: 2 active shards + 1 sleeping. Proactive
/// refresh (POST /v1/recover) rotates every shard under the SAME address; a
/// LOST shard is not healed — signing falls back to the surviving subset
/// (selection skips dead/unprovisioned parties), refresh refuses, and
/// migration is a store wipe + fresh DKG at a NEW address.
#[tokio::test(flavor = "multi_thread")]
async fn recover_flow_2of3() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls(3);
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let (sks, roster) = keys(3);
    let seal_key = [9u8; 32];

    // cosigner2 = the cloud party: same state shape, sealed store.
    let sealed_state = |sk: &SigningKey, roster: &[VerifyingKey]| {
        Arc::new(CosignerState {
            party_id: 2,
            signing_key: sk.clone(),
            roster: Some(roster.to_vec()),
            threshold: 2,
            store: SignerStore::open_with_sealer(
                dir.path().join("party2"),
                Box::new(sovra_state::XChaChaSealer::new(&seal_key)),
            )
            .unwrap(),
            relay_url: relay_url.clone(),
            relay_tls: tls.cosigners[2].ws_client_config().unwrap(),
            ttl: Duration::from_secs(10),
            op: tokio::sync::Mutex::new(()),
            policy: permissive_policy(),
        })
    };

    let (url0, h0) = spawn_cosigner(
        cosigner_state(
            0,
            &roster,
            &sks[0],
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, h1) = spawn_cosigner(
        cosigner_state(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let (url2, h2) = spawn_cosigner(sealed_state(&sks[2], &roster), tls.cosigners[2].clone()).await;
    let urls = vec![(0u8, url0), (1u8, url1), (2u8, url2)];

    // 1. dkg + a first signature, and the cloud shard really is sealed.
    let router = api_router(&urls, None, &tls.orchestrator);
    let (status, body) = call(&router, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let (public_key, address) = dkg_identities(&body);
    let (raw1, _) = unsigned_tx(1_000_000_000);
    let req1 = serde_json::json!({ "unsigned_transaction": raw1.to_string() });
    let (status, _) = call(&router, post_json("/v1/sign", req1)).await;
    assert_eq!(status, StatusCode::OK);
    let sealed_shard = std::fs::read(dir.path().join("party2").join("default/shard.bin")).unwrap();
    assert!(
        sealed_shard.starts_with(b"SVR1"),
        "cloud shard must be sealed at rest"
    );

    // 2. Proactive refresh: same address comes back, the refreshed
    //    generation signs, and the sealed cloud shard actually rotated
    //    (still sealed, different ciphertext).
    let (status, body) = call(&router, post_json("/v1/recover", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        Address::from_str(json(&body)["addresses"]["ethereum"].as_str().unwrap()).unwrap(),
        address
    );
    let resealed = std::fs::read(dir.path().join("party2").join("default/shard.bin")).unwrap();
    assert!(resealed.starts_with(b"SVR1"));
    assert_ne!(resealed, sealed_shard, "cloud shard must have been rotated");
    let (raw2, _) = unsigned_tx(2_000_000_000);
    let req2 = serde_json::json!({ "unsigned_transaction": raw2.to_string() });
    let (status, body) = call(&router, post_json("/v1/sign", req2)).await;
    assert_eq!(status, StatusCode::OK);
    let signed = Bytes::from_str(json(&body)["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // 3. Disaster: party 1's host is gone — process dead, disk wiped. It is
    //    NOT healed: the surviving pair carries the wallet.
    h1.abort();
    let _ = h1.await;
    std::fs::remove_dir_all(dir.path().join("party1")).unwrap();

    // 4. Orchestrator restart mid-incident: startup succeeds on the
    //    surviving t-quorum, and signing falls back to subset {0, 2} —
    //    selection skips the dead party (this is the degraded mode the
    //    2-active + 1-sleeping topology is designed around).
    let probe = tls
        .orchestrator
        .http_client(Duration::from_secs(5))
        .unwrap();
    let active = orchestrator::recover_active(&probe, &urls, 2)
        .await
        .unwrap();
    assert_eq!(active, Some(public_key));
    let router2 = api_router(&urls, active, &tls.orchestrator);
    let (raw3, _) = unsigned_tx(3_000_000_000);
    let req3 = serde_json::json!({ "unsigned_transaction": raw3.to_string() });
    let (status, body) = call(&router2, post_json("/v1/sign", req3)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let signed = Bytes::from_str(json(&body)["signed_transaction"].as_str().unwrap()).unwrap();
    let envelope = TxEnvelope::decode_2718(&mut signed.as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), address);

    // 5. Refresh refuses in degraded mode: it needs all n parties online
    //    with shards — a lost shard is a migration, not a refresh.
    let (status, _) = call(&router2, post_json("/v1/recover", serde_json::json!({}))).await;
    assert!(
        !status.is_success(),
        "refresh must refuse while a party is lost"
    );

    // 6. Migration: wipe every store, respawn the fleet (same identities and
    //    roster — only the shards are gone), fresh DKG → a NEW address.
    //    In production this is where funds move from the old address.
    for h in [h0, h2] {
        h.abort();
        let _ = h.await;
    }
    for party_dir in ["party0", "party1", "party2"] {
        let _ = std::fs::remove_dir_all(dir.path().join(party_dir));
    }
    let (url0b, _h0b) = spawn_cosigner(
        cosigner_state(
            0,
            &roster,
            &sks[0],
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1b, _h1b) = spawn_cosigner(
        cosigner_state(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let (url2b, _h2b) =
        spawn_cosigner(sealed_state(&sks[2], &roster), tls.cosigners[2].clone()).await;
    let urls_b = vec![(0u8, url0b), (1u8, url1b), (2u8, url2b)];

    let router3 = api_router(&urls_b, None, &tls.orchestrator);
    let (status, body) = call(&router3, post_json("/v1/dkg", serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let (new_public_key, new_address) = dkg_identities(&body);
    assert_ne!(new_public_key, public_key, "migration mints a new key");
    assert_ne!(new_address, address);
}

/// M8 gate: a client that trusts the CA but presents **no identity** is
/// refused at the TLS handshake — a transport error, never an HTTP status —
/// and nothing server-side is touched: the full sign path runs clean right
/// after, proving rejection happened before any handler or op lock.
#[tokio::test(flavor = "multi_thread")]
async fn no_client_cert_is_refused_at_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let tls = test_tls(2);
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let (sks, roster) = keys(2);
    let (url0, _h0) = spawn_cosigner(
        cosigner_state(
            0,
            &roster,
            &sks[0],
            dir.path(),
            &relay_url,
            &tls.cosigners[0],
        ),
        tls.cosigners[0].clone(),
    )
    .await;
    let (url1, _h1) = spawn_cosigner(
        cosigner_state(
            1,
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = vec![(0u8, url0), (1u8, url1)];
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
        .post(urls[0].1.join("sign").unwrap())
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
    let tls = test_tls(2);
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let (sks, roster) = keys(2);

    // Ceiling between the two test values: 1 gwei passes, 2 gwei violates.
    let ceiling = sovra_policy::Policy {
        max_value_wei: U256::from(1_500_000_000u64),
        ..permissive_policy()
    };
    let (url0, _h0) = spawn_cosigner(
        cosigner_state_with_policy(
            0,
            &roster,
            &sks[0],
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
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
            ceiling,
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = vec![(0u8, url0), (1u8, url1)];
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
    let tls = test_tls(2);
    let relay_url = start_hub(tls.orchestrator.clone()).await;
    let (sks, roster) = keys(2);

    let strict = sovra_policy::Policy {
        max_value_wei: U256::from(1_500_000_000u64),
        ..permissive_policy()
    };
    let (url0, _h0) = spawn_cosigner(
        cosigner_state_with_policy(
            0,
            &roster,
            &sks[0],
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
            &roster,
            &sks[1],
            dir.path(),
            &relay_url,
            &tls.cosigners[1],
            strict, // party 1 vetoes
        ),
        tls.cosigners[1].clone(),
    )
    .await;
    let urls = vec![(0u8, url0), (1u8, url1)];
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
