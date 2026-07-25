use std::{sync::Arc, time::Duration};

use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use http_body_util::BodyExt;
use serde::{Serialize, de::DeserializeOwned};
use sovra_cosigner::{policy::Policy, run::build_router, state::CosignerState};
use sovra_eth::{TxIntent, encode_unsigned, prepare};
use sovra_ipc::{
    control::*,
    hub::{RelayHub, ws_router},
};
use sovra_state::SignerStore;
use tower::ServiceExt;

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

/// The recipient every test policy allows; txs to anyone else get rejected.
const MERCHANT: Address = Address::new([0x11; 20]);

fn test_policy() -> Policy {
    Policy {
        allowed_recipients: vec![MERCHANT],
        max_value_wei: U256::from(10_000_000_000_000_000u64), // 0.01 ETH
        allowed_chain_ids: vec![11155111],
    }
}

/// An in-policy unsigned tx (raw bytes + the digest the cosigner will derive).
fn unsigned_tx(to: Address, value: U256) -> Bytes {
    let prepared = prepare(TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to,
        value,
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    })
    .unwrap();
    encode_unsigned(&prepared.tx)
}

/// Two cosigners, keys exchanged, pointed at one hub. Returns (router0, router1).
fn two_cosigners(dir: &std::path::Path, relay_url: &str) -> (Router, Router) {
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let mk = |party_id: u8, sk: &SigningKey, peer: &SigningKey| {
        Arc::new(CosignerState {
            party_id,
            signing_key: sk.clone(),
            peer_vk: Some(peer.verifying_key()),
            store: SignerStore::open(dir.join(format!("party{party_id}"))).unwrap(),
            relay_url: relay_url.to_owned(),
            ttl: Duration::from_secs(60),
            op: tokio::sync::Mutex::new(()),
            policy: Some(test_policy()),
        })
    };
    (
        build_router(mk(0, &sk0, &sk1)),
        build_router(mk(1, &sk1, &sk0)),
    )
}

fn post_json(path: &str, body: &impl Serialize) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn json_body<T: DeserializeOwned>(resp: axum::response::Response) -> T {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn joint_dkg_then_sign() {
    let dir = tempfile::tempdir().unwrap();
    let relay_url = start_hub().await;
    let (r0, r1) = two_cosigners(dir.path(), &relay_url);

    // dkg: one instance, both parties, concurrently — RemoteBackend's job, played here by the test
    let dkg = StartDkgRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
    };
    let (a, b) = tokio::join!(
        r0.clone().oneshot(post_json("/dkg", &dkg)),
        r1.clone().oneshot(post_json("/dkg", &dkg)),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::OK);
    let (i0, i1): (SignerInfo, SignerInfo) = (json_body(a).await, json_body(b).await);
    assert_eq!(i0.address, i1.address);

    // sign: fresh instance, same in-policy raw tx, concurrently -> identical
    // SignParts. Each cosigner decodes the payload and derives the digest itself.
    let sign = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: unsigned_tx(MERCHANT, U256::from(1u64)),
    };
    let (a, b) = tokio::join!(
        r0.clone().oneshot(post_json("/sign", &sign)),
        r1.clone().oneshot(post_json("/sign", &sign)),
    );
    let (p0, p1): (SignParts, SignParts) =
        (json_body(a.unwrap()).await, json_body(b.unwrap()).await);
    assert_eq!(p0, p1);

    // second dkg on either party -> 409
    let dkg2 = StartDkgRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
    };
    assert_eq!(
        r0.oneshot(post_json("/dkg", &dkg2)).await.unwrap().status(),
        StatusCode::CONFLICT
    );
}

/// The demo's kill shot, as a gate test: policy rejections happen BEFORE any
/// MPC. Structural proof: these cosigners point at a dead relay URL — if the
/// handler ever dialed the hub before policing, these would 502, not 403.
#[tokio::test(flavor = "multi_thread")]
async fn policy_rejects_before_any_mpc() {
    let dir = tempfile::tempdir().unwrap();
    let (r0, _r1) = two_cosigners(dir.path(), "ws://127.0.0.1:1/ws");

    async fn reject_code(r: &Router, raw: Bytes) -> (StatusCode, String) {
        let req = StartSignRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            unsigned_transaction: raw,
        };
        let resp = r.clone().oneshot(post_json("/sign", &req)).await.unwrap();
        let status = resp.status();
        let body: serde_json::Value = json_body(resp).await;
        (status, body["code"].as_str().unwrap_or_default().to_owned())
    }

    // Hijack beat: 0.04 ETH to a stranger — value AND recipient out of policy
    // (recipient is checked first).
    let stranger = Address::new([0x22; 20]);
    let (status, code) = reject_code(
        &r0,
        unsigned_tx(stranger, U256::from(40_000_000_000_000_000u64)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "recipient_not_allowed");

    // Over-limit value to the allowed merchant.
    let (status, code) = reject_code(
        &r0,
        unsigned_tx(MERCHANT, U256::from(40_000_000_000_000_000u64)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(code, "value_exceeds_limit");

    // Garbage payload: rejected as malformed, again before any MPC.
    let req = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
    };
    let resp = r0.clone().oneshot(post_json("/sign", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

/// No [policy] section = sign nothing: authority must be granted explicitly.
#[tokio::test(flavor = "multi_thread")]
async fn missing_policy_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let r0 = build_router(Arc::new(CosignerState {
        party_id: 0,
        signing_key: sk0.clone(),
        peer_vk: Some(sk1.verifying_key()),
        store: SignerStore::open(dir.path().join("party0")).unwrap(),
        relay_url: "ws://127.0.0.1:1/ws".into(),
        ttl: Duration::from_secs(60),
        op: tokio::sync::Mutex::new(()),
        policy: None,
    }));

    let req = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: unsigned_tx(MERCHANT, U256::from(1u64)),
    };
    let resp = r0.oneshot(post_json("/sign", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["code"], "no_policy_configured");
}
