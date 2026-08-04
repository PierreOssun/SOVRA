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
use sovra_cosigner::{run::build_router, state::CosignerState};
use sovra_ipc::{
    control::*,
    hub::{RelayHub, ws_router},
    tls::{TlsMaterials, serve_mtls},
};
use sovra_state::SignerStore;
use tower::ServiceExt;

/// One CA + one both-EKU leaf covers every role in these tests: the hub
/// serves with it and both cosigners dial with it.
fn materials(dir: &std::path::Path) -> Arc<TlsMaterials> {
    let ca = sovra_certs::ensure_ca(dir).unwrap();
    let leaf = sovra_certs::ensure_leaf(
        dir,
        "party",
        "sovra-party",
        &sovra_certs::default_sans(),
        &ca,
    )
    .unwrap();
    Arc::new(
        TlsMaterials::load(dir.join(sovra_certs::CA_CERT_FILE), &leaf.cert, &leaf.key).unwrap(),
    )
}

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

/// Wide-open policy so pre-M7 scenarios keep exercising the MPC path;
/// deny behavior gets its own dedicated tests.
fn permissive_policy() -> sovra_policy::Policy {
    sovra_policy::Policy {
        allowed_chain_ids: vec![11155111],
        allowed_recipients: sovra_policy::Recipients::Any,
        max_value_wei: U256::MAX,
        allow_calldata: false,
    }
}

/// Two cosigners, keys exchanged, pointed at one hub. Returns (router0, router1).
fn two_cosigners(dir: &std::path::Path, relay_url: &str, tls: &TlsMaterials) -> (Router, Router) {
    let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let mk = |party_id: u8, sk: &SigningKey, peer: &SigningKey| {
        Arc::new(CosignerState {
            party_id,
            signing_key: sk.clone(),
            peer_vk: Some(peer.verifying_key()),
            store: SignerStore::open(dir.join(format!("party{party_id}"))).unwrap(),
            relay_url: relay_url.to_owned(),
            relay_tls: tls.ws_client_config().unwrap(),
            ttl: Duration::from_secs(60),
            op: tokio::sync::Mutex::new(()),
            policy: permissive_policy(),
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

/// A well-formed unsigned EIP-1559 tx — the only thing a cosigner will sign.
fn unsigned_tx_bytes() -> Bytes {
    let prepared = sovra_eth::prepare(sovra_eth::TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Address::repeat_byte(0x11),
        value: U256::from(1u64),
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Bytes::new(),
    })
    .unwrap();
    sovra_eth::encode_unsigned(&prepared.tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn joint_dkg_then_sign() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let relay_url = start_hub(tls.clone()).await;
    let (r0, r1) = two_cosigners(dir.path(), &relay_url, &tls);

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

    // sign: fresh instance, same unsigned tx bytes, concurrently -> identical
    // SignParts (each party decodes and re-derives the digest itself)
    let sign = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: unsigned_tx_bytes(),
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

#[tokio::test(flavor = "multi_thread")]
async fn sign_rejects_undecodable_bytes_before_any_mpc() {
    // Deliberately dead relay URL: if the handler dialed the hub before
    // decoding, this would 502 — a 422 proves rejection happens first.
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let (r0, _r1) = two_cosigners(dir.path(), "wss://127.0.0.1:9/ws", &tls);

    let garbage = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]),
    };
    let resp = r0
        .clone()
        .oneshot(post_json("/sign", &garbage))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // A second attempt gets 422 again, not 409 Busy: the op lock was freed.
    let resp = r0.oneshot(post_json("/sign", &garbage)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_denied_by_policy_before_any_mpc() {
    // Zero ceiling: the 1-wei test tx always violates. peer_vk is None and
    // the store is empty on purpose — a 403 (not 409) proves the veto fires
    // before shard load and peer checks; the dead relay URL proves no dial.
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let state = Arc::new(CosignerState {
        party_id: 0,
        signing_key: sk,
        peer_vk: None,
        store: SignerStore::open(dir.path().join("party0")).unwrap(),
        relay_url: "wss://127.0.0.1:9/ws".into(),
        relay_tls: tls.ws_client_config().unwrap(),
        ttl: Duration::from_secs(10),
        op: tokio::sync::Mutex::new(()),
        policy: sovra_policy::Policy {
            max_value_wei: U256::ZERO,
            ..permissive_policy()
        },
    });
    let router = build_router(state);

    let req = StartSignRequest {
        instance: B256::from(rand::random::<[u8; 32]>()),
        unsigned_transaction: unsigned_tx_bytes(),
    };
    let resp = router
        .clone()
        .oneshot(post_json("/sign", &req))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["error"], "policy denied");
    assert!(body["reason"].as_str().unwrap().contains("exceeds ceiling"));

    // 403 again, not 409 Busy: the op lock was freed on deny.
    let resp = router.oneshot(post_json("/sign", &req)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
