#![allow(dead_code)]
use std::{path::PathBuf, sync::Arc};

use alloy_consensus::private::alloy_rlp::bytes;
use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sovra_eth::{TxIntent, encode_unsigned, prepare};
use sovra_ipc::tls::TlsMaterials;
use tower::ServiceExt;

/// One project CA + a leaf per process, minted into a tempdir — the test-side
/// twin of `cargo xtask certs`. Materials are `Arc` because test servers run
/// in spawned tasks that must own them.
pub struct TestTls {
    /// Keeps the tempdir (and every pem in it) alive for the test's duration.
    pub dir: tempfile::TempDir,
    pub orchestrator: Arc<TlsMaterials>,
    /// Index = party id.
    pub cosigners: Vec<Arc<TlsMaterials>>,
}

impl TestTls {
    /// For clients that should trust the CA but present no identity.
    pub fn ca_path(&self) -> PathBuf {
        self.dir.path().join(sovra_certs::CA_CERT_FILE)
    }
}

pub fn test_tls(n: usize) -> TestTls {
    let dir = tempfile::tempdir().unwrap();
    let ca = sovra_certs::ensure_ca(dir.path()).unwrap();
    let mk = |stem: &str, cn: &str| {
        let leaf =
            sovra_certs::ensure_leaf(dir.path(), stem, cn, &sovra_certs::default_sans(), &ca)
                .unwrap();
        Arc::new(
            TlsMaterials::load(
                dir.path().join(sovra_certs::CA_CERT_FILE),
                &leaf.cert,
                &leaf.key,
            )
            .unwrap(),
        )
    };
    let orchestrator = mk("orchestrator", "sovra-orchestrator");
    let cosigners = (0..n)
        .map(|id| mk(&format!("cosigner{id}"), &format!("sovra-cosigner-{id}")))
        .collect();
    TestTls {
        dir,
        orchestrator,
        cosigners,
    }
}

pub fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

pub fn json(body: &[u8]) -> serde_json::Value {
    serde_json::from_slice(body).unwrap()
}

pub fn unsigned_tx(value: u64) -> (Bytes, B256) {
    let prepared = prepare(TxIntent {
        chain_id: 11155111,
        nonce: 0,
        kind: alloy_primitives::TxKind::Call(Address::from([0x11; 20])),
        value: U256::from(value),
        gas_limit: 21_000,
        data: Default::default(),
        params: sovra_eth::TxParams::Eip1559 {
            max_fee_per_gas: 3,
            max_priority_fee_per_gas: 2,
            access_list: Default::default(),
        },
    })
    .unwrap();
    (encode_unsigned(&prepared.tx), prepared.signing_hash)
}

pub async fn call(router: &Router, req: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}
