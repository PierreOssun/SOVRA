#![allow(dead_code)]
use alloy_consensus::private::alloy_rlp::bytes;
use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sovra_eth::{TxIntent, encode_unsigned, prepare};
use tower::ServiceExt;

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

pub async fn call(router: &Router, req: Request<Body>) -> (StatusCode, bytes::Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}
