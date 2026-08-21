//! Relay-plane roundtrips over real mTLS sockets: the envelope hub's mailbox
//! semantics (live delivery, store-and-forward before join, instance
//! isolation, unclaimed-mailbox TTL), plus the handshake negatives that pin
//! the rule that every hub peer must present a project-CA leaf.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use ed25519_dalek::SigningKey;
use sovra_ipc::{
    envelope_client::WsEnvelopeRelay,
    hub::{EnvelopeHub, env_router},
    tls::{TlsMaterials, serve_mtls},
};
use sovra_mpc::{Envelope, EnvelopeRelay, SignedEnvelope, op};

/// One CA + one both-EKU leaf covers every role here: the hub serves with it
/// and both relay clients present it (any project-CA leaf is authorized).
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

async fn start_hub(tls: Arc<TlsMaterials>, unclaimed_ttl: Duration) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let router = env_router(EnvelopeHub::new(unclaimed_ttl));
        serve_mtls(listener, router, &tls).await.unwrap()
    });
    format!("wss://{addr}")
}

const INSTANCE: B256 = B256::repeat_byte(0xE0);

fn signed(from: u8, to: u8, round: u8) -> SignedEnvelope {
    Envelope::broadcast(INSTANCE, op::DKG, round, from, to, vec![round; 8])
        .sign(&SigningKey::from_bytes(&[from + 1; 32]))
}

#[tokio::test]
async fn live_delivery_between_joined_parties() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = format!(
        "{}/env",
        start_hub(tls.clone(), Duration::from_secs(120)).await
    );
    let cfg = tls.ws_client_config().unwrap();

    let mut a = WsEnvelopeRelay::connect(&url, cfg.clone(), INSTANCE, 0)
        .await
        .unwrap();
    let mut b = WsEnvelopeRelay::connect(&url, cfg, INSTANCE, 1)
        .await
        .unwrap();

    a.send(signed(0, 1, 1)).await.unwrap();
    let got = b.recv().await.unwrap();
    assert_eq!(got.env, signed(0, 1, 1).env);
    // The hub is a dumb pipe: what arrives still authenticates end-to-end.
    got.verify(&[SigningKey::from_bytes(&[1; 32]).verifying_key()])
        .unwrap();

    b.send(signed(1, 0, 1)).await.unwrap();
    assert_eq!(a.recv().await.unwrap().env.from, 1);
}

#[tokio::test]
async fn mail_before_join_is_buffered_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = format!(
        "{}/env",
        start_hub(tls.clone(), Duration::from_secs(120)).await
    );
    let cfg = tls.ws_client_config().unwrap();

    let mut a = WsEnvelopeRelay::connect(&url, cfg.clone(), INSTANCE, 0)
        .await
        .unwrap();
    a.send(signed(0, 1, 1)).await.unwrap();
    a.send(signed(0, 1, 2)).await.unwrap();

    // Party 1 joins late — the ceremony's earlier rounds must be waiting.
    let mut b = WsEnvelopeRelay::connect(&url, cfg, INSTANCE, 1)
        .await
        .unwrap();
    assert_eq!(b.recv().await.unwrap().env.round, 1);
    assert_eq!(b.recv().await.unwrap().env.round, 2);
}

#[tokio::test]
async fn instances_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = format!(
        "{}/env",
        start_hub(tls.clone(), Duration::from_secs(120)).await
    );
    let cfg = tls.ws_client_config().unwrap();

    let mut a = WsEnvelopeRelay::connect(&url, cfg.clone(), INSTANCE, 0)
        .await
        .unwrap();
    // Party 1 joined a DIFFERENT ceremony instance.
    let mut b = WsEnvelopeRelay::connect(&url, cfg, B256::repeat_byte(0xE1), 1)
        .await
        .unwrap();

    a.send(signed(0, 1, 1)).await.unwrap();
    let nothing = tokio::time::timeout(Duration::from_millis(300), b.recv()).await;
    assert!(nothing.is_err(), "mail must not cross ceremony instances");
}

#[tokio::test]
async fn unclaimed_mailboxes_are_swept_after_the_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = format!(
        "{}/env",
        start_hub(tls.clone(), Duration::from_millis(200)).await
    );
    let cfg = tls.ws_client_config().unwrap();

    let mut a = WsEnvelopeRelay::connect(&url, cfg.clone(), INSTANCE, 0)
        .await
        .unwrap();
    a.send(signed(0, 1, 1)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Joining is the access that triggers the sweep: the stale mailbox is
    // gone, so nothing is delivered.
    let mut b = WsEnvelopeRelay::connect(&url, cfg, INSTANCE, 1)
        .await
        .unwrap();
    let nothing = tokio::time::timeout(Duration::from_millis(300), b.recv()).await;
    assert!(nothing.is_err(), "stale buffered mail must be swept");
}

/// Server-only TLS would be cryptographically sufficient for the hub (its
/// compromise yields DoS, never a signature) — the client-cert requirement is
/// what closes the port to certless local processes.
#[tokio::test]
async fn no_client_cert_is_refused() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = format!("{}/env", start_hub(tls, Duration::from_secs(120)).await);

    // Trusts the project CA, presents nothing.
    let ca = CertificateDer::from_pem_file(dir.path().join(sovra_certs::CA_CERT_FILE)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let anon = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let refused = WsEnvelopeRelay::connect(&url, Arc::new(anon), INSTANCE, 0).await;
    assert!(refused.is_err(), "expected handshake refusal");
}

/// Trust means the project CA, not "any syntactically valid cert": a leaf
/// from a different CA fails the handshake in both directions.
#[tokio::test]
async fn foreign_ca_leaf_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "{}/env",
        start_hub(materials(dir.path()), Duration::from_secs(120)).await
    );

    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = materials(foreign_dir.path());
    let refused =
        WsEnvelopeRelay::connect(&url, foreign.ws_client_config().unwrap(), INSTANCE, 0).await;
    assert!(refused.is_err(), "expected handshake refusal");
}
