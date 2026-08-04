//! Hub roundtrips over real mTLS sockets, plus the handshake negatives that
//! pin the rule: every hub peer must present a project-CA leaf — a certless
//! local process can no longer open `/ws` and spray frames at a live run.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use sl_mpc_mate::message::{AskMsg, InstanceId, MessageTag, MsgId, allocate_message};
use sovra_ipc::{
    client::WsRelay,
    hub::{RelayHub, ws_router},
    tls::{TlsMaterials, serve_mtls},
};

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

fn test_frame() -> (MsgId, Vec<u8>) {
    let id = MsgId::new(
        &InstanceId::from([0u8; 32]),
        &[100],
        None,
        MessageTag::tag(0),
    );
    let frame = allocate_message(&id, 10, 0, &[1, 2, 3, 4, 5]);
    (id, frame)
}

#[tokio::test]
async fn publish_then_ask() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = start_hub(tls.clone()).await;
    let cfg = tls.ws_client_config().unwrap();
    let (mut a, mut b) = (
        WsRelay::connect(&url, cfg.clone()).await.unwrap(),
        WsRelay::connect(&url, cfg).await.unwrap(),
    );
    let (id, frame) = test_frame();
    a.send(frame.clone()).await.unwrap();
    b.send(AskMsg::allocate(&id, 10)).await.unwrap();
    assert_eq!(b.next().await.unwrap(), frame);
}

#[tokio::test]
async fn ask_then_publish_wakes_waiter() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = start_hub(tls.clone()).await;
    let cfg = tls.ws_client_config().unwrap();
    let (mut a, mut b) = (
        WsRelay::connect(&url, cfg.clone()).await.unwrap(),
        WsRelay::connect(&url, cfg).await.unwrap(),
    );
    let (id, frame) = test_frame();
    b.send(frame.clone()).await.unwrap();
    a.send(AskMsg::allocate(&id, 10)).await.unwrap();
    assert_eq!(a.next().await.unwrap(), frame);
}

/// Server-only TLS would be cryptographically sufficient for the hub (its
/// compromise yields DoS, never a signature) — the client-cert requirement is
/// what closes the port to certless local processes.
#[tokio::test]
async fn no_client_cert_is_refused() {
    use rustls::pki_types::{CertificateDer, pem::PemObject};

    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let url = start_hub(tls).await;

    // Trusts the project CA, presents nothing.
    let ca = CertificateDer::from_pem_file(dir.path().join(sovra_certs::CA_CERT_FILE)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca).unwrap();
    let anon = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let refused = WsRelay::connect(&url, Arc::new(anon)).await;
    assert!(refused.is_err(), "expected handshake refusal");
}

/// Trust means the project CA, not "any syntactically valid cert": a leaf
/// from a different CA fails the handshake in both directions.
#[tokio::test]
async fn foreign_ca_leaf_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let url = start_hub(materials(dir.path())).await;

    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = materials(foreign_dir.path());
    let refused = WsRelay::connect(&url, foreign.ws_client_config().unwrap()).await;
    assert!(refused.is_err(), "expected handshake refusal");
}
