//! Pins the seam between provisioning (sovra-certs) and runtime (tls.rs):
//! freshly minted material must load and build every per-plane config. This is
//! where a single-EKU leaf or a rustls provider clash would first explode —
//! better here than as an opaque handshake alert mid-flow.

use std::time::Duration;

use sovra_ipc::tls::TlsMaterials;

fn materials(dir: &std::path::Path) -> TlsMaterials {
    let ca = sovra_certs::ensure_ca(dir).expect("ensure_ca");
    let leaf = sovra_certs::ensure_leaf(
        dir,
        "cosigner0",
        "sovra-cosigner-0",
        &sovra_certs::default_sans(),
        &ca,
    )
    .expect("ensure_leaf");
    TlsMaterials::load(dir.join(sovra_certs::CA_CERT_FILE), &leaf.cert, &leaf.key)
        .expect("materials load")
}

#[tokio::test]
async fn minted_material_builds_every_config() {
    let dir = tempfile::tempdir().unwrap();
    let m = materials(dir.path());
    m.server_config().expect("server config");
    m.ws_client_config().expect("ws client config");
    m.http_client(Duration::from_secs(5)).expect("http client");
}

/// Startup is the only caller of `load` — a missing file must fail with the
/// offending path in the message (the fail-closed precedent from the policy
/// loader), not surface later as a handshake error.
#[test]
fn missing_material_fails_with_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.pem");
    let err = TlsMaterials::load(&missing, &missing, &missing)
        .err()
        .expect("expected an error");
    assert!(err.to_string().contains("nope.pem"), "{err}");
}

/// A present-but-garbage file is the other startup failure mode (truncated
/// copy, wrong file shipped to the box) — same rule: refuse with the path.
#[test]
fn malformed_material_fails_with_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = dir.path().join("garbage.pem");
    std::fs::write(&garbage, b"not pem at all").unwrap();
    let err = TlsMaterials::load(&garbage, &garbage, &garbage)
        .err()
        .expect("expected an error");
    assert!(err.to_string().contains("garbage.pem"), "{err}");
}
