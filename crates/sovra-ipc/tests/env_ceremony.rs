//! The MC7 de-risk for the cosigner swap: a full DKG and a subset sign run
//! by the carbon backend over [`WsEnvelopeRelay`] and the real mTLS hub —
//! the same path production cosigners will drive, including the
//! multi-hundred-KB OT frames that never touched a socket in the crate-local
//! `MemoryHub` tests.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use ed25519_dalek::SigningKey;
use sovra_ipc::{
    envelope_client::WsEnvelopeRelay,
    hub::{EnvelopeHub, env_router},
    tls::{TlsMaterials, serve_mtls},
};
use sovra_mpc::{PartyContext, PartyRunner};
use sovra_mpc_dkls23_carbon::CarbonRunner;

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

fn contexts(threshold: u8, n: u8, instance: B256) -> Vec<PartyContext> {
    let keys: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let vks = keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>();
    keys.into_iter()
        .enumerate()
        .map(|(i, signing_key)| PartyContext {
            party_id: i as u8,
            instance,
            signing_key,
            party_vks: vks.clone(),
            threshold,
            ttl: Duration::from_secs(30),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn dkg_then_subset_sign_over_the_ws_hub() {
    let dir = tempfile::tempdir().unwrap();
    let tls = materials(dir.path());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let hub_tls = tls.clone();
    tokio::spawn(async move {
        serve_mtls(listener, env_router(EnvelopeHub::default()), &hub_tls)
            .await
            .unwrap()
    });
    let url = format!("wss://{addr}/env");
    let cfg = tls.ws_client_config().unwrap();

    // DKG: all three parties over real sockets.
    let dkg_instance = B256::repeat_byte(0xC7);
    let ctxs = contexts(2, 3, dkg_instance);
    let mut tasks = Vec::new();
    for ctx in ctxs.clone() {
        let url = url.clone();
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let mut relay = WsEnvelopeRelay::connect(&url, cfg, ctx.instance, ctx.party_id)
                .await
                .unwrap();
            CarbonRunner.keygen(&ctx, &mut relay).await
        }));
    }
    let mut shares = Vec::new();
    let mut pks = Vec::new();
    for t in tasks {
        let (share, pk) = t.await.unwrap().expect("dkg completes over ws");
        shares.push(share);
        pks.push(pk);
    }
    assert!(pks.iter().all(|pk| *pk == pks[0]), "pk consensus over ws");

    // Sign with the non-prefix subset {0, 2} on a fresh instance.
    let sign_instance = B256::repeat_byte(0xC8);
    let digest = B256::repeat_byte(0xD9);
    let mut tasks = Vec::new();
    for &p in &[0u8, 2] {
        let mut ctx = ctxs[p as usize].clone();
        ctx.instance = sign_instance;
        let share = shares[p as usize].clone();
        let url = url.clone();
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let mut relay = WsEnvelopeRelay::connect(&url, cfg, sign_instance, p)
                .await
                .unwrap();
            CarbonRunner
                .sign(&ctx, &share, digest, &[0, 2], &mut relay)
                .await
        }));
    }
    let mut parts = Vec::new();
    for t in tasks {
        parts.push(t.await.unwrap().expect("sign completes over ws"));
    }
    assert_eq!(parts[0], parts[1], "both signers agree over ws");
}
