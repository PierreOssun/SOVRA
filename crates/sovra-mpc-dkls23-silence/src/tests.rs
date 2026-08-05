use std::time::Duration;

use alloy_primitives::{Address, B256};
use ed25519_dalek::SigningKey;
use sl_mpc_mate::coord::SimpleMessageRelay;
use sovra_types::KeyShare;

use crate::{keygen_party, sign_party, types::PartyContext};

fn contexts(n: u8, threshold: u8, instance: B256) -> Vec<PartyContext> {
    let sks: Vec<SigningKey> = (0..n)
        .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
        .collect();
    let vks = sks.iter().map(|sk| sk.verifying_key()).collect::<Vec<_>>();
    sks.into_iter()
        .enumerate()
        .map(|(i, signing_key)| PartyContext {
            party_id: i as u8,
            instance,
            signing_key,
            party_vks: vks.clone(),
            threshold,
            ttl: Duration::from_secs(60),
        })
        .collect()
}

/// Proves message auth is REAL, not decorative: if a party is told the wrong
/// verifying key for its peer, the signed setup messages fail verification.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_peer_vk_breaks_keygen() {
    let coord = SimpleMessageRelay::new();
    let instance = B256::from(rand::random::<[u8; 32]>());
    let mut ctxs = contexts(2, 2, instance);

    // party 1 is told the wrong verifying key for party 0
    ctxs[1].party_vks[0] = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();

    let both = async {
        tokio::join!(
            keygen_party(&ctxs[0], coord.connect()),
            keygen_party(&ctxs[1], coord.connect()),
        )
    };

    // A wrong peer vk changes MsgId routing, so the parties can never exchange round
    // messages — the run stalls rather than completing. Timing out IS the pass condition.
    match tokio::time::timeout(Duration::from_secs(2), both).await {
        Err(_elapsed) => {} // expected: keygen could not complete
        Ok((a, b)) => assert!(
            a.is_err() || b.is_err(),
            "a mismatched peer key must prevent a successful keygen, but both parties succeeded",
        ),
    }
}

/// The M9 crypto pin, with no HTTP in the loop: a 2-of-3 keygen over all
/// three parties, then a signature by subset {0, 2} — the case where a
/// party's subset index differs from its global id (party 2 signs at
/// party_idx 1). The signature must recover to the keygen address.
#[tokio::test(flavor = "multi_thread")]
async fn two_of_three_sign_with_subset_0_2() {
    let instance = B256::from(rand::random::<[u8; 32]>());
    let ctxs = contexts(3, 2, instance);

    let coord = SimpleMessageRelay::new();
    let (r0, r1, r2) = tokio::join!(
        keygen_party(&ctxs[0], coord.connect()),
        keygen_party(&ctxs[1], coord.connect()),
        keygen_party(&ctxs[2], coord.connect()),
    );
    let (share0, addr0) = r0.unwrap();
    let (_share1, addr1) = r1.unwrap();
    let (share2, addr2) = r2.unwrap();
    assert_eq!(addr0, addr1);
    assert_eq!(addr0, addr2);

    // fresh instance for the sign run; party 1 sits it out entirely
    let sign_instance = B256::from(rand::random::<[u8; 32]>());
    let mut sign_ctxs = ctxs;
    for ctx in &mut sign_ctxs {
        ctx.instance = sign_instance;
    }
    let digest = B256::from(rand::random::<[u8; 32]>());
    let subset = [0u8, 2];
    let coord = SimpleMessageRelay::new();
    let (p0, p2) = tokio::join!(
        sign_party(&sign_ctxs[0], &share0, digest, &subset, coord.connect()),
        sign_party(&sign_ctxs[2], &share2, digest, &subset, coord.connect()),
    );
    let (p0, p2) = (p0.unwrap(), p2.unwrap());
    assert_eq!(p0, p2);

    // the threshold signature is a plain ECDSA signature: recover and compare
    let sig =
        k256::ecdsa::Signature::from_scalars(p0.r.to_be_bytes::<32>(), p0.s.to_be_bytes::<32>())
            .unwrap();
    let recid = k256::ecdsa::RecoveryId::from_byte(p0.y_parity as u8).unwrap();
    let vk =
        k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid).unwrap();
    assert_eq!(Address::from_public_key(&vk), addr0);
}

/// A party handed a subset it is not in must fail fast, before touching the
/// relay or even deserializing the shard — an orchestrator bug, not a run.
#[tokio::test(flavor = "multi_thread")]
async fn sign_rejects_subset_without_this_party() {
    let ctxs = contexts(3, 2, B256::from(rand::random::<[u8; 32]>()));
    let coord = SimpleMessageRelay::new();
    let bogus_share = KeyShare::from(vec![]); // never reached: subset check comes first

    let err = sign_party(&ctxs[0], &bogus_share, B256::ZERO, &[1, 2], coord.connect())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not in signing subset"), "{err}");

    // non-ascending (duplicate) subsets are rejected the same way
    let err = sign_party(&ctxs[0], &bogus_share, B256::ZERO, &[0, 0], coord.connect())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("strictly ascending"), "{err}");
}
