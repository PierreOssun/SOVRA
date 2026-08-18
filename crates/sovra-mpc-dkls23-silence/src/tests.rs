use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::SigningKey;
use sl_mpc_mate::coord::SimpleMessageRelay;
use sovra_types::{KeyShare, PubkeySec1};

use crate::{keygen_party, refresh_party, sign_party, types::PartyContext};

/// The recovered verifying key, in the same identity encoding the ceremonies
/// agree on — so "signature recovers to the wallet key" is one comparison.
fn pubkey_of(vk: &k256::ecdsa::VerifyingKey) -> PubkeySec1 {
    PubkeySec1::from_slice(&vk.to_sec1_bytes()).unwrap()
}

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
/// party_idx 1). The signature must recover to the keygen public key.
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
    let (share0, pk0) = r0.unwrap();
    let (_share1, pk1) = r1.unwrap();
    let (share2, pk2) = r2.unwrap();
    assert_eq!(pk0, pk1);
    assert_eq!(pk0, pk2);

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
    assert_eq!(pubkey_of(&vk), pk0);
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

/// The M10 crypto pin: 2-of-3 keygen, party 1's shard is lost, the
/// replacement host has a BRAND-NEW ed25519 identity. All three run the
/// refresh ceremony; the recovered shard signs under the same public key,
/// and a surviving OLD shard can no longer co-sign with the new generation.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_recovers_lost_shard_and_kills_old_generation() {
    let ctxs = contexts(3, 2, B256::from(rand::random::<[u8; 32]>()));

    let coord = SimpleMessageRelay::new();
    let (r0, r1, r2) = tokio::join!(
        keygen_party(&ctxs[0], coord.connect()),
        keygen_party(&ctxs[1], coord.connect()),
        keygen_party(&ctxs[2], coord.connect()),
    );
    let (share0, wallet_pk) = r0.unwrap();
    let (old_share1, _) = r1.unwrap();
    let (share2, _) = r2.unwrap();

    // Party 1's host is rebuilt: fresh identity key, roster updated on all
    // parties (config + restart in production).
    let new_sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
    let refresh_instance = B256::from(rand::random::<[u8; 32]>());
    let mut refresh_ctxs = ctxs;
    for ctx in &mut refresh_ctxs {
        ctx.instance = refresh_instance;
        ctx.party_vks[1] = new_sk1.verifying_key();
    }
    refresh_ctxs[1].signing_key = new_sk1;

    // The lost party's only crypto input besides its id: the wallet pubkey.
    let public_key = crate::compressed_public_key(
        &sl_dkls23::keygen::Keyshare::from_bytes(share0.as_bytes()).unwrap(),
    );

    let coord = SimpleMessageRelay::new();
    let (n0, n1, n2) = tokio::join!(
        refresh_party(
            &refresh_ctxs[0],
            Some(&share0),
            1,
            &public_key,
            coord.connect()
        ),
        refresh_party(&refresh_ctxs[1], None, 1, &public_key, coord.connect()),
        refresh_party(
            &refresh_ctxs[2],
            Some(&share2),
            1,
            &public_key,
            coord.connect()
        ),
    );
    let (new_share0, a0) = n0.unwrap();
    let (new_share1, a1) = n1.unwrap();
    let (_new_share2, a2) = n2.unwrap();
    assert_eq!(a0, wallet_pk, "refresh must not change the public key");
    assert_eq!(a1, wallet_pk);
    assert_eq!(a2, wallet_pk);

    // The RECOVERED shard signs: subset {0, 1} over the new generation.
    let sign_instance = B256::from(rand::random::<[u8; 32]>());
    for ctx in &mut refresh_ctxs {
        ctx.instance = sign_instance;
    }
    let digest = B256::from(rand::random::<[u8; 32]>());
    let coord = SimpleMessageRelay::new();
    let (p0, p1) = tokio::join!(
        sign_party(
            &refresh_ctxs[0],
            &new_share0,
            digest,
            &[0, 1],
            coord.connect()
        ),
        sign_party(
            &refresh_ctxs[1],
            &new_share1,
            digest,
            &[0, 1],
            coord.connect()
        ),
    );
    let (p0, p1) = (p0.unwrap(), p1.unwrap());
    assert_eq!(p0, p1);
    let sig =
        k256::ecdsa::Signature::from_scalars(p0.r.to_be_bytes::<32>(), p0.s.to_be_bytes::<32>())
            .unwrap();
    let recid = k256::ecdsa::RecoveryId::from_byte(p0.y_parity as u8).unwrap();
    let vk =
        k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid).unwrap();
    assert_eq!(pubkey_of(&vk), wallet_pk);

    // The OLD shard is dead: mixing it with a new-generation shard must not
    // yield a signature that recovers to the wallet key. Depending on
    // where the inconsistency surfaces, the run may error, stall, or emit
    // garbage — every one of those outcomes is a pass; a valid signature is
    // the only failure.
    let mixed_instance = B256::from(rand::random::<[u8; 32]>());
    let mut mixed_ctxs = refresh_ctxs.clone();
    for ctx in &mut mixed_ctxs {
        ctx.instance = mixed_instance;
    }
    // Transport identity is orthogonal to shard validity — give the attacker
    // the best case: current roster, current identity, old shard bytes.
    let coord = SimpleMessageRelay::new();
    let mixed = async {
        tokio::join!(
            sign_party(
                &mixed_ctxs[0],
                &new_share0,
                digest,
                &[0, 1],
                coord.connect()
            ),
            sign_party(
                &mixed_ctxs[1],
                &old_share1,
                digest,
                &[0, 1],
                coord.connect()
            ),
        )
    };
    match tokio::time::timeout(Duration::from_secs(3), mixed).await {
        Err(_elapsed) => {} // stall: pass
        Ok((a, b)) => {
            for parts in [a, b].into_iter().flatten() {
                let sig = k256::ecdsa::Signature::from_scalars(
                    parts.r.to_be_bytes::<32>(),
                    parts.s.to_be_bytes::<32>(),
                );
                let recovered = sig.ok().and_then(|sig| {
                    let recid = k256::ecdsa::RecoveryId::from_byte(parts.y_parity as u8)?;
                    k256::ecdsa::VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, recid)
                        .ok()
                });
                if let Some(vk) = recovered {
                    assert_ne!(
                        pubkey_of(&vk),
                        wallet_pk,
                        "an old shard co-signed a valid signature after refresh"
                    );
                }
            }
        }
    }
}
