//! This party's share of signing one digest with a t-subset, mapping
//! 0xCarbon's session onto three envelope rounds (routing per upstream's
//! `test_sign_session_happy_path`, the de-facto spec):
//!
//! round 1: `SignSession::new`'s transmits, sealed p2p.
//! round 2: phase2's transmits, sealed p2p.
//! round 3: phase3's `Broadcast3to4`, plaintext broadcast.
//! local:   phase4 over ALL broadcasts (own included) → (r, s, recovery id).
//!
//! Unlike sl-dkls23, the subset is expressed in **global** DKG indices —
//! the position-in-subset remap that headlined the silence backend's docs
//! is gone. `y_parity` is derived by trial recovery against the shard's own
//! public key rather than trusting the library's recovery id: its
//! interaction with low-s normalization is undocumented, and recovering to
//! the wallet key doubles as the end-of-ceremony belt check.

use alloy_primitives::{B256, U256};
use dkls23_secp256k1::protocols::{
    sign_session::SignSession,
    signing::{Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3},
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sovra_mpc::{EnvelopeRelay, Exchange, Expect, MpcError, PartyContext, RoundOutbox, op};
use sovra_types::{EcdsaParts, KeyShare};

use crate::{
    convert::{cidx, compress_pk, sidx},
    de, map_abort,
    rounds::{gather, route},
    ser, shard,
};

type Curve = k256::Secp256k1;

pub(crate) async fn sign_party(
    ctx: &PartyContext,
    share: &KeyShare,
    digest: B256,
    subset: &[u8],
    relay: &mut impl EnvelopeRelay,
) -> Result<EcdsaParts, MpcError> {
    // All validation happens before the relay is touched, so a bad subset
    // never opens an MPC session. Strictly ascending = canonical order AND
    // duplicate rejection in one check: every selected party must build the
    // identical subset vector.
    let n = ctx.party_vks.len();
    if !subset.windows(2).all(|w| w[0] < w[1]) || subset.iter().any(|&p| p as usize >= n) {
        return Err(MpcError::Sign(format!(
            "invalid signing subset {subset:?}: must be strictly ascending party ids < {n}"
        )));
    }
    if !subset.contains(&ctx.party_id) {
        return Err(MpcError::Sign(format!(
            "party {} is not in signing subset {subset:?}",
            ctx.party_id
        )));
    }
    // A shard from another generation (different roster or threshold) would
    // otherwise stall the protocol with an opaque timeout — name the mismatch.
    let party = shard::decode_for(share, ctx.party_id, subset.len() as u8, n as u8, op::SIGN)?;

    let data = SignData {
        sign_id: ctx.instance.to_vec(),
        counterparties: subset
            .iter()
            .filter(|&&p| p != ctx.party_id)
            .map(|&p| cidx(p))
            .collect(),
        message_hash: digest.0,
    };
    let (mut session, t1_out) =
        SignSession::<Curve>::new(&party, data).map_err(|a| map_abort(op::SIGN, a))?;
    let mut ex = Exchange::new(relay, ctx, op::SIGN, subset);

    // Rounds 1 and 2 — per-recipient transmits, sealed.
    ex.send_round(
        1,
        RoundOutbox {
            broadcast: None,
            p2p: route(&t1_out, |m| sidx(m.parties.receiver)),
        },
    )
    .await?;
    let received1: Vec<TransmitPhase1to2> = gather(
        &ex.recv_round(1, Expect::P2p).await?.p2p,
        "sign round-1 transmit",
        op::SIGN,
    )?;
    let t2_out = session
        .phase2(&received1)
        .map_err(|a| map_abort(op::SIGN, a))?;

    ex.send_round(
        2,
        RoundOutbox {
            broadcast: None,
            p2p: route(&t2_out, |m| sidx(m.parties.receiver)),
        },
    )
    .await?;
    let received2: Vec<TransmitPhase2to3<Curve>> = gather(
        &ex.recv_round(2, Expect::P2p).await?.p2p,
        "sign round-2 transmit",
        op::SIGN,
    )?;

    // Round 3 — the signature-share broadcast; phase4 needs own included.
    let my_broadcast = session
        .phase3(&received2)
        .map_err(|a| map_abort(op::SIGN, a))?;
    ex.send_round(
        3,
        RoundOutbox {
            broadcast: Some(ser(&my_broadcast)),
            ..Default::default()
        },
    )
    .await?;
    let inbox = ex.recv_round(3, Expect::Broadcasts).await?;
    let mut broadcasts = vec![my_broadcast];
    for (&p, bytes) in &inbox.broadcasts {
        broadcasts.push(de::<Broadcast3to4<Curve>>(
            bytes,
            p,
            "sign round-3 broadcast",
            op::SIGN,
        )?);
    }

    let sig = session
        .phase4(&broadcasts, true)
        .map_err(|a| map_abort(op::SIGN, a))?;

    // Trial recovery: pick the parity that recovers to the wallet key.
    // Doubles as the belt check that (r, s) verifies at all.
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&sig.r);
    rs[32..].copy_from_slice(&sig.s);
    let signature = Signature::from_slice(&rs)
        .map_err(|e| MpcError::Sign(format!("protocol produced a malformed signature: {e}")))?;
    let wallet = VerifyingKey::from_sec1_bytes(compress_pk(&party.pk).as_bytes())
        .expect("a shard's public key is a valid curve point");
    let y_parity = [false, true]
        .into_iter()
        .find(|&odd| {
            VerifyingKey::recover_from_prehash(&digest.0, &signature, RecoveryId::new(odd, false))
                .is_ok_and(|vk| vk == wallet)
        })
        .ok_or_else(|| {
            MpcError::Sign("signature does not recover to the wallet public key".into())
        })?;

    Ok(EcdsaParts {
        r: U256::from_be_slice(&sig.r),
        s: U256::from_be_slice(&sig.s),
        y_parity,
    })
}

#[cfg(test)]
mod tests {
    use sovra_mpc::{MemoryHub, PartyRunner};
    use sovra_types::PubkeySec1;

    use super::*;
    use crate::{CarbonRunner, testutil};

    async fn run_sign(
        ctxs: &[PartyContext],
        shares: &[KeyShare],
        digest: B256,
        subset: &'static [u8],
    ) -> Vec<EcdsaParts> {
        let hub = MemoryHub::new();
        let mut tasks = Vec::new();
        for &p in subset {
            let mut ctx = ctxs[p as usize].clone();
            ctx.instance = B256::repeat_byte(0x51); // fresh instance per ceremony
            let share = shares[p as usize].clone();
            let mut relay = hub.connect(p);
            tasks.push(tokio::spawn(async move {
                CarbonRunner
                    .sign(&ctx, &share, digest, subset, &mut relay)
                    .await
            }));
        }
        let mut out = Vec::new();
        for t in tasks {
            out.push(
                t.await
                    .expect("task not cancelled")
                    .expect("sign completes"),
            );
        }
        out
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dkg_then_subset_sign_recovers_to_the_wallet_key() {
        let ctxs = testutil::contexts(2, 3);
        let results = testutil::run_dkg(ctxs.clone()).await;
        let (shares, pks): (Vec<_>, Vec<PubkeySec1>) = results
            .into_iter()
            .map(|r| r.expect("dkg completes"))
            .unzip();

        // Subset {0, 2}: the non-prefix case that needed a positional remap
        // under sl-dkls23 — global indexing makes it just another subset.
        let digest = B256::repeat_byte(0xE7);
        let parts = run_sign(&ctxs, &shares, digest, &[0, 2]).await;

        assert_eq!(
            parts[0], parts[1],
            "both signers assemble the same signature"
        );
        let p = &parts[0];

        // Independent re-check: (r, s, y_parity) recovers to the DKG key.
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&p.r.to_be_bytes::<32>());
        rs[32..].copy_from_slice(&p.s.to_be_bytes::<32>());
        let signature = Signature::from_slice(&rs).expect("well-formed");
        let recovered = VerifyingKey::recover_from_prehash(
            &digest.0,
            &signature,
            RecoveryId::new(p.y_parity, false),
        )
        .expect("recoverable");
        assert_eq!(
            recovered.to_sec1_bytes().as_ref(),
            pks[0].as_bytes(),
            "signature recovers to the wallet key"
        );
        // EIP-2 low-s: normalizing an already-low-s signature is a no-op.
        assert_eq!(
            signature.normalize_s(),
            signature,
            "s must be low-s already"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sign_rejects_bad_subsets_and_foreign_shards_before_the_relay() {
        let ctxs = testutil::contexts(2, 3);
        let results = testutil::run_dkg(ctxs.clone()).await;
        let shares: Vec<_> = results.into_iter().map(|r| r.unwrap().0).collect();

        let hub = MemoryHub::new();
        let mut relay = hub.connect(0);
        let digest = B256::ZERO;
        let cases: [(&[u8], &str); 4] = [
            (&[2, 0], "not ascending"),
            (&[0, 9], "out of range"),
            (&[1, 2], "missing self"),
            (&[0, 1, 2], "subset larger than shard threshold"),
        ];
        for (subset, why) in cases {
            let err = CarbonRunner
                .sign(&ctxs[0], &shares[0], digest, subset, &mut relay)
                .await
                .unwrap_err();
            assert!(
                matches!(err, MpcError::Sign(_)),
                "{why}: unexpected error {err:?}"
            );
        }
    }
}
