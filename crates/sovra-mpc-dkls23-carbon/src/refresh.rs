//! This party's share of the all-parties proactive refresh: every party
//! brings its shard, every shard is replaced, the public key is unchanged.
//! There is no lost-party role — recovery is a product flow (sign with the
//! surviving subset, fresh DKG, migrate funds), not a protocol operation.
//!
//! 0xCarbon's `refresh_complete_*` phases are DKG-shaped minus the BIP-32
//! derivation (each party deals a zero-constant polynomial; the corrections
//! sum to the zero point, which phase4 verifies), so the round mapping
//! mirrors `keygen.rs`:
//!
//! round 1: zero-polynomial Shamir fragments, sealed p2p; own kept.
//! round 2: `ProofCommitment` broadcast, zero-share transmits sealed p2p.
//! round 3: zero-share + mul transmits (big OT payloads), sealed p2p only.
//! local:   phase4 → the refreshed `Party`; old shards are dead.

use dkls23_secp256k1::protocols::dkg::ProofCommitment;
use sovra_mpc::{EnvelopeRelay, Exchange, Expect, MpcError, PartyContext, RoundOutbox, op};
use sovra_types::{KeyShare, PubkeySec1};

use crate::{
    convert::{compress_pk, scheme, sidx},
    de, map_abort,
    rounds::{gather, gather_zero_mul, route, route_zero_mul, share_fragments},
    ser, shard,
};

type Curve = k256::Secp256k1;

pub(crate) async fn refresh_party(
    ctx: &PartyContext,
    share: &KeyShare,
    public_key: &PubkeySec1,
    relay: &mut impl EnvelopeRelay,
) -> Result<(KeyShare, PubkeySec1), MpcError> {
    let (params, _) = scheme(ctx)?;
    let me = ctx.party_id;
    let party = shard::decode_for(share, me, ctx.threshold, params.share_count, op::REFRESH)?;
    // The operator-supplied anchor: a wrong expected key fails before the
    // relay is touched instead of corrupting anything.
    if compress_pk(&party.pk) != *public_key {
        return Err(MpcError::PartyMismatch(
            "expected public key does not match this party's shard".into(),
        ));
    }
    let sid = ctx.instance.to_vec();
    let all: Vec<u8> = (0..params.share_count).collect();
    let mut ex = Exchange::new(relay, ctx, op::REFRESH, &all);

    // Round 1 — zero-constant fragments.
    let poly_fragments = share_fragments(
        &mut ex,
        me,
        party.refresh_complete_phase1(),
        "refresh round-1 fragment",
        op::REFRESH,
    )
    .await?;

    // Round 2 — proof broadcast, zero-share transmits p2p.
    let (correction, my_proof, zero_keep23, zero2_out) =
        party.refresh_complete_phase2(&sid, &poly_fragments);
    ex.send_round(
        2,
        RoundOutbox {
            broadcast: Some(ser(&my_proof)),
            p2p: route(&zero2_out, |m| sidx(m.parties.receiver)),
        },
    )
    .await?;
    let inbox = ex.recv_round(2, Expect::Both).await?;
    let mut proofs: Vec<ProofCommitment<Curve>> = Vec::with_capacity(all.len());
    for &p in &all {
        proofs.push(if p == me {
            my_proof.clone()
        } else {
            de::<ProofCommitment<Curve>>(
                &inbox.broadcasts[&p],
                p,
                "refresh round-2 proof",
                op::REFRESH,
            )?
        });
    }
    let zero2_in = gather(&inbox.p2p, "refresh round-2 zero-share", op::REFRESH)?;

    // Round 3 — zero-share + mul (big OT) transmits, p2p only.
    let (zero_keep34, zero3_out, mul_keep, mul3_out) =
        party.refresh_complete_phase3(&sid, &zero_keep23);
    ex.send_round(
        3,
        RoundOutbox {
            broadcast: None,
            p2p: route_zero_mul(&zero3_out, &mul3_out),
        },
    )
    .await?;
    let inbox = ex.recv_round(3, Expect::P2p).await?;
    let (zero3_in, mul3_in) =
        gather_zero_mul(&inbox.p2p, "refresh round-3 transmits", op::REFRESH)?;

    // Phase 4 — local; the library verifies the corrections sum to the zero
    // point, so the wallet key is preserved by construction.
    let new_party = party
        .refresh_complete_phase4(
            &sid,
            &correction,
            &proofs,
            &zero_keep34,
            &zero2_in,
            &zero3_in,
            &mul_keep,
            &mul3_in,
        )
        .map_err(|a| map_abort(op::REFRESH, a))?;

    // Belt over the protocol's own check.
    let pk = compress_pk(&new_party.pk);
    if pk != *public_key {
        return Err(MpcError::PartyMismatch(
            "refresh produced a different public key".into(),
        ));
    }
    Ok((shard::encode(&new_party), pk))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use sovra_mpc::{MemoryHub, PartyRunner};

    use super::*;
    use crate::{CarbonRunner, testutil};

    /// The security point of proactive refresh, migrated from the silence
    /// backend's `refresh_..._kills_old_generation` test: after a refresh, a
    /// PRE-refresh shard mixed with a new one must never co-sign a valid
    /// wallet signature — a stolen old shard is worthless. The assertion
    /// leans on `sign_party`'s built-in trial-recovery gate: it only ever
    /// returns `Ok` for a signature that recovers to the wallet key, so
    /// *any* `Ok` here would mean the old generation still signs. Depending
    /// on where the zero-share/OT inconsistency surfaces, a party may error
    /// or time out its round — both are passes.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_old_shard_cannot_co_sign_after_refresh() {
        let ctxs = testutil::contexts(2, 3);
        let results = testutil::run_dkg(ctxs.clone()).await;
        let (old_shares, _): (Vec<_>, Vec<_>) = results
            .into_iter()
            .map(|r| r.expect("dkg completes"))
            .unzip();
        let expected = CarbonRunner.public_key_of(&old_shares[0]).unwrap();

        let hub = MemoryHub::new();
        let mut tasks = Vec::new();
        for ctx in &ctxs {
            let mut ctx = ctx.clone();
            ctx.instance = B256::repeat_byte(0x5D);
            let share = old_shares[ctx.party_id as usize].clone();
            let mut relay = hub.connect(ctx.party_id);
            tasks.push(tokio::spawn(async move {
                CarbonRunner
                    .refresh(&ctx, &share, &expected, &mut relay)
                    .await
            }));
        }
        let mut new_shares = Vec::new();
        for t in tasks {
            new_shares.push(t.await.unwrap().expect("refresh completes").0);
        }

        // Mixed generations: party 1 brings its NEW shard, party 2 the OLD
        // one it should have destroyed. Same wallet key on both, so all the
        // pre-relay checks pass — the protocol itself must be what fails.
        let hub = MemoryHub::new();
        let mut tasks = Vec::new();
        for (p, share) in [(1u8, new_shares[1].clone()), (2u8, old_shares[2].clone())] {
            let mut ctx = ctxs[p as usize].clone();
            ctx.instance = B256::repeat_byte(0x5C);
            ctx.ttl = std::time::Duration::from_secs(5); // a stalled round is a pass
            let mut relay = hub.connect(p);
            tasks.push(tokio::spawn(async move {
                CarbonRunner
                    .sign(&ctx, &share, B256::repeat_byte(0xCD), &[1, 2], &mut relay)
                    .await
            }));
        }
        for t in tasks {
            let result = t.await.expect("task not cancelled");
            assert!(
                result.is_err(),
                "an old shard co-signed a valid wallet signature after refresh: {result:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refresh_preserves_the_key_and_new_shards_sign() {
        let ctxs = testutil::contexts(2, 3);
        let results = testutil::run_dkg(ctxs.clone()).await;
        let (shares, pks): (Vec<_>, Vec<_>) = results
            .into_iter()
            .map(|r| r.expect("dkg completes"))
            .unzip();

        // All three re-randomize; the wallet key must come back unchanged
        // and every shard must actually rotate.
        let hub = MemoryHub::new();
        let mut tasks = Vec::new();
        for ctx in &ctxs {
            let mut ctx = ctx.clone();
            ctx.instance = B256::repeat_byte(0x5F);
            let share = shares[ctx.party_id as usize].clone();
            let expected = pks[0];
            let mut relay = hub.connect(ctx.party_id);
            tasks.push(tokio::spawn(async move {
                CarbonRunner
                    .refresh(&ctx, &share, &expected, &mut relay)
                    .await
            }));
        }
        let mut new_shares = Vec::new();
        for (id, t) in tasks.into_iter().enumerate() {
            let (share, pk) = t
                .await
                .expect("task not cancelled")
                .expect("refresh completes");
            assert_eq!(pk, pks[0], "refresh must not change the public key");
            assert_ne!(share, shares[id], "shard must rotate");
            new_shares.push(share);
        }

        // The refreshed generation signs: subset {1, 2}.
        let hub = MemoryHub::new();
        let mut tasks = Vec::new();
        for &p in &[1u8, 2] {
            let mut ctx = ctxs[p as usize].clone();
            ctx.instance = B256::repeat_byte(0x5E);
            let share = new_shares[p as usize].clone();
            let mut relay = hub.connect(p);
            tasks.push(tokio::spawn(async move {
                CarbonRunner
                    .sign(&ctx, &share, B256::repeat_byte(0xAB), &[1, 2], &mut relay)
                    .await
            }));
        }
        let mut parts = Vec::new();
        for t in tasks {
            parts.push(t.await.unwrap().expect("new generation signs"));
        }
        assert_eq!(parts[0], parts[1]);
    }

    #[tokio::test]
    async fn refresh_rejects_a_mismatched_anchor_before_the_relay() {
        let ctxs = testutil::contexts(2, 2);
        let results = testutil::run_dkg(ctxs.clone()).await;
        let (share, _) = results.into_iter().next().unwrap().unwrap();

        let wrong = sovra_types::PubkeySec1::from_slice(&{
            let mut b = [2u8; 33];
            b[32] = 1; // a valid-format but different key
            b
        })
        .unwrap();
        let hub = MemoryHub::new();
        let mut relay = hub.connect(0);
        let err = CarbonRunner
            .refresh(&ctxs[0], &share, &wrong, &mut relay)
            .await
            .unwrap_err();
        assert!(matches!(err, MpcError::PartyMismatch(_)), "got {err:?}");
    }
}
