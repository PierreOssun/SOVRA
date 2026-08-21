//! This party's share of a t-of-n DKG, mapping 0xCarbon's four session
//! phases onto three envelope rounds (the routing mirrors upstream's
//! `test_dkg_session_full_flow`, the de-facto spec):
//!
//! round 1: phase1's Shamir fragments — fragment j is SECRET and goes sealed
//!          p2p to party j (vec position = 0-based id); own is kept.
//! round 2: phase2 — (ProofCommitment ‖ derivation broadcast) to everyone,
//!          zero-share transmits sealed p2p to their receivers.
//! round 3: phase3 — derivation broadcast, zero-share + mul transmits
//!          (the big OT payloads) sealed p2p.
//! local:   phase4 consumes all n proofs/broadcasts (own included) plus the
//!          p2p messages addressed to us, and yields the `Party` shard.

use std::collections::BTreeMap;

use dkls23_secp256k1::{
    compute_eth_address,
    protocols::{
        dkg::{BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment},
        dkg_session::DkgSession,
    },
};
use sovra_mpc::{EnvelopeRelay, Exchange, Expect, MpcError, PartyContext, RoundOutbox, op};
use sovra_types::{KeyShare, PubkeySec1};

use crate::{
    convert::{cidx, compress_pk, scheme, sidx},
    de, map_abort,
    rounds::{gather, gather_zero_mul, route, route_zero_mul, share_fragments},
    ser, shard,
};

type Curve = k256::Secp256k1;

pub(crate) async fn keygen_party(
    ctx: &PartyContext,
    relay: &mut impl EnvelopeRelay,
) -> Result<(KeyShare, PubkeySec1), MpcError> {
    let (params, my_index) = scheme(ctx)?;
    let me = ctx.party_id;
    let all: Vec<u8> = (0..params.share_count).collect();
    let mut ex = Exchange::new(relay, ctx, op::DKG, &all);
    let mut session = DkgSession::<Curve>::new(params, my_index, ctx.instance.to_vec());

    // Round 1 — one secret fragment per party.
    let poly_fragments = share_fragments(
        &mut ex,
        me,
        session.phase1(),
        "dkg round-1 fragment",
        op::DKG,
    )
    .await?;

    // Round 2 — proof+derivation broadcast, zero-share transmits p2p.
    let (my_proof, zero2_out, my_bip2) = session
        .phase2(&poly_fragments)
        .map_err(|a| map_abort(op::DKG, a))?;
    ex.send_round(
        2,
        RoundOutbox {
            broadcast: Some(ser(&(&my_proof, &my_bip2))),
            p2p: route(&zero2_out, |m| sidx(m.parties.receiver)),
        },
    )
    .await?;
    let inbox = ex.recv_round(2, Expect::Both).await?;
    let mut proofs: Vec<ProofCommitment<Curve>> = Vec::with_capacity(all.len());
    let mut bip2 = BTreeMap::new();
    for &p in &all {
        let (proof, bip) = if p == me {
            (my_proof.clone(), my_bip2.clone())
        } else {
            de::<(ProofCommitment<Curve>, BroadcastDerivationPhase2to4)>(
                &inbox.broadcasts[&p],
                p,
                "dkg round-2 broadcast",
                op::DKG,
            )?
        };
        proofs.push(proof);
        bip2.insert(cidx(p), bip);
    }
    let zero2_in = gather(&inbox.p2p, "dkg round-2 zero-share", op::DKG)?;

    // Round 3 — derivation broadcast, zero-share + mul (big OT) p2p.
    let (zero3_out, mul3_out, my_bip3) = session.phase3().map_err(|a| map_abort(op::DKG, a))?;
    ex.send_round(
        3,
        RoundOutbox {
            broadcast: Some(ser(&my_bip3)),
            p2p: route_zero_mul(&zero3_out, &mul3_out),
        },
    )
    .await?;
    let inbox = ex.recv_round(3, Expect::Both).await?;
    let mut bip3 = BTreeMap::new();
    bip3.insert(my_index, my_bip3);
    for (&p, bytes) in &inbox.broadcasts {
        bip3.insert(
            cidx(p),
            de::<BroadcastDerivationPhase3to4>(bytes, p, "dkg round-3 broadcast", op::DKG)?,
        );
    }
    let (zero3_in, mul3_in) = gather_zero_mul(&inbox.p2p, "dkg round-3 transmits", op::DKG)?;

    // Phase 4 — local assembly; the library verifies proofs and consistency.
    let (party, _pkg) = session
        .phase4(
            &proofs,
            &zero2_in,
            &zero3_in,
            &mul3_in,
            &bip2,
            &bip3,
            compute_eth_address,
        )
        .map_err(|a| map_abort(op::DKG, a))?;
    Ok((shard::encode(&party), compress_pk(&party.pk)))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ed25519_dalek::SigningKey;
    use sovra_mpc::PartyRunner;

    use super::*;
    use crate::{
        CarbonRunner,
        testutil::{contexts, run_dkg},
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn dkg_reaches_pk_consensus_and_valid_shards() {
        for (t, n) in [(2u8, 2u8), (2, 3)] {
            let results = run_dkg(contexts(t, n)).await;
            let (shares, pks): (Vec<_>, Vec<_>) = results
                .into_iter()
                .map(|r| r.expect("dkg completes"))
                .unzip();
            assert!(
                pks.iter().all(|pk| *pk == pks[0]),
                "{t}-of-{n} pk consensus"
            );
            for (id, share) in shares.iter().enumerate() {
                // The shard belongs to this party and this scheme, and
                // independently re-derives the agreed public key.
                shard::decode_for(share, id as u8, t, n, op::DKG)
                    .expect("shard matches its context");
                assert_eq!(CarbonRunner.public_key_of(share).unwrap(), pks[0]);
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_peer_vk_breaks_keygen() {
        // The migrated security property: party 1 pins the wrong key for
        // party 0, so party 0's first envelope fails roster authentication
        // and party 1 aborts with an attributable auth error — fast, not by
        // burning the ceremony TTL (sl-dkls23 surfaced this as a stall).
        let mut ctxs = contexts(2, 2);
        for ctx in &mut ctxs {
            ctx.ttl = Duration::from_secs(3); // party 0 dies by timeout, quickly
        }
        ctxs[1].party_vks[0] = SigningKey::from_bytes(&[0xAD; 32]).verifying_key();
        ctxs[1].ttl = Duration::from_secs(60); // party 1 must abort, not time out

        let started = std::time::Instant::now();
        let results = run_dkg(ctxs).await;
        assert!(
            matches!(&results[1], Err(MpcError::EnvelopeAuth(_))),
            "got: {:?}",
            results[1].as_ref().err()
        );
        assert!(results[0].is_err(), "party 0 cannot complete alone");
        assert!(
            started.elapsed().as_secs() < 30,
            "abort, not a 60s TTL burn"
        );
    }
}
