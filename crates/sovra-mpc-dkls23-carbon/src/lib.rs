//! 0xCarbon DKLs23 MPC backend: implements the `sovra-mpc` [`PartyRunner`]
//! seam over the `dkls23-secp256k1` crate, replacing the Silence Labs
//! backend (Apache-2.0/MIT vs non-commercial — the migration's raison
//! d'être). Unlike sl-dkls23, this library brings no transport security of
//! its own: every round travels in sovra's signed/sealed envelope via
//! [`Exchange`](sovra_mpc::Exchange).
//!
//! All three ceremonies are live: keygen, sign, and the all-parties
//! proactive refresh (lost-shard recovery is a product flow — degraded
//! signing + fresh DKG — not a protocol operation).

// Private on purpose: k256-0.14 types (`Party`, `AffinePoint`) must never
// cross the crate boundary — the workspace k256 is 0.13 and the two
// generations don't share types. Everything external goes through
// [`CarbonRunner`]'s byte-level API.
mod convert;
mod inprocess;
mod keygen;
mod refresh;
mod rounds;
mod shard;
mod sign;
#[cfg(test)]
pub(crate) mod testutil;

use alloy_primitives::B256;
use dkls23_secp256k1::protocols::{Abort, AbortKind};
pub use inprocess::InProcessBackend;
use sovra_mpc::{EnvelopeRelay, MpcError, PartyContext, PartyRunner, op};
use sovra_types::{EcdsaParts, KeyShare, PubkeySec1};

/// The seam error variant an operation's failures surface as — mirrors how
/// the silence backend labeled them (sign errors are not "dkg failed").
pub(crate) fn fail(op: u8) -> fn(String) -> MpcError {
    if op == op::SIGN {
        MpcError::Sign
    } else {
        MpcError::Dkg
    }
}

/// Serialize a 0xCarbon protocol struct for an envelope payload.
pub(crate) fn ser<T: serde::Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("protocol structs have no unserializable state")
}

/// Deserialize a peer's payload, attributing failure to the sender.
pub(crate) fn de<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    from: u8,
    what: &str,
    op: u8,
) -> Result<T, MpcError> {
    bincode::deserialize(bytes)
        .map_err(|_| fail(op)(format!("party {from} sent an undecodable {what}")))
}

/// Map a protocol abort to the seam error. `BanCounterparty` is the one
/// abort that must not look routine: the paper mandates permanently
/// excluding the flagged party — re-running with them enables key
/// extraction over repeated sessions — so it is named loudly in both the
/// log and the error.
pub(crate) fn map_abort(op: u8, abort: Abort) -> MpcError {
    if let AbortKind::BanCounterparty(p) = abort.kind {
        let banned = convert::sidx(p);
        tracing::error!(
            banned,
            "DKLs23 abort mandates permanently banning this party — do NOT re-run ceremonies with this roster"
        );
        fail(op)(format!(
            "aborted; party {banned} must be permanently banned before any retry: {}",
            abort.description()
        ))
    } else {
        fail(op)(abort.description())
    }
}

/// The 0xCarbon-backed [`PartyRunner`]. Stateless: every ceremony's inputs
/// arrive via [`PartyContext`] and the shard bytes.
#[derive(Clone, Copy, Default)]
pub struct CarbonRunner;

impl PartyRunner for CarbonRunner {
    async fn keygen(
        &self,
        ctx: &PartyContext,
        relay: &mut impl EnvelopeRelay,
    ) -> Result<(KeyShare, PubkeySec1), MpcError> {
        keygen::keygen_party(ctx, relay).await
    }

    async fn sign(
        &self,
        ctx: &PartyContext,
        share: &KeyShare,
        digest: B256,
        subset: &[u8],
        relay: &mut impl EnvelopeRelay,
    ) -> Result<EcdsaParts, MpcError> {
        sign::sign_party(ctx, share, digest, subset, relay).await
    }

    async fn refresh(
        &self,
        ctx: &PartyContext,
        share: &KeyShare,
        public_key: &PubkeySec1,
        relay: &mut impl EnvelopeRelay,
    ) -> Result<(KeyShare, PubkeySec1), MpcError> {
        refresh::refresh_party(ctx, share, public_key, relay).await
    }

    fn public_key_of(&self, share: &KeyShare) -> Result<PubkeySec1, MpcError> {
        Ok(convert::compress_pk(&shard::decode(share)?.pk))
    }
}

#[cfg(test)]
mod tests {
    use dkls23_secp256k1::protocols::{Parameters, re_key::re_key};

    use super::*;
    use crate::convert::{cidx, compress_pk};

    /// Mint valid `Party` values locally via 0xCarbon's trusted-dealer
    /// re-key — full shard state, zero network, zero DKG.
    fn mint(threshold: u8, share_count: u8) -> Vec<dkls23_secp256k1::Party> {
        let params = Parameters::new(threshold, share_count).expect("valid scheme");
        let secret = k256::Scalar::from(0xC0FFEEu64);
        let (parties, _) = re_key::<k256::Secp256k1>(
            &params,
            b"sovra-mc2-test",
            &secret,
            None,
            dkls23_secp256k1::compute_eth_address,
        );
        parties
    }

    #[test]
    fn shard_roundtrip_preserves_identity_scheme_and_key() {
        for party in mint(2, 3) {
            let decoded = shard::decode(&shard::encode(&party)).expect("roundtrip");
            assert_eq!(decoded.party_index, party.party_index);
            assert_eq!(decoded.parameters.threshold, 2);
            assert_eq!(decoded.parameters.share_count, 3);
            assert_eq!(compress_pk(&decoded.pk), compress_pk(&party.pk));
            assert_eq!(decoded.session_id, party.session_id);
        }
    }

    #[test]
    fn all_parties_of_one_scheme_agree_on_the_public_key() {
        let shares: Vec<KeyShare> = mint(2, 3).iter().map(shard::encode).collect();
        let pks: Vec<PubkeySec1> = shares
            .iter()
            .map(|s| CarbonRunner.public_key_of(s).expect("valid shard"))
            .collect();
        assert_eq!(pks[0], pks[1]);
        assert_eq!(pks[1], pks[2]);
    }

    #[test]
    fn decode_names_foreign_and_future_shards() {
        // An sl-era shard (raw bytes, no magic) and a future-version shard
        // must both fail closed — Deserialize, not garbage-in-garbage-out.
        assert!(matches!(
            shard::decode(&KeyShare::from(vec![0u8; 64])),
            Err(MpcError::Deserialize)
        ));
        let mut future = shard::encode(&mint(2, 2).remove(0)).0;
        future[4] = 2; // bump the version byte
        assert!(matches!(
            shard::decode(&KeyShare::from(future)),
            Err(MpcError::Deserialize)
        ));
        assert!(matches!(
            shard::decode(&KeyShare::from(b"SVR".to_vec())),
            Err(MpcError::Deserialize)
        ));
    }

    #[test]
    fn decode_for_rejects_wrong_party_and_wrong_scheme() {
        let party1 = mint(2, 3).remove(1); // 0xCarbon index 2 == sovra id 1
        let share = shard::encode(&party1);
        shard::decode_for(&share, 1, 2, 3, op::DKG).expect("matching context");
        assert!(
            shard::decode_for(&share, 0, 2, 3, op::DKG).is_err(),
            "wrong party"
        );
        assert!(
            shard::decode_for(&share, 1, 3, 3, op::DKG).is_err(),
            "wrong threshold"
        );
        assert!(
            shard::decode_for(&share, 1, 2, 4, op::DKG).is_err(),
            "wrong share count"
        );
    }

    #[test]
    fn tampered_shard_body_never_decodes_to_the_original() {
        let original = mint(2, 2).remove(0);
        let mut bytes = shard::encode(&original).0;
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        // Either the body no longer parses, or it parses to *different*
        // state — a flip that decodes back to the identical Party would mean
        // the codec ignores bytes, and sealing-at-rest is the only tamper
        // authentication this layer can rely on.
        if let Ok(party) = shard::decode(&KeyShare::from(bytes)) {
            assert_ne!(
                bincode::serialize(&party).unwrap(),
                bincode::serialize(&original).unwrap(),
            );
        }
    }

    #[test]
    fn minted_indices_map_back_to_sovra_ids() {
        for (sovra_id, party) in mint(2, 3).iter().enumerate() {
            assert_eq!(party.party_index, cidx(sovra_id as u8));
        }
    }
}
