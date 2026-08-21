//! The single place where the two id/point vocabularies meet: 0xCarbon's
//! 1-based [`PartyIndex`] vs sovra's 0-based `u8` party ids, and k256-0.14
//! curve points vs the byte-level [`PubkeySec1`]. Nothing outside this module
//! may add or subtract 1, and no k256-0.14 type may cross the crate boundary.

use dkls23_secp256k1::protocols::{Parameters, PartyIndex};
use elliptic_curve::sec1::ToSec1Point;
use sovra_mpc::{MpcError, PartyContext};
use sovra_types::PubkeySec1;

/// Validate the context against scheme bounds and translate it into the
/// library's vocabulary — every ceremony's first step, before any relay
/// traffic (mirrors the silence backend's `keygen_setup` checks; the
/// `2 <= t <= n` bound itself lives in `Parameters::new`).
pub(crate) fn scheme(ctx: &PartyContext) -> Result<(Parameters, PartyIndex), MpcError> {
    let n = ctx.party_vks.len();
    if !(2..=255).contains(&n) {
        return Err(MpcError::Dkg(format!(
            "roster must have 2..=255 parties, has {n}"
        )));
    }
    if usize::from(ctx.party_id) >= n {
        return Err(MpcError::Dkg(format!(
            "party id {} out of range for {n} parties",
            ctx.party_id
        )));
    }
    let parameters = Parameters::new(ctx.threshold, n as u8)
        .map_err(|e| MpcError::Dkg(format!("invalid scheme {}-of-{n}: {e}", ctx.threshold)))?;
    Ok((parameters, cidx(ctx.party_id)))
}

/// Sovra party id (0-based) → 0xCarbon index (1-based).
///
/// Infallible by invariant: rosters are `Vec`-indexed by id, so an id is
/// always < n ≤ 255 and the +1 cannot overflow — a 255 here means the caller
/// skipped roster validation, which is a bug worth the panic.
pub fn cidx(party_id: u8) -> PartyIndex {
    PartyIndex::new(party_id.wrapping_add(1)).expect("party id 255 cannot exist in a valid roster")
}

/// 0xCarbon index (1-based) → sovra party id (0-based).
pub fn sidx(index: PartyIndex) -> u8 {
    index.as_u8() - 1 // never underflows: PartyIndex rejects 0 at construction
}

/// Compressed SEC1 encoding of a k256-0.14 public key — the only way curve
/// points leave this crate.
pub fn compress_pk(pk: &k256::AffinePoint) -> PubkeySec1 {
    PubkeySec1::from_slice(pk.to_sec1_point(true).as_bytes())
        .expect("a curve point always compresses to a valid 33-byte SEC1 key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_mapping_roundtrips_across_the_full_domain() {
        for id in 0..=254u8 {
            assert_eq!(sidx(cidx(id)), id);
        }
    }

    #[test]
    #[should_panic(expected = "valid roster")]
    fn party_id_255_panics() {
        cidx(255);
    }

    #[test]
    fn compress_pk_yields_canonical_sec1() {
        use elliptic_curve::group::prime::PrimeCurveAffine;
        let pk = (k256::AffinePoint::generator() * k256::Scalar::from(7u64)).to_affine();
        let sec1 = compress_pk(&pk);
        assert!(matches!(sec1.as_bytes()[0], 0x02 | 0x03));
        assert_eq!(sec1.as_bytes().len(), 33);
    }
}
