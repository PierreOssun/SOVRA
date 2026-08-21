//! Shared round plumbing for the three ceremony runners. Every DKLs23
//! ceremony here is DKG-shaped, so the same four patterns recur: the
//! round-1 secret-fragment scatter/gather, per-receiver transmit routing
//! (one serialized `Vec` per recipient), the per-peer flatten-decode of
//! those payloads, and the round-3 zero+mul pairing. One definition each —
//! a wire-shape change happens in exactly one place.

use std::collections::BTreeMap;

use dkls23_secp256k1::protocols::dkg::{TransmitInitMulPhase3to4, TransmitInitZeroSharePhase3to4};
use sovra_mpc::{EnvelopeRelay, Exchange, Expect, MpcError, RoundOutbox};

use crate::{de, ser};

type Curve = k256::Secp256k1;

/// Round 1 of DKG and refresh: fragment j is SECRET and goes sealed p2p to
/// party j (vec position = 0-based id); own is kept. Returns the assembled
/// phase-2 input — own fragment plus every peer's, ordered by sender id
/// (they are summed, so order only matters for log reproducibility).
pub(crate) async fn share_fragments<R: EnvelopeRelay>(
    ex: &mut Exchange<'_, R>,
    me: u8,
    fragments: Vec<k256::Scalar>,
    what: &str,
    op: u8,
) -> Result<Vec<k256::Scalar>, MpcError> {
    let mut outbox = RoundOutbox::default();
    for (j, fragment) in fragments.iter().enumerate() {
        if j as u8 != me {
            outbox.p2p.insert(j as u8, ser(fragment));
        }
    }
    ex.send_round(1, outbox).await?;
    let inbox = ex.recv_round(1, Expect::P2p).await?;
    let mut poly_fragments = Vec::with_capacity(fragments.len());
    for p in 0..fragments.len() as u8 {
        poly_fragments.push(if p == me {
            fragments[p as usize]
        } else {
            de::<k256::Scalar>(&inbox.p2p[&p], p, what, op)?
        });
    }
    Ok(poly_fragments)
}

/// Group per-receiver transmits into one serialized `Vec` per recipient —
/// the p2p half of a [`RoundOutbox`].
pub(crate) fn route<T: serde::Serialize>(
    items: &[T],
    receiver: impl Fn(&T) -> u8,
) -> BTreeMap<u8, Vec<u8>> {
    let mut grouped: BTreeMap<u8, Vec<&T>> = BTreeMap::new();
    for item in items {
        grouped.entry(receiver(item)).or_default().push(item);
    }
    grouped.into_iter().map(|(to, v)| (to, ser(&v))).collect()
}

/// Flatten every peer's serialized `Vec` of transmits, attributing decode
/// failure to the sender — the inverse of [`route`].
pub(crate) fn gather<T: serde::de::DeserializeOwned>(
    p2p: &BTreeMap<u8, Vec<u8>>,
    what: &str,
    op: u8,
) -> Result<Vec<T>, MpcError> {
    let mut out = Vec::new();
    for (&p, bytes) in p2p {
        out.extend(de::<Vec<T>>(bytes, p, what, op)?);
    }
    Ok(out)
}

/// Round 3 of DKG and refresh: both zero-share and mul transmits (the big
/// OT payloads) travel to the same recipients — pack them as one
/// `(zeros, muls)` payload per recipient.
pub(crate) fn route_zero_mul(
    zero: &[TransmitInitZeroSharePhase3to4],
    mul: &[TransmitInitMulPhase3to4<Curve>],
) -> BTreeMap<u8, Vec<u8>> {
    use crate::convert::sidx;
    let mut grouped: BTreeMap<u8, (Vec<_>, Vec<_>)> = BTreeMap::new();
    for m in zero {
        grouped
            .entry(sidx(m.parties.receiver))
            .or_default()
            .0
            .push(m);
    }
    for m in mul {
        grouped
            .entry(sidx(m.parties.receiver))
            .or_default()
            .1
            .push(m);
    }
    grouped
        .into_iter()
        .map(|(to, pair)| (to, ser(&pair)))
        .collect()
}

/// The inverse of [`route_zero_mul`]: flatten every peer's payload.
pub(crate) type ZeroMul = (
    Vec<TransmitInitZeroSharePhase3to4>,
    Vec<TransmitInitMulPhase3to4<Curve>>,
);

pub(crate) fn gather_zero_mul(
    p2p: &BTreeMap<u8, Vec<u8>>,
    what: &str,
    op: u8,
) -> Result<ZeroMul, MpcError> {
    let (mut zeros, mut muls) = (Vec::new(), Vec::new());
    for (&p, bytes) in p2p {
        let (z, m) = de::<ZeroMul>(bytes, p, what, op)?;
        zeros.extend(z);
        muls.extend(m);
    }
    Ok((zeros, muls))
}
