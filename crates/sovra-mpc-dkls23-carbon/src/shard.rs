//! Versioned shard codec: `b"SVRC" ‖ version ‖ bincode(Party)`.
//!
//! The sl backend stored `Keyshare::as_slice()` raw — no marker, so a backend
//! swap was undetectable from bytes alone and old shards failed with an
//! anonymous deserialize error. The magic+version prefix fixes that for the
//! *next* migration: a wrong-backend or wrong-version shard is named as such
//! before any body parsing. The body stays bincode-of-`Party` (0xCarbon's own
//! serde impl); the prefix is ours. Sealing-at-rest is unchanged — this whole
//! encoding passes opaquely through `sovra-state`'s `ShardSealer`.

use dkls23_secp256k1::Party;
use sovra_mpc::MpcError;
use sovra_types::KeyShare;

use crate::{
    convert::{cidx, sidx},
    fail,
};

const MAGIC: &[u8; 4] = b"SVRC";
const VERSION: u8 = 1;

pub fn encode(party: &Party) -> KeyShare {
    let body = bincode::serialize(party).expect("Party has no unserializable state");
    let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + body.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&body);
    KeyShare::from(bytes)
}

pub fn decode(share: &KeyShare) -> Result<Party, MpcError> {
    let rest = share
        .as_bytes()
        .strip_prefix(MAGIC)
        .ok_or(MpcError::Deserialize)?;
    let (&version, body) = rest.split_first().ok_or(MpcError::Deserialize)?;
    if version != VERSION {
        return Err(MpcError::Deserialize);
    }
    bincode::deserialize(body).map_err(|_| MpcError::Deserialize)
}

/// [`decode`] plus the shard-vs-scheme sanity check every ceremony performs
/// before touching the relay: the shard must belong to this party and to this
/// t-of-n scheme, or the operator mixed stores/configs.
pub fn decode_for(
    share: &KeyShare,
    party_id: u8,
    threshold: u8,
    share_count: u8,
    op: u8,
) -> Result<Party, MpcError> {
    let party = decode(share)?;
    if party.party_index != cidx(party_id)
        || party.parameters.threshold != threshold
        || party.parameters.share_count != share_count
    {
        return Err(fail(op)(format!(
            "keyshare/scheme mismatch: shard is party {} of {}-of-{}, \
             ceremony runs as party {party_id} of {threshold}-of-{share_count}",
            sidx(party.party_index),
            party.parameters.threshold,
            party.parameters.share_count,
        )));
    }
    Ok(party)
}
