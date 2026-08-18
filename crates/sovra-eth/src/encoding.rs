//! Wire format for transactions crossing the API boundary: legacy (bare RLP
//! list), EIP-2930 (0x01) and EIP-1559 (0x02) payloads — unsigned signing
//! form and signed EIP-2718 envelope — hex-encoded by `Bytes`' serde.
//!
//! `decode_unsigned` and `decode_signed` are strict by design — only the
//! three supported types (0x03/0x04 are refused, matching what [`EthTx`] can
//! represent), no trailing bytes — and recompute the hash (and, for the
//! signed form, the signer) from the decoded tx, so a caller can never
//! smuggle in a digest or address that doesn't match the bytes (the API's
//! never-trust-the-caller-hash rule starts here). Dispatch is EIP-2718's own
//! rule: a first byte ≥ 0xc0 is an RLP list, therefore legacy; below 0x80 it
//! is a type byte. Pattern: parse, don't validate — the outputs are a
//! `PreparedTx`/`SignedTx` whose hash and signer are correct by construction.

use alloy_consensus::{
    SignableTransaction, Signed, TxEip1559, TxEip2930, TxLegacy,
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx, SignerRecoverable},
};
use alloy_primitives::{Bytes, Signature};
use alloy_rlp::{Decodable, Header};

use crate::{DecodeError, EthTx, PreparedTx, SignedTx};

pub fn encode_unsigned(tx: &EthTx) -> Bytes {
    tx.encoded_for_signing().into()
}

/// The strictness rule, in one place: the rlp payload must consume every
/// remaining byte.
fn decode_strict<T>(
    mut payload: &[u8],
    decode: fn(&mut &[u8]) -> alloy_rlp::Result<T>,
) -> Result<T, DecodeError> {
    let tx = decode(&mut payload)?;
    if !payload.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(tx)
}

/// One dispatch for both decode directions: the closure per supported type
/// keeps unsigned/signed decoding from drifting apart on the type-byte rule.
fn decode_dispatch<T>(
    raw: &[u8],
    legacy: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
    eip2930: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
    eip1559: impl FnOnce(&[u8]) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let Some((&first, payload)) = raw.split_first() else {
        return Err(DecodeError::Empty);
    };
    match first {
        0x01 => eip2930(payload),
        0x02 => eip1559(payload),
        // An RLP list header: legacy txs have no type byte. The full raw
        // slice (including `first`) is the payload.
        0xc0.. => legacy(raw),
        other => Err(DecodeError::UnsupportedType(other)),
    }
}

/// Legacy has no canonical unsigned encoding that carries a chain id — the
/// 6-item tx form drops it, and only the *signed* form encodes it (inside
/// `v`). The one self-describing unsigned-legacy format is the EIP-155
/// signing preimage `rlp([nonce, gas_price, gas_limit, to, value, data,
/// chain_id, 0, 0])` — exactly what `TxLegacy::encoded_for_signing`
/// produces — so that is the wire form, and this is its decoder (alloy has
/// no public one). A 6-item pre-155 preimage still parses (`chain_id:
/// None`) so validation can refuse it with a precise error instead of an
/// opaque RLP failure.
fn decode_legacy_unsigned(raw: &[u8]) -> Result<TxLegacy, DecodeError> {
    let mut buf = raw;
    let header = Header::decode(&mut buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString.into());
    }
    if buf.len() < header.payload_length {
        return Err(alloy_rlp::Error::InputTooShort.into());
    }
    if buf.len() > header.payload_length {
        return Err(DecodeError::TrailingBytes);
    }
    let mut payload = buf;
    // Alloy's canonical decoder for the 6 tx fields; leaves chain_id: None.
    let mut tx = TxLegacy::rlp_decode_fields(&mut payload)?;
    if !payload.is_empty() {
        let chain_id = u64::decode(&mut payload)?;
        let (zero_r, zero_s) = (u8::decode(&mut payload)?, u8::decode(&mut payload)?);
        if zero_r != 0 || zero_s != 0 || !payload.is_empty() {
            return Err(alloy_rlp::Error::Custom("malformed EIP-155 signing preimage").into());
        }
        tx.chain_id = Some(chain_id);
    }
    Ok(tx)
}

pub fn decode_unsigned(raw: &[u8]) -> Result<PreparedTx, DecodeError> {
    let tx = decode_dispatch(
        raw,
        |p| decode_legacy_unsigned(p).map(EthTx::Legacy),
        |p| decode_strict(p, TxEip2930::rlp_decode).map(EthTx::Eip2930),
        |p| decode_strict(p, TxEip1559::rlp_decode).map(EthTx::Eip1559),
    )?;
    let signing_hash = tx.signature_hash();
    Ok(PreparedTx { tx, signing_hash })
}

pub fn decode_signed(raw: &[u8]) -> Result<SignedTx, DecodeError> {
    fn to_signed_tx<T>(raw: &[u8], signed: Signed<T>) -> Result<SignedTx, DecodeError>
    where
        T: SignableTransaction<Signature> + RlpEcdsaEncodableTx,
        Signed<T>: SignerRecoverable,
    {
        let from = signed.recover_signer().map_err(|_| DecodeError::Recovery)?;
        Ok(SignedTx {
            raw: raw.to_vec().into(),
            tx_hash: *signed.hash(),
            from,
        })
    }

    decode_dispatch(
        raw,
        |p| to_signed_tx(raw, decode_strict(p, TxLegacy::rlp_decode_signed)?),
        |p| to_signed_tx(raw, decode_strict(p, TxEip2930::rlp_decode_signed)?),
        |p| to_signed_tx(raw, decode_strict(p, TxEip1559::rlp_decode_signed)?),
    )
}
