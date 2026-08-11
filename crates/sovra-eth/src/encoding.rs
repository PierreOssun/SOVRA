//! Wire format for transactions crossing the API boundary: 0x02-prefixed
//! EIP-1559 payloads (unsigned signing form and signed EIP-2718 envelope),
//! hex-encoded by `Bytes`' serde.
//!
//! `decode_unsigned` and `decode_signed` are strict by design — only type
//! 0x02, no trailing bytes — and recompute the hash (and, for the signed
//! form, the signer) from the decoded tx, so a caller can never smuggle in a
//! digest or address that doesn't match the bytes (the API's
//! never-trust-the-caller-hash rule starts here). Pattern: parse, don't
//! validate — the outputs are a `PreparedTx`/`SignedTx` whose hash and
//! signer are correct by construction.

use alloy_consensus::{SignableTransaction, TxEip1559, transaction::RlpEcdsaDecodableTx};
use alloy_primitives::Bytes;

use crate::{DecodeError, PreparedTx, SignedTx};

pub fn encode_unsigned(tx: &TxEip1559) -> Bytes {
    tx.encoded_for_signing().into()
}

/// The strictness rule, in one place: type byte must be 0x02, the rlp
/// payload must consume every remaining byte.
fn decode_eip1559<T>(
    raw: &[u8],
    decode: fn(&mut &[u8]) -> alloy_rlp::Result<T>,
) -> Result<T, DecodeError> {
    let Some((&first, mut elements)) = raw.split_first() else {
        return Err(DecodeError::Empty);
    };
    if first != 0x02 {
        return Err(DecodeError::UnsupportedType(first));
    }
    let tx = decode(&mut elements)?;
    if !elements.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(tx)
}

pub fn decode_unsigned(raw: &[u8]) -> Result<PreparedTx, DecodeError> {
    let tx = decode_eip1559(raw, TxEip1559::rlp_decode)?;
    let signing_hash = tx.signature_hash();
    Ok(PreparedTx { tx, signing_hash })
}

pub fn decode_signed(raw: &[u8]) -> Result<SignedTx, DecodeError> {
    let signed = decode_eip1559(raw, TxEip1559::rlp_decode_signed)?;
    let from = signed.recover_signer().map_err(|_| DecodeError::Recovery)?;

    Ok(SignedTx {
        raw: raw.to_vec().into(),
        tx_hash: *signed.hash(),
        from,
    })
}
