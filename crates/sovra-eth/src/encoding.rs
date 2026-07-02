use alloy_consensus::{SignableTransaction, TxEip1559, transaction::RlpEcdsaDecodableTx};
use alloy_primitives::Bytes;

use crate::{DecodeError, PreparedTx};

pub fn encode_unsigned(tx: &TxEip1559) -> Bytes {
    tx.encoded_for_signing().into()
}

pub fn decode_unsigned(raw: &[u8]) -> Result<PreparedTx, DecodeError> {
    let Some((&first, mut elements)) = raw.split_first() else {
        return Err(DecodeError::Empty);
    };
    if first != 0x02 {
        return Err(DecodeError::UnsupportedType(first));
    }

    let tx = TxEip1559::rlp_decode(&mut elements)?;

    if !elements.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }

    let signing_hash = tx.signature_hash();

    Ok(PreparedTx { tx, signing_hash })
}
