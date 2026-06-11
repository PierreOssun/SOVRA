mod types;

#[cfg(test)]
mod tests;

use alloy_consensus::private::alloy_eips::Encodable2718;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_primitives::{Address, Signature, U256};
pub use types::*;

pub fn prepare(intent: TxIntent) -> Result<PreparedTx, PrepareError> {
    // Validate inputs
    if intent.chain_id == 0 {
        return Err(PrepareError::ZeroChainId);
    }
    if intent.gas_limit == 0 {
        return Err(PrepareError::ZeroGasLimit);
    }
    if intent.max_priority_fee_per_gas > intent.max_fee_per_gas {
        return Err(PrepareError::MaxPriorityFeeExceedsMaxFee);
    }

    let eip1559_tx = TxEip1559::from(intent);
    let signing_hash = eip1559_tx.signature_hash();

    Ok(PreparedTx {
        tx: eip1559_tx,
        signing_hash,
    })
}

pub fn finalize(
    prepared_tx: PreparedTx,
    r: U256,
    s: U256,
    y_parity: bool,
    expected_from: Address,
) -> Result<SignedTx, FinalizeError> {
    let signature = Signature::new(r, s, y_parity);

    let recovered = signature
        .recover_address_from_prehash(&prepared_tx.signing_hash)
        .map_err(|_| FinalizeError::Recovery)?;

    if recovered != expected_from {
        return Err(FinalizeError::AddressMismatch {
            expected: expected_from,
            recovered,
        });
    }

    // attach the signature to the unsigned tx
    let signed = prepared_tx.tx.into_signed(signature);

    // the on-chain tx id (keccak of the signed bytes)
    let tx_hash = *signed.hash();

    // alloy's enum over every typed-tx kind
    let envelope = TxEnvelope::from(signed);

    // serialize to raw EIP-2718 bytes (0x02…) for eth_sendRawTransaction
    let raw = envelope.encoded_2718().into();

    Ok(SignedTx {
        raw,
        tx_hash,
        from: recovered,
    })
}
