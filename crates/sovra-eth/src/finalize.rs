use crate::{FinalizeError, PreparedTx, SignedTx};
use alloy_consensus::{SignableTransaction, TxEnvelope};
use alloy_network::eip2718::Encodable2718;
use alloy_primitives::{Address, Signature, U256};

pub fn finalize_impl(
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
