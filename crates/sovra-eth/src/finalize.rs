//! Attach a signature to a prepared tx and produce broadcast-ready bytes.
//!
//! The load-bearing step is the check, not the encoding: the signer address
//! is recovered from the prehash and must equal `expected_from`, so a wrong
//! or malicious signature (different key, different digest) is rejected here
//! rather than discovered on-chain. Encoding goes through alloy's
//! `TxEnvelope`/EIP-2718 path so the raw bytes and tx hash are exactly what
//! the network computes. Pattern: pure function, validate-then-construct.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Signature, U256};

use crate::{FinalizeError, PreparedTx, SignedTx};

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
        tracing::error!(expected = %expected_from, recovered = %recovered, "signer mismatch");
        return Err(FinalizeError::AddressMismatch {
            expected: expected_from,
            recovered,
        });
    }

    // attach the signature and wrap in alloy's envelope; for legacy, alloy
    // derives the EIP-155 v from the tx's chain id here
    let envelope = prepared_tx.tx.into_envelope(signature);

    // the on-chain tx id (keccak of the signed bytes)
    let tx_hash = *envelope.tx_hash();

    // serialize to raw EIP-2718 bytes (legacy = bare RLP) for
    // eth_sendRawTransaction
    let raw = envelope.encoded_2718().into();

    tracing::info!(tx_hash = %tx_hash, from = %recovered, "tx finalized");

    Ok(SignedTx {
        raw,
        tx_hash,
        from: recovered,
    })
}
