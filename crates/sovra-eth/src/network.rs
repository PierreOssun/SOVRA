//! Ethereum's implementation of the `sovra_network::Network` seam.
//!
//! Pure delegation to this crate's existing pipeline (decode → validate →
//! signature_hash → finalize); the only logic here is the error translation:
//! rich internal enums (`DecodeError`, `PrepareError`, `FinalizeError`)
//! stringify into `TxError`'s four HTTP-classed buckets at this boundary, so
//! the generic layers keep today's 4xx/5xx mapping without knowing Ethereum
//! error shapes. Pattern: adapter over the crate's own core.

use sovra_network::{EthTxView, Network, SignedArtifacts, TxError, TxView};
use sovra_types::{EcdsaParts, NetworkId, PubkeySec1};

use crate::{EthTx, address_from_sec1, decode_unsigned, finalize, prepare::validate_unsigned};

pub struct Ethereum;

impl Network for Ethereum {
    const ID: NetworkId = NetworkId::Ethereum;

    type Unsigned = EthTx;

    fn decode_unsigned(bytes: &[u8]) -> Result<EthTx, TxError> {
        decode_unsigned(bytes)
            .map(|prepared| prepared.tx)
            .map_err(|e| TxError::Decode(e.to_string()))
    }

    fn validate(tx: &EthTx) -> Result<(), TxError> {
        validate_unsigned(tx).map_err(|e| TxError::Validate(e.to_string()))
    }

    fn signing_digests(tx: &EthTx) -> Vec<[u8; 32]> {
        vec![tx.signature_hash().0]
    }

    fn policy_view<'a>(tx: &'a EthTx) -> TxView<'a> {
        // chain_id is Some past validate; the 0 fallback only ever denies
        // (no policy allowlists chain 0) — fail-closed either way.
        TxView::Ethereum(EthTxView {
            chain_id: tx.chain_id().unwrap_or_default(),
            to: tx.to(),
            value: tx.value(),
            data: tx.input(),
        })
    }

    fn finalize(
        tx: EthTx,
        sigs: &[EcdsaParts],
        signer: &PubkeySec1,
    ) -> Result<SignedArtifacts, TxError> {
        let [sig] = sigs else {
            return Err(TxError::Finalize(format!(
                "ethereum signs exactly one digest, got {} signatures",
                sigs.len()
            )));
        };
        let expected_from =
            address_from_sec1(signer).map_err(|e| TxError::Pubkey(e.to_string()))?;
        let signing_hash = tx.signature_hash();
        let signed = finalize(
            crate::PreparedTx { tx, signing_hash },
            sig.r,
            sig.s,
            sig.y_parity,
            expected_from,
        )
        .map_err(|e| TxError::Finalize(e.to_string()))?;
        Ok(SignedArtifacts {
            raw: signed.raw,
            txid: signed.tx_hash,
        })
    }

    fn derive_address(pk: &PubkeySec1) -> Result<String, TxError> {
        // Lowercase hex, matching serde's rendering of Address elsewhere in
        // the API (Display would be EIP-55 checksummed).
        Ok(format!(
            "{:#x}",
            address_from_sec1(pk).map_err(|e| TxError::Pubkey(e.to_string()))?
        ))
    }
}
