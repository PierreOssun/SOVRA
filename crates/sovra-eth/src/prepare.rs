//! Build an unsigned tx: `enrich` pulls chain id, pending nonce, fee data
//! (per-type: `eth_gasPrice` for legacy/2930, EIP-1559 estimates for 1559),
//! and gas limit from the RPC node; `prepare` turns the resulting `TxIntent`
//! into a validated [`EthTx`] + signing hash.
//!
//! Why the enrich/prepare split: `prepare` is pure and exhaustively
//! unit-testable, while `enrich` is the only RPC-touching step — and it's
//! generic over `Provider` so tests substitute a mock transport.
//! `validate_unsigned` is public because the same invariants must hold for
//! transactions supplied as raw bytes by callers, not just ones built here.
//! Pattern: functional core, imperative shell.

#[cfg(feature = "rpc")]
use alloy_primitives::{Address, TxKind};
#[cfg(feature = "rpc")]
use alloy_provider::{Provider, ProviderBuilder};
#[cfg(feature = "rpc")]
use alloy_rpc_types_eth::TransactionRequest;
#[cfg(feature = "rpc")]
use url::Url;

#[cfg(feature = "rpc")]
use crate::{EnrichError, EthTxType, ProviderError, TxParams, TxRequest};
use crate::{EthTx, PrepareError, PreparedTx, TxIntent};

#[cfg(feature = "rpc")]
pub async fn prepare_from_rpc_impl<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<PreparedTx, PrepareError> {
    // Refused rather than silently dropped: past this point `TxParams`
    // makes a legacy access list unrepresentable, so this is the one spot
    // where the caller's mistake is still visible.
    if req.tx_type == EthTxType::Legacy && !req.access_list.is_empty() {
        return Err(PrepareError::AccessListUnsupported);
    }
    let tx_intent = enrich(req, from, provider).await?;
    prepare(tx_intent)
}

pub fn prepare(intent: TxIntent) -> Result<PreparedTx, PrepareError> {
    let tx = EthTx::from(intent);
    validate_unsigned(&tx)?;

    let signing_hash = tx.signature_hash();

    Ok(PreparedTx { tx, signing_hash })
}

/// Invariants every transaction must satisfy before signing, whether it was
/// built by `prepare` or supplied as raw bytes by a third party. Fixed check
/// order (chain id, gas, fees) so a multiply-invalid tx reports the same
/// error everywhere it is validated.
pub fn validate_unsigned(tx: &EthTx) -> Result<(), PrepareError> {
    match tx.chain_id() {
        // Only a pre-EIP-155 legacy tx decodes to None — refuse the replay-
        // unprotected form with its own error, not a generic zero.
        None => return Err(PrepareError::MissingChainId),
        Some(0) => return Err(PrepareError::ZeroChainId),
        Some(_) => {}
    }
    if tx.gas_limit() == 0 {
        return Err(PrepareError::ZeroGasLimit);
    }
    // The two-fee invariant only exists on 1559; legacy/2930's single
    // gas_price has no cross-field constraint.
    if let EthTx::Eip1559(tx) = tx
        && tx.max_priority_fee_per_gas > tx.max_fee_per_gas
    {
        return Err(PrepareError::MaxPriorityFeeExceedsMaxFee);
    }
    Ok(())
}

#[cfg(feature = "rpc")]
pub async fn enrich<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<TxIntent, EnrichError> {
    tracing::debug!(from = %from, "enriching tx from RPC");

    let kind = req.to.map_or(TxKind::Create, TxKind::Call);

    let eth_chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(from).pending().await?;

    let params = match req.tx_type {
        EthTxType::Legacy => TxParams::Legacy {
            gas_price: provider.get_gas_price().await?,
        },
        EthTxType::Eip2930 => TxParams::Eip2930 {
            gas_price: provider.get_gas_price().await?,
            access_list: req.access_list.clone(),
        },
        EthTxType::Eip1559 => {
            let fees = provider.estimate_eip1559_fees().await?;
            TxParams::Eip1559 {
                max_fee_per_gas: fees.max_fee_per_gas,
                max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                access_list: req.access_list.clone(),
            }
        }
    };

    let tx_req = TransactionRequest {
        from: Some(from),
        to: Some(kind),
        value: Some(req.value),
        input: req.data.clone().into(),
        // The access list changes gas accounting (EIP-2930 discounts), so
        // the estimate must see it.
        access_list: (!req.access_list.is_empty()).then(|| req.access_list.clone()),
        ..Default::default()
    };

    let gas_limit = provider.estimate_gas(tx_req).await?;

    tracing::debug!(
        chain_id = eth_chain_id,
        nonce,
        gas_limit,
        ?params,
        "enrichment complete"
    );

    Ok(TxIntent {
        chain_id: eth_chain_id,
        nonce,
        kind,
        value: req.value,
        gas_limit,
        data: req.data,
        params,
    })
}

#[cfg(feature = "rpc")]
pub fn http_provider(url: &str) -> Result<impl Provider + use<>, ProviderError> {
    let url = Url::parse(url)?;
    Ok(ProviderBuilder::new().connect_http(url))
}
