use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::Address;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use url::Url;

use crate::{EnrichError, PrepareError, PreparedTx, ProviderError, TxIntent, TxRequest};

pub async fn prepare_from_rpc_impl<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<PreparedTx, PrepareError> {
    let tx_intent = enrich(req, from, provider).await?;
    prepare(tx_intent)
}

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

pub async fn enrich<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<TxIntent, EnrichError> {
    tracing::debug!(from = %from, "enriching tx from RPC");

    let eth_chain_id = provider.get_chain_id().await?;
    let nonce = provider.get_transaction_count(from).pending().await?;
    let fees = provider.estimate_eip1559_fees().await?;

    let tx_req = TransactionRequest {
        from: Some(from),
        to: Some(req.to.into()),
        value: Some(req.value),
        input: req.data.clone().into(),
        ..Default::default()
    };

    let gas_limit = provider.estimate_gas(tx_req).await?;

    tracing::debug!(
        chain_id = eth_chain_id,
        nonce,
        gas_limit,
        max_fee = fees.max_fee_per_gas,
        "enrichment complete"
    );

    let tx_intent = TxIntent {
        chain_id: eth_chain_id,
        nonce,
        to: req.to,
        value: req.value,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        data: req.data,
    };

    Ok(tx_intent)
}

pub fn http_provider(url: &str) -> Result<impl Provider + use<>, ProviderError> {
    let url = Url::parse(url)?;
    Ok(ProviderBuilder::new().connect_http(url))
}
