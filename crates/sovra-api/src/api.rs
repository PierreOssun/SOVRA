use crate::errors::ApiError;
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, TxNonce, U256};
use alloy_provider::DynProvider;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use sovra_eth::{PreparedTx, TxRequest, prepare_from_rpc};

pub async fn prepare(
    State(state): State<AppState>,
    Json(body): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ApiError> {
    let req = TxRequest {
        to: body.to,
        value: body.value,
        data: body.data,
    };

    let PreparedTx { tx, signing_hash } = prepare_from_rpc(req, body.from, &state.provider).await?;

    let to = match tx.to {
        TxKind::Call(addr) => addr,
        TxKind::Create => unreachable!("prepare always supports TxKind::Call for now"),
    };

    Ok(Json(PrepareResponse {
        signing_hash: signing_hash,
        chain_id: tx.chain_id,
        nonce: tx.nonce,
        gas_limit: tx.gas_limit,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        to,
        value: tx.value,
        data: tx.input,
    }))
}

#[derive(Clone)]
pub struct AppState {
    pub provider: DynProvider,
}

#[derive(Deserialize, Default, Debug)]
pub struct PrepareRequest {
    from: Address,
    to: Address,
    value: U256,
    data: Bytes,
}

#[derive(Serialize)]
pub struct PrepareResponse {
    signing_hash: B256,
    chain_id: ChainId,
    nonce: TxNonce,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    to: Address,
    value: U256,
    data: Bytes,
}
