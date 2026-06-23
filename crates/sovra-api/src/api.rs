use crate::errors::ApiError;
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, TxNonce, U256};
use alloy_provider::DynProvider;
use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use sovra_eth::{PreparedTx, TxRequest, prepare_from_rpc};
use utoipa::{OpenApi, ToSchema};

#[utoipa::path(post, path = "/v1/prepare", request_body = PrepareRequest)]
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

#[derive(Deserialize, Default, Debug, ToSchema)]
pub struct PrepareRequest {
    #[schema(value_type = String)]
    from: Address,
    #[schema(value_type = String)]
    to: Address,
    #[schema(value_type = String, example = "0")]
    value: U256,
    #[schema(value_type = String)]
    data: Bytes,
}

#[derive(Serialize, ToSchema)]
pub struct PrepareResponse {
    #[schema(value_type = String)]
    signing_hash: B256,
    #[schema(value_type = u64)]
    chain_id: ChainId,
    #[schema(value_type = u64)]
    nonce: TxNonce,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    #[schema(value_type = String)]
    to: Address,
    #[schema(value_type = String, example = "0")]
    value: U256,
    #[schema(value_type = String)]
    data: Bytes,
}

#[derive(OpenApi)]
#[openapi(paths(prepare,), components(schemas(PrepareRequest, PrepareResponse),))]
pub struct ApiDoc;
