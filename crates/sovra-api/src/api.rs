use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use sovra_eth::{
    PreparedTx, TxRequest, decode_unsigned, encode_unsigned, finalize, prepare::validate_unsigned,
    prepare_from_rpc,
};
use sovra_mpc::MpcBackend;
use utoipa::{OpenApi, ToSchema};

use crate::{errors::ApiError, orchestrator, state::AppState};

#[utoipa::path(post, path = "/v1/prepare", request_body = PrepareRequest)]
pub async fn prepare(
    State(state): State<AppState>,
    Json(body): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ApiError> {
    let from = state
        .signer
        .state
        .read()
        .unwrap()
        .active
        .ok_or(ApiError::DkgNotInitialized)?;

    tracing::info!(%from, to = %body.to, value = %body.value, "prepare request");

    let req = TxRequest {
        to: body.to,
        value: body.value,
        data: body.data,
    };
    let PreparedTx { tx, signing_hash } = prepare_from_rpc(req, from, &state.provider).await?;

    tracing::info!(tx_digest = %signing_hash, nonce = tx.nonce, "prepare ok");

    Ok(Json(PrepareResponse {
        from,
        unsigned_transaction: encode_unsigned(&tx),
        tx_digest: signing_hash,
    }))
}

#[utoipa::path(post, path = "/v1/dkg")]
pub async fn dkg_create(State(state): State<AppState>) -> Result<Json<DkgResponse>, ApiError> {
    let _op = state
        .signer
        .op
        .try_lock()
        .map_err(|_| ApiError::SigningInProgress)?;

    if state.signer.state.read().unwrap().active.is_some() {
        return Err(ApiError::DkgAlreadyInitialized);
    }

    let address = orchestrator::run_dkg(&state.backend, &state.stores).await?;
    state.signer.state.write().unwrap().active = Some(address);

    tracing::info!(%address, "dkg complete");
    Ok(Json(DkgResponse { address }))
}

#[utoipa::path(get, path = "/v1/dkg")]
pub async fn dkg_get(State(state): State<AppState>) -> Result<Json<DkgResponse>, ApiError> {
    let active = state.signer.state.read().unwrap().active;
    active
        .map(|address| Json(DkgResponse { address }))
        .ok_or(ApiError::DkgNotFound)
}
#[utoipa::path(post, path = "/v1/sign", request_body = SignRequest)]
pub async fn sign(
    State(state): State<AppState>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    // 1. Decode + recompute the digest. Never trust a caller-supplied hash.
    let prepared = decode_unsigned(&body.unsigned_transaction)?;
    validate_unsigned(&prepared.tx)?;
    let tx_digest = prepared.signing_hash;

    // 2. Idempotency + readiness in one short read.
    let active = {
        let signer = state.signer.state.read().unwrap();
        if let Some(cached) = signer.signed.get(&tx_digest) {
            tracing::info!(%tx_digest, "sign cache hit");
            return Ok(Json(cached.clone()));
        }
        signer.active.ok_or(ApiError::DkgNotInitialized)?
    };

    // 3. Global MPC exclusivity — busy means 409, never queue.
    let _op = state
        .signer
        .op
        .try_lock()
        .map_err(|_| ApiError::SigningInProgress)?;

    // Re-check under the lock: another request may have signed this digest
    // between our cache read above and this lock acquisition.
    if let Some(cached) = state.signer.state.read().unwrap().signed.get(&tx_digest) {
        tracing::info!(%tx_digest, "sign cache hit");
        return Ok(Json(cached.clone()));
    }

    let shards = orchestrator::load_shards(&state.stores)?;
    let parts = state.backend.sign(tx_digest, &shards).await?;

    // Load-bearing safety check: recovered signer must be the active address.
    let signed = finalize(prepared, parts.r, parts.s, parts.y_parity, active)?;

    let response = SignResponse {
        signed_transaction: signed.raw,
        signature: SignatureParts {
            r: parts.r,
            s: parts.s,
            y_parity: parts.y_parity,
        },
        recovered_address: signed.from,
        tx_digest,
    };
    state
        .signer
        .state
        .write()
        .unwrap()
        .signed
        .insert(tx_digest, response.clone());

    tracing::info!(%tx_digest, address = %signed.from, "sign complete");
    Ok(Json(response))
}

#[derive(Deserialize, ToSchema)]
pub struct PrepareRequest {
    #[schema(value_type = String)]
    to: Address,
    #[schema(value_type = String, example = "0")]
    value: U256,
    #[serde(default)]
    #[schema(value_type = String)]
    data: Bytes,
}

#[derive(Serialize, ToSchema)]
pub struct PrepareResponse {
    #[schema(value_type = String)]
    from: Address,
    #[schema(value_type = String)]
    unsigned_transaction: Bytes,
    #[schema(value_type = String)]
    tx_digest: B256,
}

#[derive(Clone, Serialize, ToSchema)]
pub struct SignatureParts {
    #[schema(value_type = String)]
    pub r: U256,
    #[schema(value_type = String)]
    pub s: U256,
    pub y_parity: bool,
}

#[derive(Clone, Serialize, ToSchema)]
pub struct SignResponse {
    #[schema(value_type = String)]
    pub signed_transaction: Bytes,
    pub signature: SignatureParts,
    #[schema(value_type = String)]
    pub recovered_address: Address,
    #[schema(value_type = String)]
    pub tx_digest: B256,
}

#[derive(Serialize, ToSchema)]
pub struct DkgResponse {
    #[schema(value_type = String)]
    pub address: Address,
}

#[derive(Deserialize, ToSchema)]
pub struct SignRequest {
    #[schema(value_type = String)]
    unsigned_transaction: Bytes,
}

#[derive(OpenApi)]
#[openapi(
    paths(dkg_create, dkg_get, prepare, sign),
    components(schemas(
        DkgResponse,
        PrepareRequest,
        PrepareResponse,
        SignRequest,
        SignatureParts,
        SignResponse
    ))
)]
pub struct ApiDoc;
