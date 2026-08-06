//! HTTP handlers for the public API (`/v1/dkg`, `/v1/prepare`, `/v1/sign`),
//! their request/response DTOs, and the OpenAPI doc ([`ApiDoc`]).
//!
//! Why generic over `B: MpcBackend`: handlers never name a concrete backend,
//! so integration tests drive the same code with the in-process backend while
//! production uses `RemoteBackend` — the HTTP contract is pinned independently
//! of the MPC transport. Two invariants live here on purpose: `sign` decodes
//! and *recomputes* the digest (a caller-supplied hash is never trusted), and
//! `finalize` checks the recovered signer against the active address.
//! Concurrency: idempotency-cache read → `try_lock` (busy = 409, never queue)
//! → re-check cache under the lock. utoipa annotations are colocated with each
//! handler so the Swagger docs can't drift from the code.
//! Pattern: thin controllers over the `MpcBackend` port; wire DTOs kept
//! separate from domain types.

use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use sovra_eth::{
    PreparedTx, TxRequest, decode_unsigned, encode_unsigned, finalize, prepare::validate_unsigned,
    prepare_from_rpc,
};
use sovra_mpc::MpcBackend;
use utoipa::{OpenApi, ToSchema};

use crate::{errors::ApiError, state::AppState};

#[utoipa::path(post, path = "/v1/prepare", request_body = PrepareRequest)]
pub async fn prepare<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
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
pub async fn dkg_create<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
) -> Result<Json<DkgResponse>, ApiError> {
    let _op = state
        .signer
        .op
        .try_lock()
        .map_err(|_| ApiError::SigningInProgress)?;

    if state.signer.state.read().unwrap().active.is_some() {
        return Err(ApiError::DkgAlreadyInitialized);
    }

    let address = state.backend.dkg().await?;
    state.signer.state.write().unwrap().active = Some(address);

    tracing::info!(%address, "dkg complete");
    Ok(Json(DkgResponse { address }))
}

/// Operator endpoint: the recovery re-share ceremony. All n cosigners
/// (including the normally-cold recovery party) must be online; the
/// declared-lost party rebuilds its shard from scratch, every other shard
/// re-randomizes, and the address must come back unchanged — a different
/// one is a broken invariant, not a result.
#[utoipa::path(post, path = "/v1/recover", request_body = RecoverRequest)]
pub async fn recover<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
    Json(body): Json<RecoverRequest>,
) -> Result<Json<DkgResponse>, ApiError> {
    let _op = state
        .signer
        .op
        .try_lock()
        .map_err(|_| ApiError::SigningInProgress)?;

    let active = state
        .signer
        .state
        .read()
        .unwrap()
        .active
        .ok_or(ApiError::DkgNotInitialized)?;

    let address = state.backend.refresh(body.lost_party).await?;
    if address != active {
        return Err(ApiError::Mpc(sovra_mpc::MpcError::PartyMismatch(format!(
            "refresh returned {address}, active generation is {active}"
        ))));
    }

    tracing::info!(%address, lost_party = body.lost_party, "recovery re-share complete");
    Ok(Json(DkgResponse { address }))
}

#[utoipa::path(get, path = "/v1/dkg")]
pub async fn dkg_get<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
) -> Result<Json<DkgResponse>, ApiError> {
    let active = state.signer.state.read().unwrap().active;
    active
        .map(|address| Json(DkgResponse { address }))
        .ok_or(ApiError::DkgNotFound)
}
#[utoipa::path(post, path = "/v1/sign", request_body = SignRequest)]
pub async fn sign<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
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

    let parts = state.backend.sign(&body.unsigned_transaction).await?;

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

#[derive(Deserialize, ToSchema)]
pub struct RecoverRequest {
    /// Global id of the party whose shard is being rebuilt. Its store must
    /// be empty (a rebuilt host), and its new identity must already be in
    /// every party's pinned roster.
    pub lost_party: u8,
}

#[derive(OpenApi)]
#[openapi(
    paths(dkg_create, dkg_get, prepare, sign, recover),
    components(schemas(
        DkgResponse,
        PrepareRequest,
        PrepareResponse,
        RecoverRequest,
        SignRequest,
        SignatureParts,
        SignResponse
    ))
)]
pub struct ApiDoc;
