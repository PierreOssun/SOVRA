//! HTTP handlers for the public API (`/v1/dkg`, `/v1/prepare`, `/v1/sign`,
//! `/v1/broadcast`), their request/response DTOs, and the OpenAPI doc
//! ([`ApiDoc`]).
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

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, Bytes, U256};
use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use sovra_eth::{
    AccessList, BroadcastOutcome, EthTxType, PreparedTx, TxRequest, address_from_sec1,
    broadcast_via_rpc, decode_signed, encode_unsigned, prepare_from_rpc,
};
use sovra_mpc::MpcBackend;
use sovra_network::Network;
use sovra_types::{NetworkId, PubkeySec1};
use utoipa::{OpenApi, ToSchema};

use crate::{errors::ApiError, state::AppState};

#[utoipa::path(post, path = "/v1/prepare", request_body = PrepareRequest)]
pub async fn prepare<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
    Json(body): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ApiError> {
    // Enrichment I/O is deliberately outside the Network trait (fee
    // estimation and UTXO selection don't share a shape) — a new network
    // adds its own concrete arm here.
    let NetworkId::Ethereum = body.network;
    let active = state
        .signer
        .state
        .read()
        .unwrap()
        .active
        .ok_or(ApiError::DkgNotInitialized)?;
    let from = address_from_sec1(&active)?;

    tracing::info!(%from, to = ?body.to, value = %body.value, tx_type = ?body.tx_type, "prepare request");

    let req = TxRequest {
        to: body.to,
        value: body.value,
        data: body.data,
        tx_type: body.tx_type,
        access_list: body.access_list,
    };
    let PreparedTx { tx, signing_hash } = prepare_from_rpc(req, from, &state.provider).await?;

    tracing::info!(tx_digest = %signing_hash, nonce = tx.nonce(), "prepare ok");

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

    let public_key = state.backend.dkg().await?;
    state.signer.state.write().unwrap().active = Some(public_key);

    tracing::info!(%public_key, "dkg complete");
    DkgResponse::new(public_key).map(Json)
}

/// Operator endpoint: the recovery re-share ceremony. All n cosigners
/// (including the normally-cold recovery party) must be online; the
/// declared-lost party rebuilds its shard from scratch, every other shard
/// re-randomizes, and the public key must come back unchanged — a different
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

    let public_key = state.backend.refresh(body.lost_party).await?;
    if public_key != active {
        return Err(ApiError::Mpc(sovra_mpc::MpcError::PartyMismatch(format!(
            "refresh returned {public_key}, active generation is {active}"
        ))));
    }

    tracing::info!(%public_key, lost_party = body.lost_party, "recovery re-share complete");
    DkgResponse::new(public_key).map(Json)
}

#[utoipa::path(get, path = "/v1/dkg")]
pub async fn dkg_get<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
) -> Result<Json<DkgResponse>, ApiError> {
    let active = state.signer.state.read().unwrap().active;
    let public_key = active.ok_or(ApiError::DkgNotFound)?;
    DkgResponse::new(public_key).map(Json)
}
#[utoipa::path(post, path = "/v1/sign", request_body = SignRequest)]
pub async fn sign<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
    Json(body): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    // The one dispatch point: the tag picks the Network impl, everything
    // below is generic. A new network is a new arm here (and the compiler
    // holds the door until it exists).
    match body.network {
        NetworkId::Ethereum => {
            sign_via::<sovra_eth::Ethereum, B>(&state, &body.unsigned_transaction).await
        }
    }
}

async fn sign_via<N: Network, B: MpcBackend + Send + Sync + 'static>(
    state: &AppState<B>,
    unsigned: &Bytes,
) -> Result<Json<SignResponse>, ApiError> {
    // 1. Decode + recompute the digests. Never trust a caller-supplied hash.
    let tx = N::decode_unsigned(unsigned)?;
    N::validate(&tx)?;
    let digests = N::signing_digests(&tx);
    // Idempotency key: the first digest. Fine while every network signs one
    // digest; a multi-digest network should key on a hash of the full list.
    let tx_digest = B256::from(digests[0]);

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

    let parts = state.backend.sign(N::ID, unsigned).await?;

    // Load-bearing safety check, inside the impl: finalize verifies every
    // recovered signer against the active key before emitting bytes.
    let signed = N::finalize(tx, &parts, &active)?;

    let response = SignResponse {
        network: N::ID,
        signed_transaction: signed.raw,
        signatures: parts
            .iter()
            .map(|p| SignatureParts {
                r: p.r,
                s: p.s,
                y_parity: p.y_parity,
            })
            .collect(),
        signer_address: N::derive_address(&active)?,
        tx_digest,
    };
    state
        .signer
        .state
        .write()
        .unwrap()
        .signed
        .insert(tx_digest, response.clone());

    tracing::info!(%tx_digest, signer = %response.signer_address, "sign complete");
    Ok(Json(response))
}

#[derive(Deserialize, ToSchema)]
pub struct PrepareRequest {
    /// Absent means "ethereum" — existing callers keep working.
    #[serde(default)]
    #[schema(value_type = String, example = "ethereum")]
    network: NetworkId,
    /// Omit (or null) to request contract creation — `data` is the init
    /// code and the cosigners' policies must allow creation.
    #[schema(value_type = Option<String>)]
    to: Option<Address>,
    #[schema(value_type = String, example = "0")]
    value: U256,
    #[serde(default)]
    #[schema(value_type = String)]
    data: Bytes,
    /// "legacy" | "eip2930" | "eip1559" (default).
    #[serde(default)]
    #[schema(value_type = String, example = "eip1559")]
    tx_type: EthTxType,
    /// EIP-2930 access list; rejected for legacy. Entries:
    /// `{ "address": "0x…", "storageKeys": ["0x…"] }`.
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    access_list: AccessList,
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
    #[schema(value_type = String, example = "ethereum")]
    pub network: NetworkId,
    #[schema(value_type = String)]
    pub signed_transaction: Bytes,
    /// One per digest the network defines (Ethereum: exactly one).
    pub signatures: Vec<SignatureParts>,
    /// The active key's address on `network`, verified against the
    /// signature(s) during finalize.
    pub signer_address: String,
    #[schema(value_type = String)]
    pub tx_digest: B256,
}

/// Submit a signed transaction to the chain and wait (bounded) for its
/// receipt: 200 = mined within the window, 202 = accepted by the node but
/// still pending when the window closed (verify by tx_hash on Etherscan).
///
/// Deliberately does NOT take the `op` lock: that lock encodes MPC
/// exclusivity, and broadcast is a plain RPC relay — holding it through up
/// to 30 s of receipt polling would 409 every sign for no custody benefit.
/// A concurrent double-broadcast is neutralized by the chain itself (node
/// dedup / nonce rules), and a rejected re-submit of a mined tx comes back
/// as 200 via the receipt recheck in `broadcast_via_rpc`.
#[utoipa::path(post, path = "/v1/broadcast", request_body = BroadcastRequest)]
pub async fn broadcast<B: MpcBackend + Send + Sync + 'static>(
    State(state): State<AppState<B>>,
    Json(body): Json<BroadcastRequest>,
) -> Result<(StatusCode, Json<BroadcastResponse>), ApiError> {
    // Broadcast I/O stays per-network concrete, like prepare's enrichment.
    let NetworkId::Ethereum = body.network;
    // Cheap in-memory guard first: nothing works before DKG, regardless of
    // payload (same 409 semantics as prepare), and no caller bytes are
    // parsed before it passes.
    let active = state
        .signer
        .state
        .read()
        .unwrap()
        .active
        .ok_or(ApiError::DkgNotInitialized)?;

    // Decode + recover the signer from the bytes themselves — the caller's
    // word is never taken for the hash or the sender, and the orchestrator
    // only relays transactions produced by its own signer (not an open relay).
    let decoded = decode_signed(&body.signed_transaction)?;
    let active = address_from_sec1(&active)?;
    if decoded.from != active {
        return Err(ApiError::BroadcastSignerMismatch {
            recovered: decoded.from,
            active,
        });
    }

    tracing::info!(tx_hash = %decoded.tx_hash, from = %decoded.from, "broadcast request");

    let outcome = broadcast_via_rpc(
        &decoded.raw,
        decoded.tx_hash,
        &state.provider,
        state.broadcast.timeout,
        state.broadcast.poll,
    )
    .await?;

    let (status, response) = match outcome {
        BroadcastOutcome::Confirmed(receipt) => (
            StatusCode::OK,
            BroadcastResponse {
                tx_hash: decoded.tx_hash,
                status: BroadcastStatus::Confirmed,
                block_number: receipt.block_number,
                gas_used: Some(receipt.gas_used),
                execution_success: Some(receipt.status()),
            },
        ),
        BroadcastOutcome::Pending => (
            StatusCode::ACCEPTED,
            BroadcastResponse {
                tx_hash: decoded.tx_hash,
                status: BroadcastStatus::Pending,
                block_number: None,
                gas_used: None,
                execution_success: None,
            },
        ),
    };

    tracing::info!(tx_hash = %response.tx_hash, status = ?response.status, "broadcast done");
    Ok((status, Json(response)))
}

#[derive(Serialize, ToSchema)]
pub struct DkgResponse {
    /// The chain-neutral key identity (33-byte compressed SEC1, hex).
    #[schema(value_type = String)]
    pub public_key: PubkeySec1,
    /// Per-network display addresses derived from `public_key`.
    #[schema(value_type = Object)]
    pub addresses: BTreeMap<NetworkId, String>,
}

impl DkgResponse {
    fn new(public_key: PubkeySec1) -> Result<Self, ApiError> {
        // {:#x} = lowercase hex, matching how serde renders every other
        // Address field in this API (Display would be EIP-55 checksummed).
        let addresses = BTreeMap::from([(
            NetworkId::Ethereum,
            format!("{:#x}", address_from_sec1(&public_key)?),
        )]);
        Ok(Self {
            public_key,
            addresses,
        })
    }
}

#[derive(Deserialize, ToSchema)]
pub struct SignRequest {
    /// Absent means "ethereum" — existing callers keep working.
    #[serde(default)]
    #[schema(value_type = String, example = "ethereum")]
    network: NetworkId,
    #[schema(value_type = String)]
    unsigned_transaction: Bytes,
}

#[derive(Deserialize, ToSchema)]
pub struct BroadcastRequest {
    /// Absent means "ethereum" — existing callers keep working.
    #[serde(default)]
    #[schema(value_type = String, example = "ethereum")]
    network: NetworkId,
    /// Signed EIP-2718 bytes as returned by `/v1/sign` (0x01/0x02-prefixed,
    /// or a bare RLP list for legacy).
    #[schema(value_type = String)]
    signed_transaction: Bytes,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastStatus {
    Confirmed,
    Pending,
}

#[derive(Serialize, ToSchema)]
pub struct BroadcastResponse {
    #[schema(value_type = String)]
    pub tx_hash: B256,
    pub status: BroadcastStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<u64>,
    /// `receipt.status()`: false = mined but reverted. A revert is
    /// chain-level execution, not a broadcast failure — still 200.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_success: Option<bool>,
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
    paths(dkg_create, dkg_get, prepare, sign, broadcast, recover),
    components(schemas(
        BroadcastRequest,
        BroadcastResponse,
        BroadcastStatus,
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
