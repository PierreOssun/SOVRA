//! Control-plane handlers: `/dkg` and `/sign` run this party's half of an MPC
//! protocol; `/signer` is the recovery probe; `/identity` and `/health` serve
//! operator setup and liveness.
//!
//! The shape both MPC handlers share is deliberate: `try_lock` the op mutex
//! (busy = 409, never queue) → check shard preconditions → build the
//! `PartyContext` → dial the hub fresh (`WsRelay::connect`, one connection per
//! run, dropped at the end — no reconnect state to manage) → drive the party
//! runner under `tokio::time::timeout(ttl)`. The timeout is what frees the op
//! lock when the peer never joins; without it one dead peer would wedge this
//! cosigner forever (a bug the split_flow gate test caught).
//! Pattern: thin controllers delegating to `sovra-mpc-dkls23-silence`
//! runners; wire types come from `sovra_ipc::control`.

use std::sync::Arc;

use axum::{Json, extract::State};
use sovra_ipc::{
    client::WsRelay,
    control::{Identity, SignParts, SignerInfo, StartDkgRequest, StartSignRequest},
};
use sovra_mpc_dkls23_silence::{keygen_party, sign_party};
use sovra_state::StateError;
use sovra_types::{ACTIVE_SIGNER_ID, SignerId, SignerMetadata};

use crate::{errors::CosignerError, state::CosignerState};

pub async fn dkg(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartDkgRequest>,
) -> Result<Json<SignerInfo>, CosignerError> {
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    let id = SignerId::new(ACTIVE_SIGNER_ID);
    match state.store.load_metadata(&id) {
        Ok(_) => return Err(CosignerError::ShardExists),
        Err(StateError::NotFound(_)) => {}
        Err(e) => return Err(e.into()),
    }
    let ctx = state.ctx(req.instance)?;
    let relay = WsRelay::connect(&state.relay_url).await?; // dial per run, 502 on refusal
    let (share, address) = tokio::time::timeout(state.ttl, keygen_party(&ctx, relay))
        .await
        .map_err(|_| CosignerError::RunTimeout)??;
    state.store.save_shard(
        &SignerMetadata {
            signer_id: id,
            address,
        },
        &share,
    )?;
    Ok(Json(SignerInfo { address }))
}

pub async fn sign(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartSignRequest>,
) -> Result<Json<SignParts>, CosignerError> {
    // 1. Decode the raw payload and derive the digest OURSELVES — the wire
    //    deliberately carries no digest (see StartSignRequest). A cosigner
    //    that signs what it decoded can never be made to sign what it didn't.
    let prepared = sovra_eth::decode_unsigned(&req.unsigned_transaction)
        .map_err(|e| CosignerError::BadTransaction(e.to_string()))?;
    sovra_eth::prepare::validate_unsigned(&prepared.tx)
        .map_err(|e| CosignerError::BadTransaction(e.to_string()))?;

    // 2. Policy gate, fail closed — no [policy] means no signatures. Runs
    //    before the op lock and before any relay dial: a rejected request
    //    must leave zero cryptographic footprint.
    let policy = state
        .policy
        .as_ref()
        .ok_or(crate::policy::PolicyReject::NoPolicyConfigured)?;
    policy.check_tx(&prepared.tx)?;

    // 3. Only now: exclusivity, shard, MPC — unchanged from before.
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    let share = match state.store.load_shard(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(s) => s,
        Err(StateError::NotFound(_)) => return Err(CosignerError::NoShard),
        Err(e) => return Err(e.into()),
    };
    let ctx = state.ctx(req.instance)?;
    let relay = WsRelay::connect(&state.relay_url).await?;
    let parts = tokio::time::timeout(
        state.ttl,
        sign_party(&ctx, &share, prepared.signing_hash, relay),
    )
    .await
    .map_err(|_| CosignerError::RunTimeout)??;
    Ok(Json(parts.into()))
}

pub async fn signer(
    State(state): State<Arc<CosignerState>>,
) -> Result<Json<SignerInfo>, CosignerError> {
    match state.store.load_active(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(Some(address)) => Ok(Json(SignerInfo { address })),
        Ok(None) => Err(CosignerError::NoSigner),
        Err(e) => Err(e.into()),
    }
}

pub async fn identity(State(state): State<Arc<CosignerState>>) -> Json<Identity> {
    Json(Identity {
        verifying_key: alloy_primitives::hex::encode(state.signing_key.verifying_key().as_bytes()),
    })
}

pub async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
