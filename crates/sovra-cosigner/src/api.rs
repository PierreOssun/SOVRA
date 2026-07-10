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
    let (share, address) = tokio::time::timeout(state.ttl, keygen_party(&ctx, relay)) // was: keygen_party(&ctx, relay).await?
        .await
        .map_err(|_| CosignerError::RunTimeout)??;
    state.store.save_shard(
        &SignerMetadata {
            signer_id: id,
            address,
        },
        &share,
    )?;
    // The address is self-derived from our own shard — the orchestrator
    // cross-checks it against the peer's answer.
    Ok(Json(SignerInfo { address }))
}

pub async fn sign(
    State(state): State<Arc<CosignerState>>,
    Json(req): Json<StartSignRequest>,
) -> Result<Json<SignParts>, CosignerError> {
    let _op = state.op.try_lock().map_err(|_| CosignerError::Busy)?;
    let share = match state.store.load_shard(&SignerId::new(ACTIVE_SIGNER_ID)) {
        Ok(s) => s,
        Err(StateError::NotFound(_)) => return Err(CosignerError::NoShard),
        Err(e) => return Err(e.into()),
    };
    let ctx = state.ctx(req.instance)?;
    let relay = WsRelay::connect(&state.relay_url).await?;
    let parts = sign_party(&ctx, &share, req.tx_digest, relay).await?;
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
