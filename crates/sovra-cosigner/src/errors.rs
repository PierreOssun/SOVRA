use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

#[derive(thiserror::Error, Debug)]
pub enum CosignerError {
    #[error("an mpc run is already in progress")]
    Busy, // 409
    #[error("a key shard already exists; refusing to overwrite")]
    ShardExists, // 409
    #[error("no key shard; run dkg first")]
    NoShard, // 409
    #[error("peer verifying key not configured")]
    PeerKeyUnset, // 409
    #[error("no active signer")]
    NoSigner, // 404
    #[error("relay connection failed: {0}")]
    Relay(#[from] sovra_ipc::types::IpcError), // 502
    #[error("mpc run failed: {0}")]
    Mpc(#[from] sovra_mpc::MpcError), // 502
    #[error(transparent)]
    State(#[from] sovra_state::StateError), // 500
    #[error("identity key error: {0}")]
    Identity(String), // 500
    #[error("mpc run timed out; peer never joined or stalled mid-run")]
    RunTimeout, // 502
}

impl IntoResponse for CosignerError {
    fn into_response(self) -> Response {
        use CosignerError::*;
        let (status, message) = match &self {
            Busy | ShardExists | NoShard | PeerKeyUnset => (StatusCode::CONFLICT, self.to_string()),
            NoSigner => (StatusCode::NOT_FOUND, self.to_string()),
            Relay(_) | Mpc(_) | RunTimeout => (StatusCode::BAD_GATEWAY, self.to_string()),
            State(_) | Identity(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal storage error".to_string(),
            ),
        };
        tracing::error!(error = %self, "request failed");
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
