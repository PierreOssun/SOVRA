//! The cosigner error type and its HTTP mapping.
//!
//! Same facade pattern as sovra-api's `errors.rs`: `#[from]` conversions let
//! handlers use `?`, and one `IntoResponse` impl decides status codes.
//! Semantics matter to the orchestrator: 409 = precondition/concurrency
//! (busy, shard state, unpinned peer — retryable after operator action),
//! 422 = the request body is not a well-formed unsigned EIP-1559 tx (this
//! cosigner refuses to sign what it cannot decode), 502 = the MPC run itself
//! failed or timed out (relay, protocol, peer absent), 500 = local
//! storage/identity is broken. Storage detail is logged, not returned.
//! Pattern: error facade at the HTTP boundary.

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
    #[error("invalid transaction bytes: {0}")]
    Undecodable(String), // 422
    #[error("policy denied: {0}")]
    PolicyDenied(sovra_policy::DenyReason), // 403
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
        let (status, body) = match &self {
            Busy | ShardExists | NoShard | PeerKeyUnset => (
                StatusCode::CONFLICT,
                serde_json::json!({ "error": self.to_string() }),
            ),
            Undecodable(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                serde_json::json!({ "error": self.to_string() }),
            ),
            // A deny is a decision, not a failure. The separate "reason"
            // field is the contract remote.rs parses to attribute the veto.
            PolicyDenied(reason) => (
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": "policy denied", "reason": reason.to_string() }),
            ),
            NoSigner => (
                StatusCode::NOT_FOUND,
                serde_json::json!({ "error": self.to_string() }),
            ),
            Relay(_) | Mpc(_) | RunTimeout => (
                StatusCode::BAD_GATEWAY,
                serde_json::json!({ "error": self.to_string() }),
            ),
            State(_) | Identity(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({ "error": "internal storage error" }),
            ),
        };
        tracing::error!(error = %self, "request failed");
        (status, Json(body)).into_response()
    }
}
