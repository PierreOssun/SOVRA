use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sovra_eth::{DecodeError, FinalizeError, PrepareError};
use sovra_mpc::MpcError;
use sovra_state::StateError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error(transparent)]
    Prepare(#[from] PrepareError),

    #[error("invalid transaction bytes: {0}")]
    InvalidTxBytes(#[from] DecodeError),

    #[error("dkg already initialized")]
    DkgAlreadyInitialized,

    #[error("dkg not initialized")]
    DkgNotInitialized,

    #[error("no active dkg generation")]
    DkgNotFound,

    #[error("another signing operation is in progress")]
    SigningInProgress,

    #[error(transparent)]
    Mpc(#[from] MpcError),

    #[error(transparent)]
    State(#[from] StateError),

    #[error(transparent)]
    Finalize(#[from] FinalizeError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::Prepare(PrepareError::Enrich(_)) => {
                (StatusCode::BAD_GATEWAY, "rpc enrichment failed".to_string())
            }
            ApiError::Prepare(_) | ApiError::InvalidTxBytes(_) => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }

            ApiError::DkgAlreadyInitialized
            | ApiError::DkgNotInitialized
            | ApiError::SigningInProgress => (StatusCode::CONFLICT, self.to_string()),

            ApiError::DkgNotFound => (StatusCode::NOT_FOUND, self.to_string()),

            ApiError::Mpc(MpcError::Deserialize) | ApiError::State(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal storage error".to_string(),
            ),
            ApiError::Mpc(_) => (StatusCode::BAD_GATEWAY, "mpc protocol failed".to_string()),
            ApiError::Finalize(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "signature verification failed".to_string(),
            ),
        };

        if status.is_server_error() {
            tracing::error!(err = %self, %status, "request failed");
        }

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}
