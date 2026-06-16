use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use sovra_eth::PrepareError;

pub struct ApiError(pub PrepareError);

impl From<PrepareError> for ApiError {
    fn from(e: PrepareError) -> Self { ApiError(e) }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            PrepareError::Enrich(_) => StatusCode::BAD_GATEWAY,
            PrepareError::ZeroChainId
            | PrepareError::ZeroGasLimit
            | PrepareError::MaxPriorityFeeExceedsMaxFee => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({ "error": self.0.to_string() }))).into_response()
    }
}