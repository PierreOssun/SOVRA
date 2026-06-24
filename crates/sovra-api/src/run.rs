use alloy_provider::Provider;
use axum::{Router, routing::post};
use sovra_eth::http_provider;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    api,
    api::{ApiDoc, AppState},
    config::Config,
};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let provider = http_provider(&config.rpc_url)?.erased();
    let state = AppState { provider };

    let app = Router::new()
        .route("/v1/prepare", post(api::prepare))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;

    tracing::info!("listening on {}", config.bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
