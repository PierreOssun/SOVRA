use alloy_provider::Provider;
use axum::{Router, response::Response, routing::post};
use sovra_eth::http_provider;
use sovra_state::SignerStore;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{api, api::ApiDoc, config::Config, orchestrator, state::AppState};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let provider = http_provider(&config.rpc_url)?.erased();
    let stores = [
        SignerStore::open(&config.party0_dir)?,
        SignerStore::open(&config.party1_dir)?,
    ];

    let active = orchestrator::recover_active(&stores)?;
    if let Some(address) = active {
        tracing::info!(%address, "recovered active dkg generation");
    }
    let state = AppState::new(provider, stores, active);

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;

    tracing::info!("listening on {}", config.bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/dkg", post(api::dkg_create).get(api::dkg_get))
        .route("/v1/prepare", post(api::prepare))
        .route("/v1/sign", post(api::sign))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .layer(axum::middleware::from_fn(correlation))
        .with_state(state)
}

async fn correlation(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let correlation_id = format!("{:032x}", rand::random::<u128>());
    let span = tracing::info_span!(
        "request",
        %correlation_id,
        method = %req.method(),
        path = %req.uri().path(),
    );
    tracing::Instrument::instrument(next.run(req), span).await
}
