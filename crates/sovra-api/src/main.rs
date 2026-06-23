use crate::api::{ApiDoc, AppState};
use crate::config::Config;
use alloy_provider::Provider;
use axum::Router;
use axum::routing::post;
use sovra_eth::http_provider;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod api;
mod config;
mod errors;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let provider = http_provider(&config.rpc_url)?.erased();
    let state = AppState { provider };

    let app = Router::new()
        .route("/v1/prepare", post(api::prepare))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;

    println!("listening on {}", config.bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
