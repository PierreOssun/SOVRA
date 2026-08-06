//! Process wiring for the orchestrator binary: config → RPC provider → relay
//! hub → startup recovery → `AppState` → serve API and hub concurrently.
//!
//! Ordering is load-bearing: the hub binds *first* because cosigners dial it
//! in the middle of every dkg/sign; recovery runs with a short-timeout probe
//! client and bounded retries (cosigners are started before the api, but get
//! ~10s of grace). `try_join!` serves both listeners so the process dies if
//! either does — half-alive is worse than down. The `correlation` middleware
//! mints one id per request and scopes it as a task-local, which is how the
//! same id reaches cosigner logs via `RemoteBackend`.
//! Pattern: composition root — the only place concrete types
//! (`RemoteBackend`, real provider) are chosen.

use std::time::Duration;

use alloy_primitives::Address;
use alloy_provider::Provider;
use axum::{Router, response::Response, routing::post};
use sovra_eth::http_provider;
use sovra_ipc::{hub::RelayHub, remote::RemoteBackend};
use sovra_mpc::MpcBackend;
use url::Url;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    api, api::ApiDoc, config::Config, orchestrator, orchestrator::RecoverError, state::AppState,
};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;
    let provider = http_provider(&config.rpc_url)?.erased();
    // Preference order straight from the config file — the cold recovery
    // party sits last and is only selected when a preferred party is down.
    let cosigners: Vec<(u8, Url)> = config
        .cosigners
        .iter()
        .map(|entry| Ok::<_, url::ParseError>((entry.party_id, entry.url.parse()?)))
        .collect::<Result<_, _>>()?;
    let threshold = config.threshold as usize;

    // Hub up FIRST — cosigners dial it mid-run; it must exist before any dkg/sign.
    let relay_listener = std::net::TcpListener::bind(&config.relay_bind)?;
    let hub = sovra_ipc::hub::ws_router(RelayHub::default());
    tracing::info!("relay hub on {} (mTLS)", config.relay_bind);

    // Fail-closed: no TLS material, no process (same rule as the cosigners).
    let tls = sovra_ipc::tls::TlsMaterials::load(
        &config.tls_ca_path,
        &config.tls_cert_path,
        &config.tls_key_path,
    )?;

    // Built before recovery on purpose: `new` validates the cosigner set
    // (unique ids, threshold bounds, https), so a bad config fails startup
    // immediately instead of after the recovery retry loop.
    let backend = RemoteBackend::new(cosigners.clone(), threshold, &tls)?;

    // Bounded retry: cosigners start first (RUN.md), but give them ~10s of grace.
    let probe = tls.http_client(Duration::from_secs(5))?;
    let active = recover_with_retry(&probe, &cosigners, threshold).await?;
    if let Some(address) = active {
        tracing::info!(%address, "recovered active dkg generation");
    }

    let state = AppState::new(provider, backend, active);
    let api_listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("listening on {}", config.bind_addr);

    // The public API stays plaintext loopback (the custody boundary is the
    // cosigner); the hub requires a project-CA client cert like every other
    // internal socket.
    tokio::try_join!(
        async { axum::serve(api_listener, build_router(state)).await },
        async {
            sovra_ipc::tls::serve_mtls(relay_listener, hub, &tls)
                .await
                .map_err(std::io::Error::other)
        },
    )?;
    Ok(())
}

pub fn build_router<B: MpcBackend + Send + Sync + 'static>(state: AppState<B>) -> Router {
    Router::new()
        .route("/v1/dkg", post(api::dkg_create).get(api::dkg_get))
        .route("/v1/recover", post(api::recover))
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
    sovra_ipc::control::CORRELATION_ID
        .scope(
            correlation_id,
            tracing::Instrument::instrument(next.run(req), span),
        )
        .await
}

async fn recover_with_retry(
    http: &reqwest::Client,
    cosigners: &[(u8, Url)],
    threshold: usize,
) -> Result<Option<Address>, RecoverError> {
    for _ in 0..9 {
        match orchestrator::recover_active(http, cosigners, threshold).await {
            Err(e @ RecoverError::Transport { .. }) => {
                tracing::warn!(error = %e, "cosigners not ready, retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            other => return other,
        }
    }
    orchestrator::recover_active(http, cosigners, threshold).await
}
