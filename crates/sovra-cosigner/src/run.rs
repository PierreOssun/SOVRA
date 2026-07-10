use std::{path::Path, sync::Arc, time::Duration};

use axum::{
    Router,
    response::Response,
    routing::{get, post},
};
use ed25519_dalek::VerifyingKey;
use sovra_state::SignerStore;

use crate::{api, config::Config, identity, state::CosignerState};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/cosigner0".into());
    let config = Config::load(&config_path)?;

    let data_dir = Path::new(&config.data_dir);
    let signing_key = identity::load_or_generate(data_dir)?;
    // Operator UX: this is what gets pinned in the peer's config — print it every start.
    tracing::info!(
        party_id = config.party_id,
        verifying_key = %alloy_primitives::hex::encode(signing_key.verifying_key().as_bytes()),
        "cosigner identity",
    );
    let peer_vk = match &config.peer_verifying_key {
        Some(hex) => Some(parse_vk(hex)?), // hex decode -> [u8; 32] -> VerifyingKey::from_bytes (errors on bad point)
        None => {
            tracing::warn!("peer verifying key not configured; dkg/sign will 409");
            None
        }
    };
    let store = SignerStore::open(data_dir.join("store"))?;

    let state = Arc::new(CosignerState {
        party_id: config.party_id,
        signing_key,
        peer_vk,
        store,
        relay_url: config.relay_url,
        ttl: Duration::from_secs(config.ttl_secs),
        op: tokio::sync::Mutex::new(()),
    });

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("cosigner listening on {}", config.bind_addr);
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}

pub fn build_router(state: Arc<CosignerState>) -> Router {
    Router::new()
        .route("/dkg", post(api::dkg))
        .route("/sign", post(api::sign))
        .route("/signer", get(api::signer))
        .route("/identity", get(api::identity))
        .route("/health", get(api::health))
        .layer(axum::middleware::from_fn(correlation))
        .with_state(state)
}

fn parse_vk(hex: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = alloy_primitives::hex::decode(hex)?
        .as_slice()
        .try_into()
        .map_err(|_| "peer verifying key must be 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&bytes)?) // rejects bytes that aren't a valid curve point
}

/// Like sovra-api's middleware, but this end ACCEPTS an incoming
/// x-correlation-id (sent by RemoteBackend) so one id threads through
/// orchestrator and cosigner logs; minting is only the fallback.
async fn correlation(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let correlation_id = req
        .headers()
        .get(sovra_ipc::control::CORRELATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{:032x}", rand::random::<u128>()));
    let span = tracing::info_span!(
        "request",
        %correlation_id,
        method = %req.method(),
        path = %req.uri().path(),
    );
    tracing::Instrument::instrument(next.run(req), span).await
}
