//! Process wiring for the cosigner binary: config (`argv[1]`) → identity →
//! pinned peer key → shard store → `CosignerState` → serve the control API.
//!
//! Choices worth knowing: the verifying key is logged on every start because
//! pinning it in the peer's config is a manual operator step; a missing peer
//! key is a warning at startup but a 409 at use, so a half-configured
//! cosigner still serves `/identity` (needed to bootstrap the pairing).
//! The correlation middleware differs from sovra-api's on purpose — this end
//! ACCEPTS the incoming id so one id threads through all processes' logs.
//! Pattern: composition root for the cosigner process.

use std::{path::Path, sync::Arc, time::Duration};

use axum::{
    Router,
    response::Response,
    routing::{get, post},
};
use ed25519_dalek::VerifyingKey;
use sovra_ipc::tls::{TlsMaterials, serve_mtls};
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
    let policy = load_policy(&config.policy_path)?;
    tracing::info!(policy_path = %config.policy_path, "signing policy loaded");
    // Fail-closed like the policy: no TLS material, no process. The loader's
    // errors carry the offending path.
    let tls = TlsMaterials::load(
        &config.tls_ca_path,
        &config.tls_cert_path,
        &config.tls_key_path,
    )?;
    // Same rule at the scheme: for a `ws://` relay_url tungstenite would
    // silently skip TLS — refuse it here as a config error instead.
    if !config.relay_url.starts_with("wss://") {
        return Err(Box::new(sovra_ipc::tls::TlsError::PlainScheme {
            url: config.relay_url,
            expected: "wss",
        }));
    }

    let state = Arc::new(CosignerState {
        party_id: config.party_id,
        signing_key,
        peer_vk,
        store,
        relay_url: config.relay_url,
        relay_tls: tls.ws_client_config()?,
        ttl: Duration::from_secs(config.ttl_secs),
        op: tokio::sync::Mutex::new(()),
        policy,
    });

    let listener = std::net::TcpListener::bind(&config.bind_addr)?;
    tracing::info!("cosigner listening on {} (mTLS)", config.bind_addr);
    serve_mtls(listener, build_router(state), &tls).await?;
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

/// Fail-closed: any problem reading or parsing the policy file aborts
/// startup — unlike the peer key, there is no degraded mode in which running
/// without a policy is acceptable (that would be a blind signer again).
fn load_policy(path: &str) -> Result<sovra_policy::Policy, Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("policy file {path}: {e}"))?;
    Ok(toml::from_str(&raw).map_err(|e| format!("policy file {path}: {e}"))?)
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

#[cfg(test)]
mod tests {
    /// Fail-closed startup: no policy file, no process.
    #[test]
    fn missing_policy_file_refuses_to_start() {
        assert!(super::load_policy("/nonexistent/policy.toml").is_err());
    }

    #[test]
    fn corrupt_policy_file_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.toml");
        // Partially parsed == parse failure: keys are missing.
        std::fs::write(&path, "allowed_chain_ids = [11155111]\n").unwrap();
        assert!(super::load_policy(path.to_str().unwrap()).is_err());
    }
}
