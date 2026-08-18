//! Shared per-process state handed to every handler via axum `State`.
//!
//! Two locks with distinct jobs: `state` is a `std::sync::RwLock` for cheap
//! synchronous reads (guards must never be held across an `.await`), while
//! `op` is a `tokio::sync::Mutex` used with `try_lock` only — it encodes
//! "at most one MPC operation in flight", and busy callers get 409 rather
//! than queueing behind a 60s protocol run. `Clone` is implemented by hand
//! because deriving would wrongly require `B: Clone` (the backend is shared
//! through the `Arc`). Everything here is in-memory and rebuilt at startup.
//! Pattern: shared-state cell (Arc + interior mutability), standard axum.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_primitives::B256;
use alloy_provider::DynProvider;
use sovra_mpc::MpcBackend;
use sovra_types::PubkeySec1;

use crate::api::SignResponse;

/// How long `/v1/broadcast` waits for a receipt and how often it polls.
/// A field (not constants) so tests can shrink the window to milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct BroadcastTiming {
    pub timeout: Duration,
    pub poll: Duration,
}

impl Default for BroadcastTiming {
    /// 30 s window, 2 s poll — Sepolia mines every ~12 s, so ~15 checks
    /// cover two block opportunities.
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            poll: Duration::from_secs(2),
        }
    }
}

pub struct AppState<B> {
    pub provider: DynProvider,
    pub backend: Arc<B>,
    pub signer: Arc<SignerCell>,
    pub broadcast: BroadcastTiming,
}

impl<B> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            backend: self.backend.clone(),
            signer: self.signer.clone(),
            broadcast: self.broadcast,
        }
    }
}

impl<B: MpcBackend> AppState<B> {
    pub fn new(provider: DynProvider, backend: B, active: Option<PubkeySec1>) -> Self {
        Self {
            provider,
            backend: Arc::new(backend),
            signer: Arc::new(SignerCell {
                state: std::sync::RwLock::new(SignerState {
                    active,
                    signed: HashMap::new(),
                }),
                op: tokio::sync::Mutex::new(()),
            }),
            broadcast: BroadcastTiming::default(),
        }
    }
}
pub struct SignerCell {
    /// Cheap-read state. Guards are held only for short synchronous
    /// sections — never across an .await.
    pub state: std::sync::RwLock<SignerState>,
    /// Global MPC exclusivity: at most one DKG or sign runs at a time.
    /// try_lock only — busy means 409, requests never queue.
    pub op: tokio::sync::Mutex<()>,
}

pub struct SignerState {
    /// Public key of the active DKG generation. `None` until DKG runs;
    /// recovered from the shard stores at startup.
    pub active: Option<PubkeySec1>,
    /// Idempotency cache: completed sign responses keyed by tx_digest.
    /// In-memory only — lost on restart (a re-sign then re-runs MPC).
    pub signed: HashMap<B256, SignResponse>,
}
