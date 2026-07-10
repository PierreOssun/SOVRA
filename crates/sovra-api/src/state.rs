use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, B256};
use alloy_provider::DynProvider;
use sovra_mpc::MpcBackend;

use crate::api::SignResponse;

pub struct AppState<B> {
    pub provider: DynProvider,
    pub backend: Arc<B>,
    pub signer: Arc<SignerCell>,
}

impl<B> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            backend: self.backend.clone(),
            signer: self.signer.clone(),
        }
    }
}

impl<B: MpcBackend> AppState<B> {
    pub fn new(provider: DynProvider, backend: B, active: Option<Address>) -> Self {
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
    /// Address of the active DKG generation. `None` until DKG runs;
    /// recovered from the shard stores at startup.
    pub active: Option<Address>,
    /// Idempotency cache: completed sign responses keyed by tx_digest.
    /// In-memory only — lost on restart (a re-sign then re-runs MPC).
    pub signed: HashMap<B256, SignResponse>,
}
