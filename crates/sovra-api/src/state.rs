use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, B256};
use alloy_provider::DynProvider;
use sovra_mpc_dkls23_silence::SilenceBackend;
use sovra_state::SignerStore;

use crate::api::SignResponse;

#[derive(Clone)]
pub struct AppState {
    pub provider: DynProvider,
    pub backend: Arc<SilenceBackend>,
    pub stores: Arc<[SignerStore; 2]>,
    pub signer: Arc<SignerCell>,
}

impl AppState {
    pub fn new(provider: DynProvider, stores: [SignerStore; 2], active: Option<Address>) -> Self {
        Self {
            provider,
            backend: Arc::new(SilenceBackend),
            stores: Arc::new(stores),
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
