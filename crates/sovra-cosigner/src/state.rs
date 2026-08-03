//! Shared per-process state (`CosignerState`) and the [`CosignerState::ctx`]
//! constructor that assembles a `PartyContext` for each MPC run.
//!
//! `op` mirrors sovra-api's exclusivity mutex: `try_lock` only, at most one
//! MPC run at a time, busy = 409. `ctx` is the one place the positional
//! `party_vks` array is built (own key at `party_id`, peer at the other
//! slot) — order is a protocol invariant, so it's centralized rather than
//! rebuilt in each handler. State is immutable after startup except the
//! store's on-disk contents; no locks needed beyond `op`.
//! Pattern: shared-state cell, standard axum.

use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sovra_mpc_dkls23_silence::types::PartyContext;
use sovra_state::SignerStore;

use crate::errors::CosignerError;

pub struct CosignerState {
    pub party_id: u8,
    pub signing_key: SigningKey,
    pub peer_vk: Option<VerifyingKey>,
    pub store: SignerStore,
    pub relay_url: String,
    pub ttl: Duration,
    pub op: tokio::sync::Mutex<()>,
    /// This party's local signing policy — evaluated on every `/sign` before
    /// any MPC message, loaded fail-closed at startup.
    pub policy: sovra_policy::Policy,
}

impl CosignerState {
    /// party_vks is positional by party id — flipping it breaks DKG silently.
    pub fn ctx(&self, instance: B256) -> Result<PartyContext, CosignerError> {
        let peer = self.peer_vk.ok_or(CosignerError::PeerKeyUnset)?;
        let own = self.signing_key.verifying_key();
        let mut party_vks = [own; 2];
        party_vks[1 - self.party_id as usize] = peer;
        Ok(PartyContext {
            party_id: self.party_id,
            instance,
            signing_key: self.signing_key.clone(),
            party_vks,
            ttl: self.ttl,
        })
    }
}
