//! Shared per-process state (`CosignerState`) and the [`CosignerState::ctx`]
//! constructor that assembles a `PartyContext` for each MPC run.
//!
//! `op` mirrors sovra-api's exclusivity mutex: `try_lock` only, at most one
//! MPC run at a time, busy = 409. The roster is stored in final form (full vk
//! list, index = party id — order is a protocol invariant), so `ctx` is a
//! plain clone and no handler ever rebuilds positional arrays. State is
//! immutable after startup except the store's on-disk contents; no locks
//! needed beyond `op`.
//! Pattern: shared-state cell, standard axum.

use std::{sync::Arc, time::Duration};

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sovra_ipc::control::RosterInfo;
use sovra_mpc_dkls23_silence::types::PartyContext;
use sovra_state::SignerStore;

use crate::errors::CosignerError;

pub struct CosignerState {
    pub party_id: u8,
    pub signing_key: SigningKey,
    /// Full pinned roster, index = global party id, own key included.
    /// `None` = bootstrap mode (`/identity` serves, dkg/sign 409).
    pub roster: Option<Vec<VerifyingKey>>,
    /// t in t-of-n; n is the roster length.
    pub threshold: u8,
    pub store: SignerStore,
    pub relay_url: String,
    /// Client config for dialing the hub (`WsRelay::connect`): pins the
    /// project CA, presents this party's leaf. Built once at startup from the
    /// same materials that serve the control API.
    pub relay_tls: Arc<rustls::ClientConfig>,
    pub ttl: Duration,
    pub op: tokio::sync::Mutex<()>,
    /// This party's local signing policy — evaluated on every `/sign` before
    /// any MPC message, loaded fail-closed at startup.
    pub policy: sovra_policy::Policy,
}

impl CosignerState {
    pub fn ctx(&self, instance: B256) -> Result<PartyContext, CosignerError> {
        let roster = self.roster.clone().ok_or(CosignerError::RosterUnset)?;
        Ok(PartyContext {
            party_id: self.party_id,
            instance,
            signing_key: self.signing_key.clone(),
            party_vks: roster,
            threshold: self.threshold,
            ttl: self.ttl,
        })
    }

    /// The `GET /roster` payload. The hash commits to (n, t, every vk in id
    /// order) so the orchestrator's DKG pre-flight can detect a diverging
    /// participant list without ever learning the keys themselves — this
    /// function is the hash's single definition.
    pub fn roster_info(&self) -> Result<RosterInfo, CosignerError> {
        let roster = self.roster.as_ref().ok_or(CosignerError::RosterUnset)?;
        let mut preimage = Vec::with_capacity(2 + roster.len() * 32);
        preimage.push(roster.len() as u8);
        preimage.push(self.threshold);
        for vk in roster {
            preimage.extend_from_slice(vk.as_bytes());
        }
        Ok(RosterInfo {
            n: roster.len() as u8,
            threshold: self.threshold,
            roster_hash: alloy_primitives::keccak256(&preimage),
        })
    }
}
