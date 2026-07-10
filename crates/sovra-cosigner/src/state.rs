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
