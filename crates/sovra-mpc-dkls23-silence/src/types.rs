use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};

pub struct PartyContext {
    pub party_id: u8,                 // 0 or 1 — also the setup party index
    pub instance: B256,               // shared 32-byte run id, minted by orchestrator
    pub signing_key: SigningKey,      // this party's secret identity (SigningKey: Clone)
    pub party_vks: [VerifyingKey; 2], // both parties' pinned verifying keys, ordered by id
    pub ttl: Duration,
}
