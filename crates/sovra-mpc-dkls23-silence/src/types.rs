//! [`PartyContext`] — everything one party needs to join a protocol run:
//! its index, the shared instance id, its ed25519 identity, both parties'
//! pinned verifying keys (positional by party id — order is a protocol
//! invariant), and the run TTL. Bundled as one struct so the runner
//! signatures don't take six loose parameters and callers can't mix
//! arguments from different runs. Pattern: parameter object.

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
