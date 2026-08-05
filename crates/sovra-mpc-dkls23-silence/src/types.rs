//! [`PartyContext`] — everything one party needs to join a protocol run:
//! its global id, the shared instance id, its ed25519 identity, the full
//! roster of pinned verifying keys (positional by party id — order is a
//! protocol invariant), the scheme threshold, and the run TTL. Bundled as
//! one struct so the runner signatures don't take seven loose parameters
//! and callers can't mix arguments from different runs.
//! Pattern: parameter object.

use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};

#[derive(Clone)]
pub struct PartyContext {
    pub party_id: u8,            // global id, 0..n-1 — also the index into party_vks
    pub instance: B256,          // shared 32-byte run id, minted by orchestrator
    pub signing_key: SigningKey, // this party's secret identity (SigningKey: Clone)
    pub party_vks: Vec<VerifyingKey>, // full roster, ordered by party id; n = len()
    pub threshold: u8,           // t in t-of-n
    pub ttl: Duration,
}
