//! Shared, serializable types for the `sign` path.
//!
//! Deliberately MPC-backend-agnostic: the opaque [`KeyShare`] holds whatever
//! bytes the MPC library produces (for `sl-dkls23`, `Keyshare::as_slice()`).
//! Round-message types are owned by the MPC library, not modeled here.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Stable identifier for a provisioned signer (a cosigner pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerId(pub String);

impl SignerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SignerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque key-share bytes for one MPC party.
///
/// For `sl-dkls23` these are `Keyshare::as_slice()` bytes, reloadable via
/// `Keyshare::from_bytes`. Kept opaque so persistence never depends on the
/// MPC backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyShare(pub Vec<u8>);

impl KeyShare {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KeyShare {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Metadata persisted alongside a signer's shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerMetadata {
    pub signer_id: SignerId,
    /// Ethereum address derived from the signer's public key.
    pub address: Address,
}
