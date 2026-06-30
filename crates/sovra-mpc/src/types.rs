use alloy_primitives::{Address, B256, U256};
use sovra_types::KeyShare;

/// A 2-of-2 MPC backend: provisions key shares (DKG) and produces ECDSA
/// signatures from a 32-byte signing hash.
pub trait MpcBackend {
    /// Run a 2-of-2 distributed key generation.
    fn dkg(&self) -> impl Future<Output = Result<DkgResult, MpcError>> + Send;

    /// Produce a signature over `signing_hash` using the provided shards.
    fn sign(
        &self,
        signing_hash: B256,
        shares: &[KeyShare],
    ) -> impl Future<Output = Result<EcdsaParts, MpcError>> + Send;
}

/// Output of a distributed key generation: the per-party opaque shards plus the
/// Ethereum address derived from the shared public key.
#[derive(Debug, Clone)]
pub struct DkgResult {
    pub shares: Vec<KeyShare>,
    pub address: Address,
}

/// ECDSA signature components
#[derive(Debug, Clone, Copy)]
pub struct EcdsaParts {
    pub r: U256,
    pub s: U256,
    pub y_parity: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum MpcError {
    #[error("distributed key generation failed: {0}")]
    Dkg(String),
    #[error("distributed signing failed: {0}")]
    Sign(String),
    #[error("could not deserialize a key share")]
    Deserialize,
    #[error("signing produced no signature")]
    NoSignature,
}
