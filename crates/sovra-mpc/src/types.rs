//! The port itself: [`MpcBackend`] plus its result and error types.
//!
//! The trait is deliberately tiny — `dkg() -> Address`, `sign(unsigned tx
//! bytes) -> EcdsaParts` — so key custody stays entirely behind it: callers
//! never see shares, setup messages, or transports. Written with
//! return-position-impl-Future (+ `Send` bound) rather than `async fn` so
//! the futures are usable across spawned tasks. `MpcError` variants are
//! transport-agnostic on purpose; HTTP/WS specifics live in `sovra-ipc`.
//! Pattern: hexagonal port — implementations are `RemoteBackend` (prod) and
//! `InProcessBackend` (tests).

use alloy_primitives::{Address, U256};

/// A 2-of-2 MPC backend: provisions key shares (DKG) and produces ECDSA
/// signatures over transactions supplied as raw unsigned bytes.
pub trait MpcBackend {
    /// Run a 2-of-2 distributed key generation.
    fn dkg(&self) -> impl Future<Output = Result<Address, MpcError>> + Send;

    /// Produce a signature over the digest of `unsigned_tx`. Implementations
    /// decode the bytes and derive the digest themselves — the trait
    /// deliberately cannot express "sign this opaque digest".
    fn sign(&self, unsigned_tx: &[u8])
    -> impl Future<Output = Result<EcdsaParts, MpcError>> + Send;
}

/// ECDSA signature components
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EcdsaParts {
    pub r: U256,
    pub s: U256,
    pub y_parity: bool,
}

/// One cosigner's policy refusal, attributed to the party that vetoed.
///
/// `reason` is a display string, not `sovra_policy::DenyReason`: typing it
/// here would give the chain-agnostic MPC seam an Ethereum-policy dependency,
/// and nothing upstream branches on the variant — the enum lives at the
/// cosigner, which is where the decision is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Veto {
    pub party: u8,
    pub reason: String,
}

#[derive(thiserror::Error, Debug)]
pub enum MpcError {
    #[error("distributed key generation failed: {0}")]
    Dkg(String),
    #[error("distributed signing failed: {0}")]
    Sign(String),
    #[error("could not deserialize a key share")]
    Deserialize,
    #[error("cosigner transport failed: {0}")]
    Transport(String),
    #[error("cosigners disagreed: {0}")]
    PartyMismatch(String),
    #[error("rejected by cosigner policy: {}", .vetoes.iter().map(|v| format!("party {}: {}", v.party, v.reason)).collect::<Vec<_>>().join("; "))]
    Rejected { vetoes: Vec<Veto> },
}
