//! The port itself: [`MpcBackend`] plus its result and error types.
//!
//! The trait is deliberately tiny — `dkg() -> PubkeySec1`, `sign(unsigned tx
//! bytes) -> EcdsaParts` — so key custody stays entirely behind it: callers
//! never see shares, setup messages, or transports. Identity is the wallet's
//! public key, never a network's address format: the MPC seam predates any
//! chain choice. Written with return-position-impl-Future (+ `Send` bound)
//! rather than `async fn` so the futures are usable across spawned tasks.
//! `MpcError` variants are transport-agnostic on purpose; HTTP/WS specifics
//! live in `sovra-ipc`. Pattern: hexagonal port — implementations are
//! `RemoteBackend` (prod) and `InProcessBackend` (tests).

use alloy_primitives::B256;
/// Defined in `sovra-types` (the wire and storage layers need it too);
/// re-exported here because this seam is its semantic home.
pub use sovra_types::EcdsaParts;
use sovra_types::{NetworkId, PubkeySec1};

/// A t-of-n threshold MPC backend: provisions key shares (DKG) and produces
/// ECDSA signatures over transactions supplied as raw unsigned bytes.
pub trait MpcBackend {
    /// Run a distributed key generation over the full participant set.
    fn dkg(&self) -> impl Future<Output = Result<PubkeySec1, MpcError>> + Send;

    /// Produce one signature per digest `network` defines for these bytes,
    /// in digest order (Ethereum: one; UTXO chains: one per input).
    /// Implementations decode the bytes and derive the digests themselves —
    /// the trait deliberately cannot express "sign this opaque digest".
    fn sign(
        &self,
        network: NetworkId,
        unsigned_tx: &[u8],
    ) -> impl Future<Output = Result<Vec<EcdsaParts>, MpcError>> + Send;

    /// All-parties proactive re-randomize: every party brings its shard,
    /// every shard is replaced, and every old shard is rendered useless; the
    /// public key is unchanged. Returns that key — callers verify it against
    /// the active one. Lost-shard recovery is deliberately NOT a protocol
    /// operation: lose a shard → sign with the surviving subset, run a fresh
    /// DKG, migrate funds to the new address.
    fn refresh(&self) -> impl Future<Output = Result<PubkeySec1, MpcError>> + Send;
}

/// The ceremony instance for digest `digest_index` of a multi-digest sign:
/// `keccak256(instance ‖ u32_be(index))`. Derived identically by every
/// party from the wire's single `instance`, and distinct per digest so the
/// k protocol runs can't collide on relay message ids.
pub fn sub_instance(instance: B256, digest_index: u32) -> B256 {
    let mut preimage = [0u8; 36];
    preimage[..32].copy_from_slice(instance.as_slice());
    preimage[32..].copy_from_slice(&digest_index.to_be_bytes());
    alloy_primitives::keccak256(preimage)
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
    #[error("envelope authentication failed: {0}")]
    EnvelopeAuth(String),
    #[error("rejected by cosigner policy: {}", .vetoes.iter().map(|v| format!("party {}: {}", v.party, v.reason)).collect::<Vec<_>>().join("; "))]
    Rejected { vetoes: Vec<Veto> },
}
