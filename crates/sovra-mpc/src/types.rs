//! The port itself: [`MpcBackend`] plus its result and error types.
//!
//! The trait is deliberately tiny — `dkg() -> Address`, `sign(...) ->
//! EcdsaParts` — so key custody stays entirely behind it: callers never see
//! shares, setup messages, or transports. Written with
//! return-position-impl-Future (+ `Send` bound) rather than `async fn` so
//! the futures are usable across spawned tasks. `MpcError` variants are
//! transport-agnostic on purpose; HTTP/WS specifics live in `sovra-ipc`.
//! Pattern: hexagonal port — implementations are `RemoteBackend` (prod) and
//! `InProcessBackend` (tests).

use alloy_primitives::{Address, B256, Bytes, U256};

/// A 2-of-2 MPC backend: provisions key shares (DKG) and produces ECDSA
/// signatures over a transaction payload.
pub trait MpcBackend {
    /// Run a 2-of-2 distributed key generation.
    fn dkg(&self) -> impl Future<Output = Result<Address, MpcError>> + Send;

    /// Produce a signature over an unsigned EIP-1559 transaction.
    ///
    /// Both arguments describe the SAME transaction: `unsigned_tx` is the full
    /// raw payload (what remote cosigners receive, so they can decode, derive
    /// the digest themselves, and enforce policy — no blind signing), and
    /// `signing_hash` is the caller's locally-derived digest (what in-process
    /// implementations sign directly). A remote implementation must never
    /// transmit `signing_hash`: a digest on the wire is a value someone might
    /// later be tempted to trust.
    fn sign(
        &self,
        unsigned_tx: Bytes,
        signing_hash: B256,
    ) -> impl Future<Output = Result<EcdsaParts, MpcError>> + Send;
}

/// ECDSA signature components
#[derive(Debug, Clone, Copy, PartialEq)]
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
    /// A cosigner refused BEFORE running any MPC — a policy verdict, not a
    /// protocol failure. Kept distinct so callers can surface the refusal
    /// (with its machine-readable `code`) instead of an opaque 502.
    #[error("cosigner refused to sign: {message}")]
    Refused { code: String, message: String },
    #[error("could not deserialize a key share")]
    Deserialize,
    #[error("cosigner transport failed: {0}")]
    Transport(String),
    #[error("cosigners disagreed: {0}")]
    PartyMismatch(String),
}
