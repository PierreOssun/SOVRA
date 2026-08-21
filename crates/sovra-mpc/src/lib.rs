//! Backend-agnostic MPC seam for the `sign` path.
//!
//! Two ports and the plumbing between them. [`MpcBackend`] is the
//! orchestrator's port (dkg/sign/refresh over the whole scheme);
//! [`PartyRunner`] is the cosigner's port (one party's share of a ceremony).
//! Between them sits the sovra-owned relay plane — [`Envelope`] /
//! [`SignedEnvelope`] (signed, p2p-sealed frames), [`EnvelopeRelay`] (the
//! transport a runner is driven over), [`Exchange`] (the round-driver), and
//! [`MemoryHub`] (the in-process relay for tests). This crate knows nothing
//! about any concrete MPC library.
//!
mod envelope;
mod exchange;
mod memhub;
mod runner;
mod types;

use alloy_primitives::U256;
pub use envelope::{Envelope, SignedEnvelope, op};
pub use exchange::{Exchange, Expect, RoundInbox, RoundOutbox};
pub use memhub::{MemoryHub, MemoryRelay};
pub use runner::{EnvelopeRelay, PartyContext, PartyRunner};
pub use types::*;

/// Convert a k256 ECDSA signature and recovery id into `finalize`'s inputs.
///
/// `split_bytes` yields big-endian 32-byte `r` and `s`.
/// k256 already low-s-normalizes, which EIP-1559 requires, so no extra normalization here.
pub fn to_ecdsa_parts(sig: &k256::ecdsa::Signature, recid: k256::ecdsa::RecoveryId) -> EcdsaParts {
    let (r, s) = sig.split_bytes();
    EcdsaParts {
        r: U256::from_be_slice(r.as_ref()),
        s: U256::from_be_slice(s.as_ref()),
        y_parity: recid.is_y_odd(),
    }
}
