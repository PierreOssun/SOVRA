//! Backend-agnostic MPC seam for the `sign` path.
//!
//! Defines the [`MpcBackend`] trait, the shared result/error types, and the
//! pure conversion from a k256 ECDSA signature to the `(r, s, y_parity)` triple
//! that `sovra_eth::finalize` consumes. This crate knows nothing about any
//! concrete MPC library.
//!
mod types;

use alloy_primitives::U256;
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
