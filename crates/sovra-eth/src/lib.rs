//! Ethereum transaction lifecycle for the supported tx types (legacy,
//! EIP-2930, EIP-1559 — see [`EthTx`]): prepare (enrich from RPC, build,
//! validate), encode/decode the unsigned form, and finalize (attach the
//! signature, verify the recovered signer, emit broadcast-ready raw bytes).
//!
//! This crate holds **no key material** and knows nothing about MPC — it
//! consumes an `(r, s, y_parity)` triple from whoever produced it. Built on
//! alloy (consensus/provider/rpc-types) rather than hand-rolled RLP so tx
//! hashing and encoding can't drift from the network rules. The `*_impl`
//! functions in submodules are re-exported through thin wrappers here to keep
//! one public surface. Pattern: pure domain layer; only `enrich` touches I/O
//! (via a generic `Provider`, so tests inject a mock).
//!
//! The RPC shell (`enrich`, `prepare_from_rpc`, `http_provider` and their
//! error types) sits behind the default-on `rpc` feature; with
//! `default-features = false` only the pure core (types, encoding,
//! validation, finalize) builds — no provider/transport stack. That lean
//! profile is what the cosigner consumes.

mod types;

pub mod prepare;

mod finalize;

#[cfg(feature = "rpc")]
mod broadcast;
mod encoding;
mod network;
#[cfg(test)]
mod tests;

#[cfg(feature = "rpc")]
use std::time::Duration;

/// Re-exported so API-layer DTOs don't need their own alloy-eips dependency.
pub use alloy_eips::eip2930::AccessList;
#[cfg(feature = "rpc")]
use alloy_primitives::B256;
use alloy_primitives::{Address, U256};
#[cfg(feature = "rpc")]
use alloy_provider::Provider;
#[cfg(feature = "rpc")]
pub use broadcast::broadcast_via_rpc_impl;
pub use encoding::{decode_signed, decode_unsigned, encode_unsigned};
pub use network::Ethereum;
pub use prepare::prepare;
#[cfg(feature = "rpc")]
pub use prepare::{http_provider, prepare_from_rpc_impl};
pub use types::*;

use crate::finalize::finalize_impl;

#[cfg(feature = "rpc")]
pub async fn prepare_from_rpc<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<PreparedTx, PrepareError> {
    prepare_from_rpc_impl(req, from, provider).await
}

#[cfg(feature = "rpc")]
pub async fn broadcast_via_rpc<P: Provider>(
    raw: &[u8],
    expected_hash: B256,
    provider: &P,
    timeout: Duration,
    poll: Duration,
) -> Result<BroadcastOutcome, BroadcastError> {
    broadcast_via_rpc_impl(raw, expected_hash, provider, timeout, poll).await
}

pub fn finalize(
    prepared_tx: PreparedTx,
    r: U256,
    s: U256,
    y_parity: bool,
    expected_from: Address,
) -> Result<SignedTx, FinalizeError> {
    finalize_impl(prepared_tx, r, s, y_parity, expected_from)
}

/// Ethereum's view of the chain-neutral key identity: keccak-derived address
/// from the compressed SEC1 pubkey. The one place this derivation lives —
/// consensus and storage compare pubkeys, never addresses.
pub fn address_from_sec1(pk: &sovra_types::PubkeySec1) -> Result<Address, PubkeyError> {
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(pk.as_bytes()).map_err(|_| PubkeyError)?;
    Ok(Address::from_public_key(&vk))
}
