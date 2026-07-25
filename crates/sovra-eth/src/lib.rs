//! Ethereum EIP-1559 transaction lifecycle: prepare (enrich from RPC, build,
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

mod types;

pub mod prepare;

mod finalize;

mod encoding;
#[cfg(test)]
mod tests;

use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
pub use encoding::{decode_unsigned, encode_unsigned};
pub use prepare::{http_provider, prepare, prepare_from_rpc_impl};
pub use types::*;

use crate::finalize::finalize_impl;

pub async fn prepare_from_rpc<P: Provider>(
    req: TxRequest,
    from: Address,
    provider: &P,
) -> Result<PreparedTx, PrepareError> {
    prepare_from_rpc_impl(req, from, provider).await
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
