mod types;

mod prepare;

mod finalize;

#[cfg(test)]
mod tests;

use alloy_primitives::{Address, U256};
use alloy_provider::Provider;
pub use prepare::{http_provider, prepare_from_rpc_impl};
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
