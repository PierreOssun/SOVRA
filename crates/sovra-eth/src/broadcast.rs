//! Submit a signed tx via `eth_sendRawTransaction` and wait (bounded) for
//! its receipt.
//!
//! Why a manual `get_transaction_receipt` loop instead of alloy's
//! `PendingTransactionBuilder::get_receipt()`: the builder lazily spawns the
//! provider's heartbeat — a background block-poller whose `eth_blockNumber`
//! requests interleave nondeterministically with receipt polls, which breaks
//! FIFO mock transports in tests. The loop below uses exactly two RPC
//! methods in a deterministic order, and `timeout`/`poll` are parameters so
//! the pending path is testable in milliseconds. A node-level rejection is
//! rechecked against the receipt store once: re-broadcasting an
//! already-mined tx is reported as `Confirmed`, not an error (idempotent
//! re-submit, mirroring the API's sign-idempotency philosophy).
//! Pattern: imperative shell over a generic `Provider`, like `enrich`.

use std::time::{Duration, Instant};

use alloy_primitives::B256;
use alloy_provider::Provider;
use alloy_transport::RpcError;

use crate::{BroadcastError, BroadcastOutcome};

pub async fn broadcast_via_rpc_impl<P: Provider>(
    raw: &[u8],
    expected_hash: B256,
    provider: &P,
    timeout: Duration,
    poll: Duration,
) -> Result<BroadcastOutcome, BroadcastError> {
    let builder = match provider.send_raw_transaction(raw).await {
        Ok(builder) => builder,
        // The node said no — but if a receipt already exists the tx was
        // simply broadcast before (nonce-reuse rejection): report it mined.
        Err(RpcError::ErrorResp(payload)) => {
            return match provider.get_transaction_receipt(expected_hash).await? {
                Some(receipt) => Ok(BroadcastOutcome::Confirmed(Box::new(receipt))),
                None => Err(BroadcastError::Rejected(payload.to_string())),
            };
        }
        Err(other) => return Err(other.into()),
    };

    // The node's echoed hash must match the one computed from the bytes we
    // decoded ourselves — same spirit as finalize's recovered-signer check.
    let node_hash = *builder.tx_hash();
    if node_hash != expected_hash {
        return Err(BroadcastError::HashMismatch {
            local: expected_hash,
            node: node_hash,
        });
    }

    tracing::info!(tx_hash = %expected_hash, "tx submitted, awaiting receipt");

    // Receipt check before deadline check, so a zero timeout still performs
    // exactly one check rather than degrading to fire-and-forget.
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(receipt) = provider.get_transaction_receipt(expected_hash).await? {
            return Ok(BroadcastOutcome::Confirmed(Box::new(receipt)));
        }
        if Instant::now() >= deadline {
            return Ok(BroadcastOutcome::Pending);
        }
        tokio::time::sleep(poll).await;
    }
}
