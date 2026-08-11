//! Domain types for the tx lifecycle — one struct per stage (`TxRequest` →
//! `TxIntent` → `PreparedTx` → `SignedTx`) — plus one error enum per
//! fallible step.
//!
//! Why a struct per stage instead of one mutable builder: each type can only
//! exist if the previous stage succeeded, so "prepared but not validated" or
//! "signed but unverified" states are unrepresentable. Per-step error enums
//! keep the API layer able to map failures to distinct HTTP statuses.
//! Pattern: typestate-flavored pipeline (make invalid states
//! unrepresentable).

use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, TxNonce, U256};
#[cfg(feature = "rpc")]
use alloy_transport::TransportError;
use thiserror::Error;
#[cfg(feature = "rpc")]
use url::ParseError;

/// The caller's input
#[derive(Debug, PartialEq, Eq)]
pub struct TxIntent {
    pub chain_id: ChainId,
    pub nonce: TxNonce,
    pub to: Address,
    pub value: U256,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub data: Bytes,
}

/// The output of 'prepare_tx'
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedTx {
    pub tx: TxEip1559,
    pub signing_hash: B256,
}

impl From<TxIntent> for TxEip1559 {
    fn from(intent: TxIntent) -> Self {
        TxEip1559 {
            chain_id: intent.chain_id,
            nonce: intent.nonce,
            gas_limit: intent.gas_limit,
            max_fee_per_gas: intent.max_fee_per_gas,
            max_priority_fee_per_gas: intent.max_priority_fee_per_gas,
            to: TxKind::Call(intent.to),
            value: intent.value,
            access_list: Default::default(),
            input: intent.data,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// EIP-2718 encoded, ready to broadcast (starts 0x02)
    pub raw: Bytes,
    /// keccak256 of the encoded signed tx
    pub tx_hash: B256,
    /// recovered & verified signer
    pub from: Address,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TxRequest {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

/// Errors that can occur during 'prepare_tx'
#[derive(Error, Debug)]
pub enum PrepareError {
    #[error("chain id must not be zero")]
    ZeroChainId,

    #[error("max priority fee per gas must not exceed max fee per gas")]
    MaxPriorityFeeExceedsMaxFee,

    #[error("gas limit must not be zero")]
    ZeroGasLimit,

    #[cfg(feature = "rpc")]
    #[error("failed to enrich transaction from RPC: {0}")]
    Enrich(#[from] EnrichError),
}

#[derive(Error, Debug)]
pub enum FinalizeError {
    #[error("could not recover signer from signature")]
    Recovery,
    #[error("recovered signer {recovered} does not match expected {expected}")]
    AddressMismatch {
        expected: Address,
        recovered: Address,
    },
}

#[cfg(feature = "rpc")]
#[derive(Error, Debug)]
pub enum EnrichError {
    #[error("rpc call failed: {0}")]
    Rpc(#[from] TransportError),
}

#[cfg(feature = "rpc")]
#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(#[from] ParseError),
}
#[derive(Error, Debug)]
pub enum DecodeError {
    #[error("empty transaction bytes")]
    Empty,
    #[error("unsupported transaction type: {0:#04x}, expected 0x02 (EIP-1559)")]
    UnsupportedType(u8),
    #[error("invalid rlp encoding")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("trailing bytes after transaction")]
    TrailingBytes,
    #[error("could not recover signer from signed transaction")]
    Recovery,
}

/// The two non-error endings of a broadcast: mined within the wait window,
/// or accepted by the node but still pending when the window closed.
#[cfg(feature = "rpc")]
#[derive(Debug)]
pub enum BroadcastOutcome {
    /// Boxed: a receipt is ~576 bytes vs the empty pending variant.
    Confirmed(Box<alloy_rpc_types_eth::TransactionReceipt>),
    /// Accepted by the node, unmined when the wait window closed. Carries no
    /// hash — the caller computed it and passed it in.
    Pending,
}

#[cfg(feature = "rpc")]
#[derive(Error, Debug)]
pub enum BroadcastError {
    /// The node refused the transaction and no receipt exists for it —
    /// the message is the node's own reason (nonce too low, underpriced…).
    #[error("node rejected transaction: {0}")]
    Rejected(String),
    #[error("rpc call failed: {0}")]
    Rpc(#[from] TransportError),
    /// The node's echoed hash disagrees with the locally computed one —
    /// a broken invariant, never a caller mistake.
    #[error("node returned tx hash {node}, locally computed {local}")]
    HashMismatch { local: B256, node: B256 },
}
