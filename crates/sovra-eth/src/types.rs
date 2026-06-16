use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, TxNonce, U256};
use alloy_transport::TransportError;
use thiserror::Error;
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

#[derive(Error, Debug)]
pub enum EnrichError {
    #[error("rpc call failed: {0}")]
    Rpc(#[from] TransportError),
}

#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("invalid RPC URL: {0}")]
    InvalidUrl(#[from] ParseError),
}
