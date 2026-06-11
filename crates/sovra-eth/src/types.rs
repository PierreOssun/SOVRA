use alloy_consensus::TxEip1559;
use alloy_primitives::{Address, B256, Bytes, ChainId, TxKind, TxNonce, U256};
use thiserror::Error;

/// The caller's input
#[derive(Debug)]
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
#[derive(Debug)]
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

#[derive(Debug)]
pub struct SignedTx {
    /// EIP-2718 encoded, ready to broadcast (starts 0x02)
    pub raw: Bytes,
    /// keccak256 of the encoded signed tx
    pub tx_hash: B256,
    /// recovered & verified signer
    pub from: Address,
}

/// Errors that can occur during 'prepare_tx'
#[derive(Error, Debug, PartialEq)]
pub enum PrepareError {
    #[error("chain id must not be zero")]
    ZeroChainId,

    #[error("max priority fee per gas must not exceed max fee per gas")]
    MaxPriorityFeeExceedsMaxFee,

    #[error("gas limit must not be zero")]
    ZeroGasLimit,
}

#[derive(Error, Debug, PartialEq)]
pub enum FinalizeError {
    #[error("could not recover signer from signature")]
    Recovery,
    #[error("recovered signer {recovered} does not match expected {expected}")]
    AddressMismatch {
        expected: Address,
        recovered: Address,
    },
}
