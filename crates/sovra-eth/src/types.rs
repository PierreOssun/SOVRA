//! Domain types for the tx lifecycle — one struct per stage (`TxRequest` →
//! `TxIntent` → `PreparedTx` → `SignedTx`) — plus one error enum per
//! fallible step.
//!
//! Why a struct per stage instead of one mutable builder: each type can only
//! exist if the previous stage succeeded, so "prepared but not validated" or
//! "signed but unverified" states are unrepresentable. Per-step error enums
//! keep the API layer able to map failures to distinct HTTP statuses.
//! [`EthTx`] is a hand-rolled closed enum rather than alloy's
//! `TypedTransaction`: the alloy enum carries EIP-4844/7702 variants this
//! service refuses to sign, and an own enum keeps them unrepresentable
//! instead of runtime-rejected at every consumer. [`TxParams`] plays the same
//! trick one stage earlier — the fee variant *is* the type selector, so
//! "legacy with an access list" cannot be constructed and
//! `From<TxIntent> for EthTx` stays total.
//! Pattern: typestate-flavored pipeline (make invalid states
//! unrepresentable).

use alloy_consensus::{
    SignableTransaction, Transaction, TxEip1559, TxEip2930, TxEnvelope, TxLegacy,
};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, Bytes, ChainId, Signature, TxKind, TxNonce, U256};
#[cfg(feature = "rpc")]
use alloy_transport::TransportError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "rpc")]
use url::ParseError;

/// The transaction types this service will sign — a deliberately closed set.
/// EIP-4844 (blob sidecars) and EIP-7702 (separately-signed authorization
/// lists) are out by construction, not by runtime check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EthTx {
    /// Type `None` on the wire: a bare RLP list. EIP-155 (`chain_id: Some`)
    /// is mandatory here — `validate_unsigned` rejects pre-155 payloads.
    Legacy(TxLegacy),
    /// Type 0x01: legacy fee market + access list.
    Eip2930(TxEip2930),
    /// Type 0x02: dynamic fee market + access list.
    Eip1559(TxEip1559),
}

impl EthTx {
    fn as_tx(&self) -> &dyn Transaction {
        match self {
            EthTx::Legacy(tx) => tx,
            EthTx::Eip2930(tx) => tx,
            EthTx::Eip1559(tx) => tx,
        }
    }

    /// `None` only for a pre-EIP-155 legacy tx — which validation refuses.
    pub fn chain_id(&self) -> Option<ChainId> {
        self.as_tx().chain_id()
    }

    pub fn nonce(&self) -> TxNonce {
        self.as_tx().nonce()
    }

    pub fn gas_limit(&self) -> u64 {
        self.as_tx().gas_limit()
    }

    /// `None` means contract creation.
    pub fn to(&self) -> Option<Address> {
        self.as_tx().kind().to().copied()
    }

    pub fn value(&self) -> U256 {
        self.as_tx().value()
    }

    pub fn input(&self) -> &[u8] {
        self.as_tx().input()
    }

    pub fn signature_hash(&self) -> B256 {
        match self {
            EthTx::Legacy(tx) => tx.signature_hash(),
            EthTx::Eip2930(tx) => tx.signature_hash(),
            EthTx::Eip1559(tx) => tx.signature_hash(),
        }
    }

    /// The signing preimage: bare RLP for legacy, type byte ‖ RLP for typed.
    pub fn encoded_for_signing(&self) -> Vec<u8> {
        match self {
            EthTx::Legacy(tx) => tx.encoded_for_signing(),
            EthTx::Eip2930(tx) => tx.encoded_for_signing(),
            EthTx::Eip1559(tx) => tx.encoded_for_signing(),
        }
    }

    /// Attach a signature and wrap in alloy's envelope. For legacy, alloy
    /// derives the EIP-155 `v` (35 + 2·chain_id + parity) from the tx's
    /// chain id during encoding — the caller only ever supplies `y_parity`.
    pub fn into_envelope(self, signature: Signature) -> TxEnvelope {
        match self {
            EthTx::Legacy(tx) => tx.into_signed(signature).into(),
            EthTx::Eip2930(tx) => tx.into_signed(signature).into(),
            EthTx::Eip1559(tx) => tx.into_signed(signature).into(),
        }
    }
}

/// Public-API selector for the tx type to build in `prepare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EthTxType {
    Legacy,
    Eip2930,
    #[default]
    Eip1559,
}

/// The per-type slice of an intent: the variant selects the tx type, and
/// only carries the fields that type supports — a legacy tx with an access
/// list is unrepresentable rather than validated away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxParams {
    Legacy {
        gas_price: u128,
    },
    Eip2930 {
        gas_price: u128,
        access_list: AccessList,
    },
    Eip1559 {
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        access_list: AccessList,
    },
}

/// The caller's input
#[derive(Debug, PartialEq, Eq)]
pub struct TxIntent {
    pub chain_id: ChainId,
    pub nonce: TxNonce,
    /// `TxKind::Create` for contract deployment (`data` is the init code).
    pub kind: TxKind,
    pub value: U256,
    pub gas_limit: u64,
    pub data: Bytes,
    pub params: TxParams,
}

/// The output of 'prepare_tx'
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedTx {
    pub tx: EthTx,
    pub signing_hash: B256,
}

impl From<TxIntent> for EthTx {
    fn from(intent: TxIntent) -> Self {
        match intent.params {
            TxParams::Legacy { gas_price } => EthTx::Legacy(TxLegacy {
                chain_id: Some(intent.chain_id),
                nonce: intent.nonce,
                gas_price,
                gas_limit: intent.gas_limit,
                to: intent.kind,
                value: intent.value,
                input: intent.data,
            }),
            TxParams::Eip2930 {
                gas_price,
                access_list,
            } => EthTx::Eip2930(TxEip2930 {
                chain_id: intent.chain_id,
                nonce: intent.nonce,
                gas_price,
                gas_limit: intent.gas_limit,
                to: intent.kind,
                value: intent.value,
                access_list,
                input: intent.data,
            }),
            TxParams::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                access_list,
            } => EthTx::Eip1559(TxEip1559 {
                chain_id: intent.chain_id,
                nonce: intent.nonce,
                gas_limit: intent.gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                to: intent.kind,
                value: intent.value,
                access_list,
                input: intent.data,
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignedTx {
    /// EIP-2718 encoded, ready to broadcast (legacy = bare RLP list, typed
    /// starts with 0x01/0x02)
    pub raw: Bytes,
    /// keccak256 of the encoded signed tx
    pub tx_hash: B256,
    /// recovered & verified signer
    pub from: Address,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TxRequest {
    /// `None` requests contract creation (`data` becomes the init code).
    pub to: Option<Address>,
    pub value: U256,
    pub data: Bytes,
    pub tx_type: EthTxType,
    /// Only meaningful for 2930/1559 — `enrich` refuses it on legacy rather
    /// than silently dropping it.
    pub access_list: AccessList,
}

/// Errors that can occur during 'prepare_tx'
#[derive(Error, Debug)]
pub enum PrepareError {
    #[error("chain id must not be zero")]
    ZeroChainId,

    /// A legacy tx without EIP-155 replay protection: only reachable via
    /// decoded third-party bytes — `enrich` always stamps a chain id.
    #[error("legacy transaction without EIP-155 chain id")]
    MissingChainId,

    #[error("max priority fee per gas must not exceed max fee per gas")]
    MaxPriorityFeeExceedsMaxFee,

    #[error("gas limit must not be zero")]
    ZeroGasLimit,

    #[error("legacy transactions do not support access lists")]
    AccessListUnsupported,

    #[cfg(feature = "rpc")]
    #[error("failed to enrich transaction from RPC: {0}")]
    Enrich(#[from] EnrichError),
}

/// A 33-byte, correctly-prefixed pubkey that is nonetheless not a curve
/// point. Unreachable for keys produced by the MPC layer — a broken
/// invariant (500), never a caller mistake.
#[derive(Error, Debug)]
#[error("public key is not a valid secp256k1 point")]
pub struct PubkeyError;

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
    #[error(
        "unsupported transaction type: {0:#04x}, expected legacy (RLP list), 0x01 (EIP-2930) or 0x02 (EIP-1559)"
    )]
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
