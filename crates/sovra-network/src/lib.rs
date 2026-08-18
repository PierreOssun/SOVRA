//! The network seam: one trait for "a chain this service can sign for",
//! plus the tagged data types that cross it.
//!
//! Split of responsibilities: [`Network`] is *behavior* (decode → validate →
//! digests → policy view → finalize), implemented once per chain crate
//! (`sovra-eth` today) with an associated `Unsigned` type, so the pipeline
//! is generic without trait objects. [`TxView`]/[`TxError`]/
//! [`SignedArtifacts`] are *data* — closed serde-free unions and structs
//! shared by policy and the API layers, so adding a network is a compiler-
//! enforced checklist (every `match` on the enum must learn the variant).
//! This crate must stay lean: no alloy-consensus, no provider stack — RPC
//! I/O (fee estimation vs UTXO selection) deliberately sits outside the
//! trait, because those shapes don't generalize across chains.
//! Pattern: strategy trait with associated types; tagged enums at the
//! boundaries.

use alloy_primitives::{Address, B256, Bytes, U256};
use sovra_types::{EcdsaParts, NetworkId, PubkeySec1};

/// The policy-relevant slice of a decoded transaction, tagged by network so
/// a policy can never apply one chain's rules to another chain's tx.
#[derive(Debug, Clone, Copy)]
pub enum TxView<'a> {
    Ethereum(EthTxView<'a>),
}

/// Ethereum's policy view (all supported tx types share it).
#[derive(Debug, Clone, Copy)]
pub struct EthTxView<'a> {
    pub chain_id: u64,
    /// `None` means contract creation.
    pub to: Option<Address>,
    pub value: U256,
    pub data: &'a [u8],
}

/// Pipeline failures, bucketed by whose fault they are: `Decode`/`Validate`
/// are caller mistakes (4xx), `Finalize`/`Pubkey` are broken invariants
/// (5xx). Impls stringify their rich internal errors at this boundary; the
/// variant carries the HTTP class, the string carries the detail.
#[derive(thiserror::Error, Debug)]
pub enum TxError {
    #[error("undecodable transaction: {0}")]
    Decode(String),
    #[error("invalid transaction: {0}")]
    Validate(String),
    #[error("finalize failed: {0}")]
    Finalize(String),
    #[error("bad public key: {0}")]
    Pubkey(String),
}

/// Broadcast-ready output of [`Network::finalize`] — the only two things the
/// generic layer needs from a signed tx. Network-specific signed types stay
/// internal to each impl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedArtifacts {
    pub raw: Bytes,
    pub txid: B256,
}

/// One chain's signing pipeline. Everything is derived from the raw unsigned
/// bytes — the trait deliberately cannot express "trust this digest": each
/// party re-decodes and re-derives, which is the system's core invariant.
pub trait Network {
    const ID: NetworkId;

    /// The decoded unsigned transaction (e.g. `EthTx`).
    type Unsigned: Send + Sync;

    /// Strict parse of self-describing bytes: unsupported types and trailing
    /// bytes are errors, never ignored.
    fn decode_unsigned(bytes: &[u8]) -> Result<Self::Unsigned, TxError>;

    /// Invariants every tx must satisfy before signing, wherever it came from.
    fn validate(tx: &Self::Unsigned) -> Result<(), TxError>;

    /// The digests to sign, in canonical order. Ethereum: exactly one;
    /// Bitcoin (later): one sighash per input.
    fn signing_digests(tx: &Self::Unsigned) -> Vec<[u8; 32]>;

    /// The policy-relevant slice, for the cosigner's verdict.
    fn policy_view<'a>(tx: &'a Self::Unsigned) -> TxView<'a>;

    /// Attach signatures (one per digest, same order) and verify them
    /// against `signer` before emitting broadcast-ready bytes.
    fn finalize(
        tx: Self::Unsigned,
        sigs: &[EcdsaParts],
        signer: &PubkeySec1,
    ) -> Result<SignedArtifacts, TxError>;

    /// This network's display form of the chain-neutral key identity.
    fn derive_address(pk: &PubkeySec1) -> Result<String, TxError>;
}
