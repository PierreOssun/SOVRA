//! Control-plane wire types (HTTP/JSON bodies) shared by orchestrator and
//! cosigner, plus the correlation-id plumbing that threads one request id
//! through all three processes' logs.
//!
//! Why mirror DTOs instead of reusing domain types: [`SignParts`] duplicates
//! `sovra_mpc::EcdsaParts` (bridged by `From` both ways) so the wire contract
//! stays serde-serializable without dragging serde into the backend-agnostic
//! `sovra-mpc` seam, and can evolve independently of the domain type.
//! Plain data with no behavior. [`StartSignRequest`] carries the unsigned tx
//! preimage — never a digest — so each cosigner derives what it signs from
//! bytes it decoded itself; its `Bytes` field is why it alone isn't `Copy`.
//! Pattern: DTO / anti-corruption layer between wire and domain.

use alloy_primitives::{B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use sovra_mpc::EcdsaParts;
use sovra_types::{NetworkId, PubkeySec1};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StartDkgRequest {
    pub instance: B256,
    /// Assertions, not protocol inputs: the cosigner compares them against
    /// its local config and 409s on divergence, but always builds the keygen
    /// setup from its own roster — request data never shapes the ceremony.
    pub n_parties: u8,
    pub threshold: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSignRequest {
    pub instance: B256,
    /// Selects the decoder. Defense in depth, not trust: each cosigner's
    /// per-network decode is strict, so a tag that mismatches the bytes
    /// fails closed at every party.
    pub network: NetworkId,
    pub unsigned_transaction: Bytes,
    /// The signing subset: global party ids, strictly ascending (canonical
    /// order — every selected party must derive the identical subset vector).
    /// Each cosigner derives its own subset index from its position here.
    pub participants: Vec<u8>,
}

/// `POST /refresh` body — one party's view of the recovery re-share
/// ceremony. Like DKG, `n_parties`/`threshold` are assertions against local
/// config. `public_key` is the ceremony's anchor: survivors verify it
/// against their own shard, the lost party adopts it as the expected
/// reconstruction target — a wrong value fails the ceremony.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StartRefreshRequest {
    pub instance: B256,
    pub n_parties: u8,
    pub threshold: u8,
    pub lost_party: u8,
    pub public_key: PubkeySec1,
}

/// The wallet's compressed SEC1 public key — the answer of `GET /pubkey`
/// (derived from this party's shard), `GET /signer` (from stored metadata),
/// and every ceremony (`/dkg`, `/refresh`). Public data — it is the key the
/// whole world can already compute from any on-chain signature.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    pub public_key: PubkeySec1,
}

/// `GET /roster` response — the DKG pre-flight consistency probe. The
/// orchestrator only compares these for equality across parties (and against
/// its own n/threshold config); the hash definition lives in sovra-cosigner.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RosterInfo {
    pub n: u8,
    pub threshold: u8,
    pub roster_hash: B256,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignParts {
    pub r: U256,
    pub s: U256,
    pub y_parity: bool,
}

/// `POST /sign` response: one signature per digest the network defines for
/// the request's bytes, in digest order (Ethereum: exactly one).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignaturesInfo {
    pub signatures: Vec<SignParts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub verifying_key: String,
}

impl From<EcdsaParts> for SignParts {
    fn from(p: EcdsaParts) -> Self {
        Self {
            r: p.r,
            s: p.s,
            y_parity: p.y_parity,
        }
    }
}
impl From<SignParts> for EcdsaParts {
    fn from(p: SignParts) -> Self {
        Self {
            r: p.r,
            s: p.s,
            y_parity: p.y_parity,
        }
    }
}

pub const CORRELATION_HEADER: &str = "x-correlation-id";

tokio::task_local! { pub static CORRELATION_ID: String; }
