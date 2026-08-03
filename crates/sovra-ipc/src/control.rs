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

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use sovra_mpc::EcdsaParts;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StartDkgRequest {
    pub instance: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartSignRequest {
    pub instance: B256,
    pub unsigned_transaction: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignerInfo {
    pub address: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignParts {
    pub r: U256,
    pub s: U256,
    pub y_parity: bool,
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
