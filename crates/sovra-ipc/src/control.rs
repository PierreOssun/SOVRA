use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use sovra_mpc::EcdsaParts;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StartDkgRequest {
    pub instance: B256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StartSignRequest {
    pub instance: B256,
    pub tx_digest: B256,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
