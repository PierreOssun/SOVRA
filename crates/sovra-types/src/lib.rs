//! Shared, serializable types for the `sign` path.
//!
//! Deliberately MPC-backend-agnostic and chain-agnostic: the opaque
//! [`KeyShare`] holds whatever bytes the MPC backend's shard codec
//! produces, and [`PubkeySec1`] — not a
//! network's address format — is the canonical key identity, since one
//! secp256k1 key yields a different address on every network.
//! Round-message types are owned by the MPC library, not modeled here.

use alloy_primitives::{U256, hex};
use serde::{Deserialize, Serialize};

/// The single active DKG generation is always stored under this id.
pub const ACTIVE_SIGNER_ID: &str = "default";

/// The networks this service can sign for. A closed union: adding a variant
/// is a deliberate act that the compiler turns into a checklist of every
/// `match` that must learn about it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    #[default]
    Ethereum,
}

/// A 33-byte compressed SEC1 secp256k1 public key — the chain-neutral key
/// identity. Guaranteed well-formed by construction: exactly 33 bytes with a
/// 0x02/0x03 parity prefix (point-on-curve is the MPC layer's concern).
/// Serializes as a 0x-prefixed hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PubkeySec1([u8; 33]);

/// Why `from_slice` failed; the message is precise enough for a 4xx body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidPubkey(String);

impl std::fmt::Display for InvalidPubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid compressed SEC1 public key: {}", self.0)
    }
}

impl std::error::Error for InvalidPubkey {}

impl PubkeySec1 {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, InvalidPubkey> {
        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|_| InvalidPubkey(format!("expected 33 bytes, got {}", bytes.len())))?;
        if !matches!(bytes[0], 0x02 | 0x03) {
            return Err(InvalidPubkey(format!(
                "expected 0x02/0x03 parity prefix, got {:#04x}",
                bytes[0]
            )));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

impl std::fmt::Display for PubkeySec1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl std::str::FromStr for PubkeySec1 {
    type Err = InvalidPubkey;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `hex::decode` accepts an optional 0x prefix.
        let bytes = hex::decode(s).map_err(|e| InvalidPubkey(e.to_string()))?;
        Self::from_slice(&bytes)
    }
}

impl Serialize for PubkeySec1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PubkeySec1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// ECDSA signature components, as `finalize` consumes them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EcdsaParts {
    pub r: U256,
    pub s: U256,
    pub y_parity: bool,
}

/// Stable identifier for a provisioned signer (a cosigner pair).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerId(pub String);

impl SignerId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SignerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Opaque key-share bytes for one MPC party.
///
/// The active backend's shard codec defines the encoding (a versioned,
/// magic-prefixed body). Kept opaque so persistence never depends on the
/// MPC backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyShare(pub Vec<u8>);

impl KeyShare {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KeyShare {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Metadata persisted alongside a signer's shards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerMetadata {
    pub signer_id: SignerId,
    /// The wallet's public key — per-network addresses are derived from it,
    /// never stored.
    pub public_key: PubkeySec1,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> [u8; 33] {
        let mut b = [0u8; 33];
        b[0] = 0x02;
        b[32] = 0x01;
        b
    }

    #[test]
    fn pubkey_roundtrips_through_string_and_serde() {
        let pk = PubkeySec1::from_slice(&valid()).unwrap();
        assert_eq!(pk.to_string().parse::<PubkeySec1>().unwrap(), pk);

        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, format!("\"{pk}\""));
        assert_eq!(serde_json::from_str::<PubkeySec1>(&json).unwrap(), pk);
    }

    #[test]
    fn pubkey_rejects_wrong_length_and_prefix() {
        assert!(PubkeySec1::from_slice(&[0x02; 32]).is_err());
        assert!(PubkeySec1::from_slice(&[0x02; 34]).is_err());
        // 0x04 is the uncompressed prefix — 33 bytes of it is malformed.
        let mut uncompressed_prefix = valid();
        uncompressed_prefix[0] = 0x04;
        assert!(PubkeySec1::from_slice(&uncompressed_prefix).is_err());
    }

    #[test]
    fn network_id_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&NetworkId::Ethereum).unwrap(),
            "\"ethereum\""
        );
    }
}
