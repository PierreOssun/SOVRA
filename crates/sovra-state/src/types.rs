use std::path::{Path, PathBuf};

use alloy_primitives::Address;
use sovra_types::SignerId;

/// Seals/unseals shard bytes at rest
pub trait ShardSealer: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StateError>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, StateError>;
}

/// Identity sealer: shard bytes are written as-is (for now)
pub struct Passthrough;

impl ShardSealer for Passthrough {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StateError> {
        //TODO encrypt & decrypt
        Ok(plaintext.to_vec())
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, StateError> {
        Ok(sealed.to_vec())
    }
}

pub trait IoResultExt<T> {
    fn at(self, path: &Path) -> Result<T, StateError>;
}
impl<T> IoResultExt<T> for std::io::Result<T> {
    fn at(self, path: &Path) -> Result<T, StateError> {
        self.map_err(|source| StateError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum StateError {
    #[error("i/o error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("serialization error")]
    Serde(#[from] serde_json::Error),
    #[error("signer not found: {0}")]
    NotFound(SignerId),
    #[error("no signer found for address {0}")]
    AddressNotFound(Address),
    #[error("invalid signer id: {0}")]
    InvalidSignerId(SignerId),
    #[error("could not unseal shard")]
    Seal,
    #[error(
        "metadata for {0} present but shard missing; partial dkg persistence — wipe the store dir and re-run dkg"
    )]
    PartialState(Address),
}
