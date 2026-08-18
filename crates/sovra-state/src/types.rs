//! Support types for the store: the [`ShardSealer`] strategy trait (with the
//! identity [`Passthrough`] impl), the crate error enum, and [`IoResultExt`]
//! — a small extension that stamps every `io::Error` with the path it
//! happened at, because a bare "permission denied" from a store with several
//! files per signer is undebuggable. Errors carry operator remedies where
//! one exists (see `PartialState`). Pattern: strategy trait for sealing;
//! extension trait for error context.

use std::path::{Path, PathBuf};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use sovra_types::{PubkeySec1, SignerId};

/// Seals/unseals shard bytes at rest
pub trait ShardSealer: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StateError>;
    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, StateError>;
}

/// Identity sealer: shard bytes are written as-is. The default when no seal
/// key is configured — at-rest protection is then filesystem modes only.
pub struct Passthrough;

impl ShardSealer for Passthrough {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StateError> {
        Ok(plaintext.to_vec())
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, StateError> {
        Ok(sealed.to_vec())
    }
}

/// Versioned on-disk prefix for sealed shards. Its absence on `open` is a
/// hard error, not a plaintext fallback: once a party configures a seal key,
/// silently accepting an unsealed shard would defeat the point.
const SEAL_MAGIC: &[u8; 4] = b"SVR1";
const NONCE_LEN: usize = 24;

/// XChaCha20-Poly1305 sealer: `SVR1 || 24-byte random nonce || ciphertext`.
/// The extended nonce is why XChaCha: random nonces are collision-safe
/// without any counter state to persist. AEAD, so tampering fails `open`.
pub struct XChaChaSealer {
    cipher: XChaCha20Poly1305,
}

impl XChaChaSealer {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.into()),
        }
    }
}

impl ShardSealer for XChaChaSealer {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StateError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(&XNonce::from(nonce), plaintext)
            .map_err(|_| StateError::Seal)?;
        let mut sealed = Vec::with_capacity(SEAL_MAGIC.len() + NONCE_LEN + ciphertext.len());
        sealed.extend_from_slice(SEAL_MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open(&self, sealed: &[u8]) -> Result<Vec<u8>, StateError> {
        let rest = sealed.strip_prefix(SEAL_MAGIC).ok_or(StateError::Seal)?;
        if rest.len() < NONCE_LEN {
            return Err(StateError::Seal);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at yields NONCE_LEN bytes");
        self.cipher
            .decrypt(&XNonce::from(nonce), ciphertext)
            .map_err(|_| StateError::Seal)
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
    #[error("no signer found for public key {0}")]
    PubkeyNotFound(PubkeySec1),
    #[error("invalid signer id: {0}")]
    InvalidSignerId(SignerId),
    #[error("could not unseal shard")]
    Seal,
    #[error(
        "metadata for {0} present but shard missing; partial dkg persistence — wipe the store dir and re-run dkg"
    )]
    PartialState(PubkeySec1),
}
