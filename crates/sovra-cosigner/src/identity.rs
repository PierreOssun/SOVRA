use std::path::Path;

use ed25519_dalek::SigningKey;
use sovra_state::{IoResultExt, write_atomic};

use crate::errors::CosignerError;

const IDENTITY_FILE: &str = "identity.key";

/// Stable process identity: 32 raw bytes at `data_dir/identity.key`.
/// First run generates and persists (0600, atomic); later runs load the same key
/// the verifying key the peer has pinned must never change behind its back.
pub fn load_or_generate(data_dir: &Path) -> Result<SigningKey, CosignerError> {
    let path = data_dir.join(IDENTITY_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path).at(&path)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CosignerError::Identity(format!(
                "{} is {} bytes, expected 32 — refusing to regenerate a pinned identity",
                path.display(),
                bytes.len(),
            ))
        })?;
        Ok(SigningKey::from_bytes(&arr))
    } else {
        std::fs::create_dir_all(data_dir).at(data_dir)?;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        write_atomic(&path, key.as_bytes())?;
        Ok(key)
    }
}
