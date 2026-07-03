#[cfg(test)]
mod tests;
mod types;

use std::path::{Path, PathBuf};

use alloy_primitives::Address;
use sovra_types::{KeyShare, SignerId, SignerMetadata};
pub use types::*;

const METADATA_FILE: &str = "metadata.json";
const SHARD_FILE: &str = "shard.bin";

/// One party's on-disk store: exactly one shard per signer, plus metadata.
/// Now: The in-process PoC runs two of these (one root per party);
// TODO real cosigner need to point to its store at its own local directory.
pub struct SignerStore {
    root: PathBuf,
    sealer: Box<dyn ShardSealer>,
}

impl SignerStore {
    /// Open (creating the root if needed) with the default `Passthrough` sealer.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, StateError> {
        Self::open_with_sealer(root, Box::new(Passthrough))
    }

    /// Open with a custom at-rest sealer
    pub fn open_with_sealer(
        root: impl Into<PathBuf>,
        sealer: Box<dyn ShardSealer>,
    ) -> Result<Self, StateError> {
        let root = root.into();
        std::fs::create_dir_all(&root).at(&root)?;
        Ok(Self { root, sealer })
    }

    fn signer_dir(&self, id: &SignerId) -> Result<PathBuf, StateError> {
        let s = id.as_str();
        let safe = !s.is_empty()
            && s != "."
            && s != ".."
            && !s.contains('/')
            && !s.contains('\\')
            && !s.contains('\0');
        if !safe {
            return Err(StateError::InvalidSignerId(id.clone()));
        }
        Ok(self.root.join(s))
    }

    /// Persist this party's single shard plus the signer metadata. Idempotent:
    /// re-saving the same signer overwrites both files.
    pub fn save_shard(&self, meta: &SignerMetadata, shard: &KeyShare) -> Result<(), StateError> {
        let dir = self.signer_dir(&meta.signer_id)?;
        std::fs::create_dir_all(&dir).at(&dir)?;
        set_mode(&dir, 0o700)?;

        // Metadata: plaintext JSON (the address is public).
        let meta_bytes = serde_json::to_vec_pretty(meta)?;
        write_atomic(&dir.join(METADATA_FILE), &meta_bytes)?;

        // Shard: routed through the sealer (Passthrough = identity in M2).
        let sealed = self.sealer.seal(shard.as_bytes())?;
        write_atomic(&dir.join(SHARD_FILE), &sealed)?;

        Ok(())
    }
    /// Load this party's shard for a signer.
    pub fn load_shard(&self, id: &SignerId) -> Result<KeyShare, StateError> {
        let path = self.signer_dir(id)?.join(SHARD_FILE);
        let sealed = read_or_not_found(&path, id)?;
        let plaintext = self.sealer.open(&sealed)?;
        Ok(KeyShare::from(plaintext))
    }

    /// Load a signer's metadata.
    pub fn load_metadata(&self, id: &SignerId) -> Result<SignerMetadata, StateError> {
        let path = self.signer_dir(id)?.join(METADATA_FILE);
        let bytes = read_or_not_found(&path, id)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Find the signer whose stored metadata matches `address`.
    /// Scans the per-signer metadata files; first match wins.
    pub fn find_by_address(&self, address: &Address) -> Result<SignerId, StateError> {
        let entries = std::fs::read_dir(&self.root).at(&self.root)?;

        for entry in entries {
            let entry = entry.at(&self.root)?;
            let meta_path = entry.path().join(METADATA_FILE);

            let bytes = match std::fs::read(&meta_path) {
                Ok(b) => b,
                // Not a signer dir (no metadata.json) — skip, don't fail the scan.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(StateError::Io {
                        path: meta_path,
                        source,
                    });
                }
            };

            let meta: SignerMetadata = serde_json::from_slice(&bytes)?;
            if &meta.address == address {
                return Ok(meta.signer_id);
            }
        }

        Err(StateError::AddressNotFound(*address))
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), StateError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).at(path)
}
#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), StateError> {
    Ok(())
}

fn read_or_not_found(path: &Path, id: &SignerId) -> Result<Vec<u8>, StateError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(StateError::NotFound(id.clone())),
        Err(source) => Err(StateError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StateError> {
    let dir = path.parent().expect("file path must have a parent");
    let tmp = dir.join(format!(
        ".tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("f")
    ));
    std::fs::write(&tmp, bytes).at(&tmp)?;
    // perms before rename, so the file is never briefly world-readable
    set_mode(&tmp, 0o600)?;
    std::fs::rename(&tmp, path).at(path)
}
