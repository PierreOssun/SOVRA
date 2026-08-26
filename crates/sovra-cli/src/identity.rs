//! The `identity` verb: print this host's cosigner identity verifying key,
//! minting `data_dir/identity.key` on first run — so provisioning (compose
//! init, `sovra roster`) can know a party's key BEFORE its cosigner ever
//! starts. Mirrors sovra-cosigner's `identity::load_or_generate` contract
//! exactly (raw 32 bytes, 0600, atomic write, refuse a wrong-sized file)
//! without pulling the whole cosigner crate into the CLI; both sides go
//! through `sovra_state::write_atomic`, so the on-disk behavior cannot
//! drift.

use std::{path::Path, process::ExitCode};

use ed25519_dalek::SigningKey;

pub fn run(data_dir: &Path) -> ExitCode {
    match load_or_generate(data_dir) {
        Ok(key) => {
            // Same encoding the cosigner logs and serves on GET /identity.
            println!(
                "{}",
                alloy_primitives::hex::encode(key.verifying_key().as_bytes())
            );
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

fn load_or_generate(data_dir: &Path) -> Result<SigningKey, String> {
    let path = data_dir.join("identity.key");
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            format!(
                "{} is {} bytes, expected 32 — refusing to regenerate a pinned identity",
                path.display(),
                bytes.len(),
            )
        })?;
        Ok(SigningKey::from_bytes(&arr))
    } else {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        sovra_state::write_atomic(&path, key.as_bytes()).map_err(|e| e.to_string())?;
        Ok(key)
    }
}
