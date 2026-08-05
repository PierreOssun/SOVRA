//! Orchestrator configuration: `config/sepolia` file, overridable per key by
//! `SOVRA_*` environment variables (e.g. `SOVRA_BIND_ADDR`).
//!
//! Why the `config` crate: file + env layering with serde deserialization in
//! a few lines, instead of hand-rolling precedence. Defaults live in serde
//! `#[serde(default)]` attributes so the file only needs to state what
//! deviates. Pattern: layered (12-factor-style) configuration.

use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

/// One cosigner endpoint. The list's order is the signing preference order —
/// the cold recovery party goes last so it is only selected when a preferred
/// party is down.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignerEntry {
    pub party_id: u8,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Known limitation: the `config` crate's env source cannot express a
    /// table array, so this list is file-only (scalar keys keep their
    /// `SOVRA_*` overrides).
    pub cosigners: Vec<CosignerEntry>,
    /// t in t-of-n; n is the length of `cosigners`.
    #[serde(default = "default_threshold")]
    pub threshold: u8,
    #[serde(default = "default_relay_bind")]
    pub relay_bind: String,
    /// No defaults on purpose (mirrors the cosigner's rule): the control
    /// plane is mTLS-only, so missing material must fail startup, not fall
    /// back to plaintext.
    pub tls_ca_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}
fn default_bind_addr() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_relay_bind() -> String {
    "127.0.0.1:3100".into()
}

fn default_threshold() -> u8 {
    2
}

impl Config {
    /// Deserialization only — the cosigner-set invariants (unique party ids,
    /// threshold bounds) are enforced in `RemoteBackend::new`, the seam that
    /// owns them; `run()` constructs it before anything slow, so a bad set
    /// still fails startup immediately.
    pub fn load() -> Result<Self, ConfigError> {
        RawConfig::builder()
            .add_source(File::with_name("config/sepolia").required(true))
            .add_source(Environment::with_prefix("SOVRA").try_parsing(true))
            .build()?
            .try_deserialize()
    }
}
