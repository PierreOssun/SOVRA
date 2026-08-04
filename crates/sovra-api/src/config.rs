//! Orchestrator configuration: `config/sepolia` file, overridable per key by
//! `SOVRA_*` environment variables (e.g. `SOVRA_BIND_ADDR`).
//!
//! Why the `config` crate: file + env layering with serde deserialization in
//! a few lines, instead of hand-rolling precedence. Defaults live in serde
//! `#[serde(default)]` attributes so the file only needs to state what
//! deviates. Pattern: layered (12-factor-style) configuration.

use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    pub cosigner0_url: String,
    pub cosigner1_url: String,
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

impl Config {
    pub fn load() -> Result<Self, ConfigError> {
        RawConfig::builder()
            .add_source(File::with_name("config/sepolia").required(true))
            .add_source(Environment::with_prefix("SOVRA").try_parsing(true))
            .build()?
            .try_deserialize()
    }
}
