use config::{Config as RawConfig, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub rpc_url: String,
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_party0_dir")]
    pub party0_dir: String,
    #[serde(default = "default_party1_dir")]
    pub party1_dir: String,
}
fn default_bind_addr() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_party0_dir() -> String {
    "data/party0".to_string()
}

fn default_party1_dir() -> String {
    "data/party1".to_string()
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
