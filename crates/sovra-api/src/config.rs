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
