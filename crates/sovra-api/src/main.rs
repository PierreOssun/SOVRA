use crate::config::Config;
use alloy_primitives::{Address, U256};
use sovra_eth::{TxRequest, http_provider, prepare_from_rpc};

mod config;
mod errors;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load()?;

    let provider = http_provider(&config.rpc_url)?;

    // dummy for now
    let req = TxRequest {
        to: Address::from([0x11; 20]),
        value: U256::from(1_000_000_000u64),
        data: Default::default(),
    };

    let from = Address::from([0x22; 20]);

    let _prepared = prepare_from_rpc(req, from, &provider).await?;

    Ok(())
}
