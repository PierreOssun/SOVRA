use alloy_primitives::{Address, Bytes, U256};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "sovra-cli",
    version,
    about = "Drive the sovra-api orchestrator"
)]
pub struct Cli {
    /// Orchestrator base URL.
    #[arg(long, env = "SOVRA_API_URL", default_value = "http://127.0.0.1:3000")]
    pub api_url: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the one-time DKG ceremony (409 if already initialized).
    Dkg,
    /// Build an unsigned EIP-1559 tx from the active DKG address.
    Prepare {
        #[arg(long)]
        to: Address,
        /// Amount in wei.
        #[arg(long)]
        value: U256,
        /// Calldata as 0x-hex.
        #[arg(long, default_value = "0x")]
        data: Bytes,
    },
    /// Sign an unsigned transaction (0x02-prefixed hex, as returned by prepare).
    Sign {
        #[arg(long)]
        tx: Bytes,
    },
}
