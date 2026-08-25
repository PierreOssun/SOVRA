//! clap definitions for the CLI surface: [`Cli`] (global `--api-url` /
//! `SOVRA_API_URL`), one [`Command`] variant per orchestrator endpoint, and
//! the local [`CertsCommand`] provisioning verbs (no HTTP — these run where
//! the material lives, so a deployed host never needs the Rust toolchain).
//!
//! Kept apart from `main.rs` so the argument surface is readable in one
//! screen, separate from the HTTP mechanics. Arguments use alloy types
//! (`Address`, `U256`, `Bytes`) directly — clap's `FromStr` path gives
//! parsing and error messages for free, and malformed input dies before any
//! request is sent. Doc comments double as `--help` text.
//! Pattern: declarative CLI (derive), types-as-validation at the edge.

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
    /// Broadcast a signed transaction (0x02-prefixed hex, as returned by sign).
    Broadcast {
        #[arg(long)]
        tx: Bytes,
    },
    /// Local certificate provisioning (CA machine and node halves).
    #[command(subcommand)]
    Certs(CertsCommand),
    /// Print this host's cosigner identity verifying key (hex), minting
    /// data_dir/identity.key on first run — lets provisioning collect the
    /// roster before any cosigner starts.
    Identity {
        #[arg(long, default_value = "data")]
        data_dir: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
pub enum CertsCommand {
    /// Mint (or load) the project CA under --dir. Run once, on the machine
    /// that keeps ca.key.pem — that key never leaves it.
    Ca {
        #[arg(long, default_value = "certs")]
        dir: std::path::PathBuf,
    },
    /// Node half of enrollment: generate this host's keypair + CSR under
    /// --dir. The key stays here forever; send only the .csr.pem to the CA
    /// machine.
    Csr {
        #[arg(long, default_value = "certs")]
        dir: std::path::PathBuf,
        /// File stem, e.g. `cosigner1` -> cosigner1.{key,csr}.pem.
        #[arg(long)]
        stem: String,
        /// Certificate CN; defaults to `sovra-<stem>`.
        #[arg(long)]
        cn: Option<String>,
        /// Extra SANs (IP or DNS) on top of 127.0.0.1/localhost — pass the
        /// host's tailscale IP here. Repeatable.
        #[arg(long)]
        san: Vec<String>,
    },
    /// CA half of enrollment: review and sign a node's CSR. Prints what the
    /// CSR asks for, writes `<csr stem>.cert.pem` next to it (or --out).
    /// Send the cert back to the node — it is public data.
    Sign {
        /// Path to the .csr.pem received from the node.
        csr: std::path::PathBuf,
        /// Directory holding ca.{cert,key}.pem.
        #[arg(long, default_value = "certs")]
        dir: std::path::PathBuf,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}
