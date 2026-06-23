use alloy_consensus::SignableTransaction;
use alloy_primitives::{Address, Bytes, U256, address};
use alloy_provider::Provider;
use config::{Config, File};
use sovra_eth::{PreparedTx, TxRequest, http_provider, prepare_from_rpc};

const SEPOLIA_CHAIN_ID: u64 = 11_155_111;

fn rpc_url() -> String {
    if let Ok(url) = std::env::var("SEPOLIA_RPC_URL") {
        return url;
    }

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/sepolia");
    Config::builder()
        .add_source(File::with_name(path).required(true))
        .build()
        .and_then(|c| c.get_string("rpc_url"))
        .expect("read rpc_url from config/sepolia.toml")
}

// test EOAs
const ACCOUNT_1: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const ACCOUNT_2: Address = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

#[tokio::test]
#[ignore = "hits a live Sepolia RPC; run with --ignored"]
async fn prepare_matches_live_sepolia() {
    let provider = http_provider(&rpc_url()).expect("valid RPC URL");

    let req = TxRequest {
        to: ACCOUNT_2,
        value: U256::ZERO,
        data: Bytes::new(),
    };

    let PreparedTx { tx, signing_hash } = prepare_from_rpc(req, ACCOUNT_1, &provider)
        .await
        .expect("prepare should succeed");

    // chain_id matches the RPC and is Sepolia.
    let rpc_chain_id = provider.get_chain_id().await.expect("get_chain_id");
    assert_eq!(tx.chain_id, rpc_chain_id, "chain_id must match the RPC");
    assert_eq!(tx.chain_id, SEPOLIA_CHAIN_ID, "expected Sepolia chain id");

    // nonce matches the sender's pending transaction count on the same RPC.
    let rpc_nonce = provider
        .get_transaction_count(ACCOUNT_1)
        .pending()
        .await
        .expect("get_transaction_count");
    assert_eq!(tx.nonce, rpc_nonce, "nonce must match pending tx count");

    // Fees and gas are sane.
    assert!(tx.gas_limit > 0, "gas_limit must be > 0");
    assert!(tx.max_fee_per_gas > 0, "max_fee_per_gas must be > 0");
    assert!(
        tx.max_priority_fee_per_gas <= tx.max_fee_per_gas,
        "priority fee must not exceed max fee"
    );

    // signing_hash is consistent with the EIP-1559 signature hash of the returned fields.
    assert_eq!(
        tx.signature_hash(),
        signing_hash,
        "signing_hash must be the EIP-1559 signature hash of the prepared tx"
    );
}
