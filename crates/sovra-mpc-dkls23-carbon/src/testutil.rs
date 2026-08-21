//! Shared ceremony fixtures for this crate's tests: deterministic party
//! contexts and a full multi-party DKG over the in-process hub.

use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::SigningKey;
use sovra_mpc::{MemoryHub, MpcError, PartyContext, PartyRunner};
use sovra_types::{KeyShare, PubkeySec1};

use crate::CarbonRunner;

pub(crate) fn contexts(threshold: u8, n: u8) -> Vec<PartyContext> {
    let keys: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let vks = keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>();
    keys.into_iter()
        .enumerate()
        .map(|(i, signing_key)| PartyContext {
            party_id: i as u8,
            instance: B256::repeat_byte(0xD1),
            signing_key,
            party_vks: vks.clone(),
            threshold,
            ttl: Duration::from_secs(30),
        })
        .collect()
}

pub(crate) async fn run_dkg(
    ctxs: Vec<PartyContext>,
) -> Vec<Result<(KeyShare, PubkeySec1), MpcError>> {
    let hub = MemoryHub::new();
    let mut tasks = Vec::new();
    for ctx in ctxs {
        let mut relay = hub.connect(ctx.party_id);
        tasks.push(tokio::spawn(async move {
            CarbonRunner.keygen(&ctx, &mut relay).await
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.expect("task not cancelled"));
    }
    out
}
