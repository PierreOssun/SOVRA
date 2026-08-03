//! DKLs23 (Silence Laboratories) MPC backend.
//!
//! Two layers:
//! * `keygen_party` / `sign_party` — single-party runners, driven once per process over
//!   any `Relay` (a `WsRelay` in `sovra-cosigner`, `SimpleMessageRelay` in tests).
//! * `InProcessBackend` — runs *both* parties in one process; test-only, holds both shards,
//!   pins the HTTP contract in `sovra-api/tests/api_flow.rs`.

#[cfg(test)]
mod tests;
pub mod types;

use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use alloy_primitives::{Address, B256};
use derivation_path::DerivationPath;
use ed25519_dalek::{SigningKey, VerifyingKey};
use k256::ecdsa::VerifyingKey as K256VerifyingKey;
use sl_dkls23::{
    keygen::{self, Keyshare},
    setup::{keygen::SetupMessage as KeygenSetup, sign::SetupMessage as SignSetup},
    sign,
};
use sl_mpc_mate::{
    coord::{
        Relay, SimpleMessageRelay,
        stats::{RelayStats, Stats},
    },
    message::InstanceId,
};
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError, to_ecdsa_parts};
use sovra_state::SignerStore;
use sovra_types::{ACTIVE_SIGNER_ID, KeyShare, SignerId, SignerMetadata};

use crate::types::PartyContext;

/// Number of cosigners in the scheme — the `n` in a `t`-of-`n` setup.
const PARTIES: usize = 2;

/// Minimum parties required to sign — the `t` in `t`-of-`n`.
/// At `t = n = 2` there is no redundancy: *both* cosigners must participate
/// in every DKG and every signature.
const THRESHOLD: usize = 2;

/// Time-to-live for a protocol run's setup messages: how long the relay
/// retains them and how long a party will wait before the round is considered
/// expired.
/// Note: Generous here because both parties run in-process and finish fast;
const DEFAULT_TTL: Duration = Duration::from_secs(60);

pub struct InProcessBackend {
    stores: [SignerStore; 2],
    signing_keys: [SigningKey; 2],
    party_vks: [VerifyingKey; 2],
    ttl: Duration,
}

impl InProcessBackend {
    pub fn new(stores: [SignerStore; 2]) -> Self {
        let signing_keys = [
            SigningKey::generate(&mut rand::rngs::OsRng),
            SigningKey::generate(&mut rand::rngs::OsRng),
        ];
        let party_vks = [
            signing_keys[0].verifying_key(),
            signing_keys[1].verifying_key(),
        ];
        Self {
            stores,
            signing_keys,
            party_vks,
            ttl: DEFAULT_TTL,
        }
    }

    fn ctx(&self, party_id: u8, instance: B256) -> PartyContext {
        PartyContext {
            party_id,
            instance,
            signing_key: self.signing_keys[party_id as usize].clone(),
            party_vks: self.party_vks, // VerifyingKey is Copy; if not, use `.clone()` on the array
            ttl: self.ttl,
        }
    }
}
impl MpcBackend for InProcessBackend {
    async fn dkg(&self) -> Result<Address, MpcError> {
        let instance = B256::from(rand::random::<[u8; 32]>());
        let coord = SimpleMessageRelay::new();

        let ctx0 = self.ctx(0, instance);
        let ctx1 = self.ctx(1, instance);
        let (r0, r1) = tokio::join!(
            keygen_party(&ctx0, coord.connect()),
            keygen_party(&ctx1, coord.connect()),
        );
        let (share0, addr0) = r0?;
        let (share1, addr1) = r1?;

        if addr0 != addr1 {
            return Err(MpcError::PartyMismatch(format!(
                "dkg addresses differ: {addr0} != {addr1}"
            )));
        }

        let meta = SignerMetadata {
            signer_id: SignerId::new(ACTIVE_SIGNER_ID),
            address: addr0,
        };
        self.stores[0]
            .save_shard(&meta, &share0)
            .map_err(|e| MpcError::Dkg(e.to_string()))?;
        self.stores[1]
            .save_shard(&meta, &share1)
            .map_err(|e| MpcError::Dkg(e.to_string()))?;
        Ok(addr0)
    }

    async fn sign(&self, unsigned_tx: &[u8]) -> Result<EcdsaParts, MpcError> {
        // Mirror the production trust shape: the digest is derived here from
        // decoded bytes — this backend cannot be handed a digest to sign.
        let prepared = sovra_eth::decode_unsigned(unsigned_tx)
            .map_err(|e| MpcError::Sign(format!("undecodable transaction: {e}")))?;
        sovra_eth::prepare::validate_unsigned(&prepared.tx)
            .map_err(|e| MpcError::Sign(format!("invalid transaction: {e}")))?;
        let signing_hash = prepared.signing_hash;
        let id = SignerId::new(ACTIVE_SIGNER_ID);
        let share0 = self.stores[0]
            .load_shard(&id)
            .map_err(|e| MpcError::Sign(e.to_string()))?;
        let share1 = self.stores[1]
            .load_shard(&id)
            .map_err(|e| MpcError::Sign(e.to_string()))?;

        let instance = B256::from(rand::random::<[u8; 32]>());
        let coord = SimpleMessageRelay::new();

        let ctx0 = self.ctx(0, instance);
        let ctx1 = self.ctx(1, instance);
        let (r0, r1) = tokio::join!(
            sign_party(&ctx0, &share0, signing_hash, coord.connect()),
            sign_party(&ctx1, &share1, signing_hash, coord.connect()),
        );
        let parts0 = r0?;
        let parts1 = r1?;

        if parts0 != parts1 {
            return Err(MpcError::PartyMismatch(
                "sign parts differ between parties".into(),
            ));
        }
        Ok(parts0)
    }
}

/// Ethereum address from a keyshare's shared public key. Reuses alloy's
/// keccak-based derivation — no hand-rolled hashing.
pub fn address_from_keyshare(keyshare: &Keyshare) -> Result<Address, MpcError> {
    let affine = keyshare.public_key().to_affine();
    let vk = K256VerifyingKey::from_affine(affine)
        .map_err(|e| MpcError::Dkg(format!("bad public key: {e}")))?;
    Ok(Address::from_public_key(&vk))
}

/// This party's half of a 2-of-2 DKG. Returns its own shard (opaque bytes for the store)
/// and the address it independently derived from that shard.
pub async fn keygen_party(
    ctx: &PartyContext,
    relay: impl Relay,
) -> Result<(KeyShare, Address), MpcError> {
    let ranks = [0u8; PARTIES];

    let setup = KeygenSetup::new(
        InstanceId::new(ctx.instance.0), // B256 -> [u8; 32]
        ctx.signing_key.clone(),         // real ed25519 identity (was NoSigningKey)
        ctx.party_id as usize,
        ctx.party_vks.to_vec(), // real peer keys (was NoVerifyingKey)
        &ranks,
        THRESHOLD,
    )
    .with_ttl(ctx.ttl);
    // If MS inference ever complains, annotate:
    // let setup: KeygenSetup<_, _, ed25519::Signature> = KeygenSetup::new(...)...;

    let stats = Stats::alloc();
    let keyshare = keygen::run(setup, rand::random(), RelayStats::new(relay, stats.clone()))
        .await
        .map_err(|e| MpcError::Dkg(e.to_string()))?;
    log_bandwidth(ctx.party_id, &stats, "dkg");

    let address = address_from_keyshare(&keyshare)?; // library `Keyshare` -> Address
    let share = KeyShare::from(keyshare.as_slice().to_vec()); // library -> opaque bytes
    Ok((share, address))
}

/// This party's half of a signing round over `digest`.
pub async fn sign_party(
    ctx: &PartyContext,
    share: &KeyShare, // opaque bytes from the store
    digest: B256,
    relay: impl Relay,
) -> Result<EcdsaParts, MpcError> {
    let keyshare: Arc<Keyshare> = Keyshare::from_bytes(share.as_bytes()) // opaque -> library
        .map(Arc::new)
        .ok_or(MpcError::Deserialize)?; // from_bytes is Option

    let chain_path = DerivationPath::from_str("m")
        .map_err(|e| MpcError::Sign(format!("bad chain path: {e}")))?;

    let setup = SignSetup::new(
        InstanceId::new(ctx.instance.0),
        ctx.signing_key.clone(),
        ctx.party_id as usize,
        ctx.party_vks.to_vec(),
        keyshare.clone(), // Arc<Keyshare> — SignSetup::new wants Arc<KS>
    )
    .with_chain_path(chain_path)
    .with_hash(digest.0)
    .with_ttl(ctx.ttl);

    let stats = Stats::alloc();
    let (sig, recid) = sign::run(setup, rand::random(), RelayStats::new(relay, stats.clone()))
        .await
        .map_err(|e| MpcError::Sign(format!("{e:?}")))?;
    log_bandwidth(ctx.party_id, &stats, "sign");

    Ok(to_ecdsa_parts(&sig, recid))
}

fn log_bandwidth(party_id: u8, stats: &Arc<Mutex<Stats>>, phase: &str) {
    let s = Stats::inner(stats.clone());
    tracing::info!(
        party = party_id,
        phase,
        send_kb = s.send_size as f64 / 1024.0,
        recv_kb = s.recv_size as f64 / 1024.0,
        send_count = s.send_count,
        recv_count = s.recv_count,
        "mpc bandwidth",
    );
}

impl InProcessBackend {
    /// Startup recovery for the test backend: both stores empty → None; both
    /// holding the same address → Some; anything else is partial DKG state.
    pub fn recover_active(&self) -> Result<Option<Address>, MpcError> {
        let id = SignerId::new(ACTIVE_SIGNER_ID);
        let party0 = self.stores[0]
            .load_active(&id)
            .map_err(|e| MpcError::Dkg(e.to_string()))?;
        let party1 = self.stores[1]
            .load_active(&id)
            .map_err(|e| MpcError::Dkg(e.to_string()))?;

        match (party0, party1) {
            (None, None) => Ok(None),
            (Some(a), Some(b)) if a == b => Ok(Some(a)),
            (party0, party1) => Err(MpcError::Dkg(format!(
                "shard stores disagree (party0: {party0:?}, party1: {party1:?}); \
                 partial dkg state — wipe both store dirs and re-run dkg"
            ))),
        }
    }
}
