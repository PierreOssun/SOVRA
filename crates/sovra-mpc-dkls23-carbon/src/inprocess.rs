//! [`InProcessBackend`] — runs *all* parties in one process over a
//! [`MemoryHub`]; test-only, holds every shard, pins the orchestrator's HTTP
//! contract in `sovra-api/tests/api_flow.rs`. A direct port of the silence
//! backend's version: same store/identity/persistence shape, with the sl
//! relay swapped for the envelope hub and the sl runs for [`CarbonRunner`].

use std::time::Duration;

use alloy_primitives::B256;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sovra_eth::Ethereum;
use sovra_mpc::{
    EcdsaParts, MemoryHub, MpcBackend, MpcError, PartyContext, PartyRunner, sub_instance,
};
use sovra_network::Network;
use sovra_state::SignerStore;
use sovra_types::{ACTIVE_SIGNER_ID, KeyShare, NetworkId, PubkeySec1, SignerId, SignerMetadata};

use crate::CarbonRunner;

/// Generous because all parties run in-process and finish fast.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

pub struct InProcessBackend {
    stores: Vec<SignerStore>,
    signing_keys: Vec<SigningKey>,
    party_vks: Vec<VerifyingKey>,
    threshold: u8,
    ttl: Duration,
}

impl InProcessBackend {
    pub fn new(stores: Vec<SignerStore>, threshold: u8) -> Self {
        let signing_keys: Vec<SigningKey> = stores
            .iter()
            .map(|_| SigningKey::generate(&mut rand::rngs::OsRng))
            .collect();
        let party_vks = signing_keys.iter().map(|k| k.verifying_key()).collect();
        Self {
            stores,
            signing_keys,
            party_vks,
            threshold,
            ttl: DEFAULT_TTL,
        }
    }

    /// Startup recovery for the test backend: all stores empty → None; all
    /// holding the same public key → Some; anything else is partial DKG
    /// state. Stricter than the orchestrator's n-way probe on purpose —
    /// every store is local here, so there is no "cold party" to tolerate.
    pub fn recover_active(&self) -> Result<Option<PubkeySec1>, MpcError> {
        let id = SignerId::new(ACTIVE_SIGNER_ID);
        let mut reports = Vec::with_capacity(self.stores.len());
        for (party, store) in self.stores.iter().enumerate() {
            reports.push((
                party,
                store
                    .load_active(&id)
                    .map_err(|e| MpcError::Dkg(e.to_string()))?,
            ));
        }
        let first = reports[0].1;
        if reports.iter().any(|(_, a)| *a != first) {
            return Err(MpcError::Dkg(format!(
                "shard stores disagree ({reports:?}); \
                 partial dkg state — wipe the store dirs and re-run dkg"
            )));
        }
        Ok(first)
    }

    fn ctx(&self, party_id: u8, instance: B256) -> PartyContext {
        PartyContext {
            party_id,
            instance,
            signing_key: self.signing_keys[party_id as usize].clone(),
            party_vks: self.party_vks.clone(),
            threshold: self.threshold,
            ttl: self.ttl,
        }
    }

    /// Shared tail of dkg and refresh: collect every party's (share, pubkey),
    /// require public-key consensus, persist all shards atomically.
    fn persist_generation(
        &self,
        results: Vec<Result<(KeyShare, PubkeySec1), MpcError>>,
        op: &str,
    ) -> Result<PubkeySec1, MpcError> {
        let mut pairs = Vec::with_capacity(results.len());
        for r in results {
            pairs.push(r?);
        }
        let public_key = pairs[0].1;
        if let Some((_, other)) = pairs.iter().find(|(_, pk)| *pk != public_key) {
            return Err(MpcError::PartyMismatch(format!(
                "{op} public keys differ: {public_key} != {other}"
            )));
        }
        let meta = SignerMetadata {
            signer_id: SignerId::new(ACTIVE_SIGNER_ID),
            public_key,
        };
        for (store, (share, _)) in self.stores.iter().zip(&pairs) {
            store
                .save_shard(&meta, share)
                .map_err(|e| MpcError::Dkg(e.to_string()))?;
        }
        Ok(public_key)
    }
}

impl MpcBackend for InProcessBackend {
    async fn dkg(&self) -> Result<PubkeySec1, MpcError> {
        let instance = B256::from(rand::random::<[u8; 32]>());
        let hub = MemoryHub::new();
        let results = futures_util::future::join_all((0..self.stores.len() as u8).map(|p| {
            let ctx = self.ctx(p, instance);
            let mut relay = hub.connect(p);
            async move { CarbonRunner.keygen(&ctx, &mut relay).await }
        }))
        .await;
        self.persist_generation(results, "dkg")
    }

    async fn sign(
        &self,
        network: NetworkId,
        unsigned_tx: &[u8],
    ) -> Result<Vec<EcdsaParts>, MpcError> {
        // Mirror the production trust shape: digests are derived here from
        // decoded bytes — this backend cannot be handed a digest to sign.
        let digests = match network {
            NetworkId::Ethereum => {
                let tx = <Ethereum as Network>::decode_unsigned(unsigned_tx)
                    .map_err(|e| MpcError::Sign(e.to_string()))?;
                <Ethereum as Network>::validate(&tx).map_err(|e| MpcError::Sign(e.to_string()))?;
                <Ethereum as Network>::signing_digests(&tx)
            }
        };
        let id = SignerId::new(ACTIVE_SIGNER_ID);

        // The first t parties stand in for subset selection (RemoteBackend's
        // job in production) — every shard is local here anyway.
        let subset: Vec<u8> = (0..self.threshold).collect();
        let mut shares = Vec::with_capacity(subset.len());
        for &p in &subset {
            shares.push(
                self.stores[p as usize]
                    .load_shard(&id)
                    .map_err(|e| MpcError::Sign(e.to_string()))?,
            );
        }

        // Same per-digest instance derivation as the cosigner path; one hub
        // and one all-party run per digest, cross-checked afterwards.
        let instance = B256::from(rand::random::<[u8; 32]>());
        let mut signatures = Vec::with_capacity(digests.len());
        for (index, digest) in digests.iter().enumerate() {
            let run_instance = sub_instance(instance, index as u32);
            let hub = MemoryHub::new();
            let results =
                futures_util::future::join_all(subset.iter().zip(&shares).map(|(&p, share)| {
                    let ctx = self.ctx(p, run_instance);
                    let share = share.clone();
                    let subset = subset.clone();
                    let digest: B256 = (*digest).into();
                    let mut relay = hub.connect(p);
                    async move {
                        CarbonRunner
                            .sign(&ctx, &share, digest, &subset, &mut relay)
                            .await
                    }
                }))
                .await;
            let mut all = Vec::with_capacity(results.len());
            for r in results {
                all.push(r?);
            }
            let parts = all[0];
            if all.iter().any(|p| *p != parts) {
                return Err(MpcError::PartyMismatch(
                    "sign parts differ between parties".into(),
                ));
            }
            signatures.push(parts);
        }
        Ok(signatures)
    }

    /// All n parties in one process, each bringing its stored shard — the
    /// all-parties proactive re-randomize. A missing shard is an error, not
    /// a role: lost-shard recovery is a product flow (degraded sign + fresh
    /// DKG), not a protocol operation.
    async fn refresh(&self) -> Result<PubkeySec1, MpcError> {
        let id = SignerId::new(ACTIVE_SIGNER_ID);
        let mut shares: Vec<KeyShare> = Vec::with_capacity(self.stores.len());
        for store in &self.stores {
            shares.push(
                store
                    .load_shard(&id)
                    .map_err(|e| MpcError::Dkg(e.to_string()))?,
            );
        }
        let public_key = CarbonRunner.public_key_of(&shares[0])?;

        let instance = B256::from(rand::random::<[u8; 32]>());
        let hub = MemoryHub::new();
        let results =
            futures_util::future::join_all(shares.iter().enumerate().map(|(p, share)| {
                let ctx = self.ctx(p as u8, instance);
                let share = share.clone();
                let mut relay = hub.connect(p as u8);
                async move {
                    CarbonRunner
                        .refresh(&ctx, &share, &public_key, &mut relay)
                        .await
                }
            }))
            .await;
        // The atomic swap: every store overwrites its shard; old and new
        // generations do not interoperate, so partial persistence would be
        // caught by the next sign's keyshare cross-checks.
        self.persist_generation(results, "refresh")
    }
}
