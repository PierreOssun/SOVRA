//! DKLs23 (Silence Laboratories) MPC backend.
//!
//! Two layers:
//! * `keygen_party` / `sign_party` — single-party runners, driven once per process over
//!   any `Relay` (a `WsRelay` in `sovra-cosigner`, `SimpleMessageRelay` in tests).
//! * `InProcessBackend` — runs *all* parties in one process; test-only, holds every shard,
//!   pins the HTTP contract in `sovra-api/tests/api_flow.rs`.
//!
//! t-of-n semantics (M9): keygen always involves all n parties of the roster;
//! signing runs over an explicit *subset* of t global party ids. The library's
//! sign setup is indexed by position **within the subset** (`party_idx`),
//! which only coincides with the global `party_id` when the subset is a
//! prefix — the mapping is derived here, never sent over the wire.

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
pub use sl_dkls23::keygen::Keyshare;
use sl_dkls23::{
    keygen::{self},
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

/// Time-to-live for a protocol run's setup messages: how long the relay
/// retains them and how long a party will wait before the round is considered
/// expired.
/// Note: Generous here because all parties run in-process and finish fast;
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

    /// Shared tail of dkg and refresh: collect every party's (share, address),
    /// require address consensus, persist all shards atomically.
    fn persist_generation(
        &self,
        results: Vec<Result<(KeyShare, Address), MpcError>>,
        op: &str,
    ) -> Result<Address, MpcError> {
        let mut pairs = Vec::with_capacity(results.len());
        for r in results {
            pairs.push(r?);
        }
        let address = pairs[0].1;
        if let Some((_, other)) = pairs.iter().find(|(_, addr)| *addr != address) {
            return Err(MpcError::PartyMismatch(format!(
                "{op} addresses differ: {address} != {other}"
            )));
        }
        let meta = SignerMetadata {
            signer_id: SignerId::new(ACTIVE_SIGNER_ID),
            address,
        };
        for (store, (share, _)) in self.stores.iter().zip(&pairs) {
            store
                .save_shard(&meta, share)
                .map_err(|e| MpcError::Dkg(e.to_string()))?;
        }
        Ok(address)
    }
}
impl MpcBackend for InProcessBackend {
    async fn dkg(&self) -> Result<Address, MpcError> {
        let instance = B256::from(rand::random::<[u8; 32]>());
        let coord = SimpleMessageRelay::new();

        let ctxs: Vec<PartyContext> = (0..self.stores.len() as u8)
            .map(|p| self.ctx(p, instance))
            .collect();
        let results = futures_util::future::join_all(
            ctxs.iter().map(|ctx| keygen_party(ctx, coord.connect())),
        )
        .await;
        self.persist_generation(results, "dkg")
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

        let instance = B256::from(rand::random::<[u8; 32]>());
        let coord = SimpleMessageRelay::new();

        let ctxs: Vec<PartyContext> = subset.iter().map(|&p| self.ctx(p, instance)).collect();
        let results =
            futures_util::future::join_all(ctxs.iter().zip(&shares).map(|(ctx, share)| {
                sign_party(ctx, share, signing_hash, &subset, coord.connect())
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
        Ok(parts)
    }

    /// All n parties in one process. Whatever the lost store still holds is
    /// ignored (production instead refuses a declared-lost party that has a
    /// shard) — this backend exists to pin the HTTP contract, and letting it
    /// run without file surgery keeps the api tests simple.
    async fn refresh(&self, lost_party: u8) -> Result<Address, MpcError> {
        let n = self.stores.len();
        if lost_party as usize >= n {
            return Err(MpcError::Dkg(format!(
                "lost party {lost_party} out of range for {n} parties"
            )));
        }
        let id = SignerId::new(ACTIVE_SIGNER_ID);
        let mut shares: Vec<Option<KeyShare>> = Vec::with_capacity(n);
        for (party, store) in self.stores.iter().enumerate() {
            if party == lost_party as usize {
                shares.push(None);
            } else {
                shares.push(Some(
                    store
                        .load_shard(&id)
                        .map_err(|e| MpcError::Dkg(e.to_string()))?,
                ));
            }
        }
        let survivor = shares
            .iter()
            .flatten()
            .next()
            .expect("n >= 2 leaves at least one survivor");
        let public_key = compressed_public_key(
            &Keyshare::from_bytes(survivor.as_bytes()).ok_or(MpcError::Deserialize)?,
        );

        let instance = B256::from(rand::random::<[u8; 32]>());
        let coord = SimpleMessageRelay::new();
        let ctxs: Vec<PartyContext> = (0..n as u8).map(|p| self.ctx(p, instance)).collect();
        let results =
            futures_util::future::join_all(ctxs.iter().zip(&shares).map(|(ctx, share)| {
                refresh_party(
                    ctx,
                    share.as_ref(),
                    lost_party,
                    &public_key,
                    coord.connect(),
                )
            }))
            .await;
        // The atomic swap: every store overwrites its shard; old and new
        // generations do not interoperate, so partial persistence would be
        // caught by the next sign's keyshare cross-checks.
        self.persist_generation(results, "refresh")
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

/// Compressed SEC1 encoding (33 bytes) of a keyshare's shared public key —
/// the value a refresh ceremony's lost party needs as `expected_public_key`.
pub fn compressed_public_key(keyshare: &Keyshare) -> [u8; 33] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    keyshare
        .public_key()
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("a compressed sec1 point is 33 bytes")
}

/// Validated setup for the ceremonies that involve ALL n parties (keygen and
/// key-refresh share it verbatim): global ids, full roster, all-zero ranks.
/// The one place the scheme bounds (`2 <= t <= n`, `party_id < n`) are
/// checked. The library copies `ranks` into the message, so no lifetime
/// escapes.
fn keygen_setup(
    ctx: &PartyContext,
) -> Result<KeygenSetup<SigningKey, VerifyingKey, ed25519_dalek::Signature>, MpcError> {
    let n = ctx.party_vks.len();
    if !(2..=n).contains(&(ctx.threshold as usize)) || ctx.party_id as usize >= n {
        return Err(MpcError::Dkg(format!(
            "invalid scheme: {}-of-{n} with party_id {}",
            ctx.threshold, ctx.party_id
        )));
    }
    let ranks = vec![0u8; n];
    Ok(KeygenSetup::new(
        InstanceId::new(ctx.instance.0), // B256 -> [u8; 32]
        ctx.signing_key.clone(),
        ctx.party_id as usize, // keygen/refresh are indexed by GLOBAL id — unlike sign
        ctx.party_vks.clone(),
        &ranks,
        ctx.threshold as usize,
    )
    .with_ttl(ctx.ttl))
}

/// This party's share of a key-refresh ceremony: all n parties rebuild their
/// shards around the same public key; `lost_party` (which brings no shard)
/// gets a brand-new one. Survivors pass `Some(old_share)`, the lost party
/// `None` — any other combination is refused before the relay is touched.
/// The library enforces that the reconstructed key equals `public_key`, so a
/// wrong expected key fails the ceremony instead of corrupting anything.
pub async fn refresh_party(
    ctx: &PartyContext,
    old_share: Option<&KeyShare>,
    lost_party: u8,
    public_key: &[u8; 33],
    relay: impl Relay,
) -> Result<(KeyShare, Address), MpcError> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let setup = keygen_setup(ctx)?;
    let n = ctx.party_vks.len();
    if lost_party as usize >= n {
        return Err(MpcError::Dkg(format!(
            "lost party {lost_party} out of range for {n} parties"
        )));
    }
    // The library enforces lost_count <= n - t; with one lost party that
    // means t == n (e.g. 2-of-2) has no redundancy to rebuild from — name it
    // instead of surfacing an opaque InvalidKeyRefresh.
    if ctx.threshold as usize == n {
        return Err(MpcError::Dkg(format!(
            "a {n}-of-{n} scheme has no redundancy to recover a lost share",
        )));
    }
    let encoded = k256::EncodedPoint::from_bytes(public_key)
        .map_err(|e| MpcError::Dkg(format!("bad expected public key: {e}")))?;
    let expected =
        Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_encoded_point(&encoded))
            .ok_or_else(|| MpcError::Dkg("expected public key is not a curve point".into()))?;

    let refresh_input = match (old_share, ctx.party_id == lost_party) {
        (None, true) => keygen::key_refresh::KeyshareForRefresh::from_lost_keyshare(
            vec![0u8; n],
            ctx.threshold,
            expected,
            vec![lost_party],
            ctx.party_id,
        ),
        (Some(share), false) => {
            let keyshare = Keyshare::from_bytes(share.as_bytes()).ok_or(MpcError::Deserialize)?;
            if keyshare.party_id != ctx.party_id
                || keyshare.total_parties as usize != n
                || keyshare.threshold != ctx.threshold
            {
                return Err(MpcError::Dkg(format!(
                    "keyshare/scheme mismatch: shard is party {} of {}-of-{}, \
                     refresh runs as party {} of {}-of-{n}",
                    keyshare.party_id,
                    keyshare.threshold,
                    keyshare.total_parties,
                    ctx.party_id,
                    ctx.threshold,
                )));
            }
            if compressed_public_key(&keyshare) != *public_key {
                return Err(MpcError::PartyMismatch(
                    "expected public key does not match this party's shard".into(),
                ));
            }
            keygen::key_refresh::KeyshareForRefresh::from_keyshare(
                &keyshare,
                Some(vec![lost_party]),
            )
        }
        (Some(_), true) => {
            return Err(MpcError::Dkg(format!(
                "party {} is declared lost but still holds a shard — delete its store first",
                ctx.party_id
            )));
        }
        (None, false) => {
            return Err(MpcError::Dkg(format!(
                "party {} has no shard but is not the declared lost party",
                ctx.party_id
            )));
        }
    };

    let stats = Stats::alloc();
    let keyshare = keygen::key_refresh::run(
        setup,
        rand::random(),
        RelayStats::new(relay, stats.clone()),
        refresh_input,
    )
    .await
    .map_err(|e| MpcError::Dkg(e.to_string()))?;
    log_bandwidth(ctx.party_id, &stats, "refresh");

    // Belt over the protocol's own expected_public_key check.
    if compressed_public_key(&keyshare) != *public_key {
        return Err(MpcError::PartyMismatch(
            "refresh produced a different public key".into(),
        ));
    }
    let address = address_from_keyshare(&keyshare)?;
    Ok((KeyShare::from(keyshare.as_slice().to_vec()), address))
}

/// This party's share of a t-of-n DKG over the full roster. Returns its own
/// shard (opaque bytes for the store) and the address it independently
/// derived from that shard.
pub async fn keygen_party(
    ctx: &PartyContext,
    relay: impl Relay,
) -> Result<(KeyShare, Address), MpcError> {
    let setup = keygen_setup(ctx)?;
    let stats = Stats::alloc();
    let keyshare = keygen::run(setup, rand::random(), RelayStats::new(relay, stats.clone()))
        .await
        .map_err(|e| MpcError::Dkg(e.to_string()))?;
    log_bandwidth(ctx.party_id, &stats, "dkg");

    let address = address_from_keyshare(&keyshare)?; // library `Keyshare` -> Address
    let share = KeyShare::from(keyshare.as_slice().to_vec()); // library -> opaque bytes
    Ok((share, address))
}

/// This party's share of a signing round over `digest`, run by the `subset`
/// of global party ids (strictly ascending, length t). All validation happens
/// before the relay is touched, so a bad subset never opens an MPC session.
pub async fn sign_party(
    ctx: &PartyContext,
    share: &KeyShare, // opaque bytes from the store
    digest: B256,
    subset: &[u8],
    relay: impl Relay,
) -> Result<EcdsaParts, MpcError> {
    let n = ctx.party_vks.len();
    // Strictly ascending = canonical order AND duplicate rejection in one
    // check: every selected party must build the identical subset vector,
    // because the library verifies setup messages positionally.
    if !subset.windows(2).all(|w| w[0] < w[1]) || subset.iter().any(|&p| p as usize >= n) {
        return Err(MpcError::Sign(format!(
            "invalid signing subset {subset:?}: must be strictly ascending party ids < {n}"
        )));
    }
    // The library's sign setup is indexed by position IN THE SUBSET, not by
    // global party id — they only coincide when the subset is a prefix.
    let party_idx = subset
        .iter()
        .position(|&p| p == ctx.party_id)
        .ok_or_else(|| {
            MpcError::Sign(format!(
                "party {} is not in signing subset {subset:?}",
                ctx.party_id
            ))
        })?;

    let keyshare: Arc<Keyshare> = Keyshare::from_bytes(share.as_bytes()) // opaque -> library
        .map(Arc::new)
        .ok_or(MpcError::Deserialize)?; // from_bytes is Option

    // A shard from an older generation (different roster or threshold) would
    // otherwise stall the protocol with an opaque timeout — name the mismatch.
    if keyshare.party_id != ctx.party_id
        || keyshare.total_parties as usize != n
        || keyshare.threshold as usize != subset.len()
    {
        return Err(MpcError::Sign(format!(
            "keyshare/scheme mismatch: shard is party {} of a {}-of-{} scheme, \
             run is party {} with a {}-signer subset over n={n}",
            keyshare.party_id,
            keyshare.threshold,
            keyshare.total_parties,
            ctx.party_id,
            subset.len(),
        )));
    }

    let chain_path = DerivationPath::from_str("m")
        .map_err(|e| MpcError::Sign(format!("bad chain path: {e}")))?;

    let subset_vks: Vec<VerifyingKey> = subset.iter().map(|&p| ctx.party_vks[p as usize]).collect();
    let setup = SignSetup::new(
        InstanceId::new(ctx.instance.0),
        ctx.signing_key.clone(),
        party_idx,
        subset_vks,
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
    /// Startup recovery for the test backend: all stores empty → None; all
    /// holding the same address → Some; anything else is partial DKG state.
    /// Stricter than the orchestrator's n-way probe on purpose — every store
    /// is local here, so there is no "cold party" to tolerate.
    pub fn recover_active(&self) -> Result<Option<Address>, MpcError> {
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
}
