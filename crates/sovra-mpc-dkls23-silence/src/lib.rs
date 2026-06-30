//! Concrete `sl-dkls23` (Silence Laboratories) implementation of the
//! [`MpcBackend`] seam. Both 2-of-2 parties run in-process, exchanging messages
//! over the library's in-memory `SimpleMessageRelay`.
//!

use std::{str::FromStr, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256};
use derivation_path::DerivationPath;
use k256::ecdsa::VerifyingKey;
use sl_dkls23::{
    keygen::{self, Keyshare},
    setup::{
        NoSigningKey, NoVerifyingKey, keygen::SetupMessage as KeygenSetup,
        sign::SetupMessage as SignSetup,
    },
    sign,
};
use sl_mpc_mate::{coord::SimpleMessageRelay, message::InstanceId};
use sovra_mpc::{DkgResult, EcdsaParts, MpcBackend, MpcError, to_ecdsa_parts};
use sovra_types::KeyShare;
use tokio::task::JoinSet;

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
const TTL: Duration = Duration::from_secs(60);

/// 2-of-2 DKLs23 backend (Silence Laboratories `sl-dkls23`), in-process.
pub struct SilenceBackend;

impl MpcBackend for SilenceBackend {
    async fn dkg(&self) -> Result<DkgResult, MpcError> {
        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        // One shared instance id; auth disabled locally with No*Key
        let instance = rand::random();
        let ranks = [0u8; PARTIES];
        let vk: Vec<NoVerifyingKey> = (0..PARTIES).map(NoVerifyingKey::new).collect();

        for party_id in 0..PARTIES {
            let setup = KeygenSetup::new(
                InstanceId::new(instance),
                NoSigningKey,
                party_id,
                vk.clone(),
                &ranks,
                THRESHOLD,
            )
            .with_ttl(TTL);

            let relay = coord.connect();
            parties.spawn(keygen::run(setup, rand::random(), relay));
        }

        let mut keyshares = Vec::with_capacity(PARTIES);
        while let Some(joined) = parties.join_next().await {
            let share = joined
                .map_err(|e| MpcError::Dkg(e.to_string()))?
                .map_err(|e| MpcError::Dkg(e.to_string()))?;
            keyshares.push(share);
        }

        keyshares.sort_by_key(|k| k.party_id);

        let address = address_from_keyshare(&keyshares[0])?;
        let shares = keyshares
            .iter()
            .map(|k| KeyShare::from(k.as_slice().to_vec()))
            .collect();

        Ok(DkgResult { shares, address })
    }

    async fn sign(&self, signing_hash: B256, shares: &[KeyShare]) -> Result<EcdsaParts, MpcError> {
        // Rebuild library keyshares from the opaque shard bytes.
        let mut keyshares: Vec<Arc<Keyshare>> = shares
            .iter()
            .map(|s| {
                Keyshare::from_bytes(s.as_bytes())
                    .map(Arc::new)
                    .ok_or(MpcError::Deserialize)
            })
            .collect::<Result<_, _>>()?;
        keyshares.sort_by_key(|k| k.party_id);

        let chain_path = DerivationPath::from_str("m")
            .map_err(|e| MpcError::Sign(format!("bad chain path: {e}")))?;

        let coord = SimpleMessageRelay::new();
        let mut parties = JoinSet::new();

        let instance = rand::random();
        let vk: Vec<NoVerifyingKey> = keyshares
            .iter()
            .map(|k| NoVerifyingKey::new(k.party_id as usize))
            .collect();

        for (party_idx, share) in keyshares.iter().enumerate() {
            let setup = SignSetup::new(
                InstanceId::new(instance),
                NoSigningKey,
                party_idx,
                vk.clone(),
                share.clone(),
            )
            .with_chain_path(chain_path.clone())
            .with_hash(signing_hash.0)
            .with_ttl(TTL);

            let relay = coord.connect();
            parties.spawn(sign::run(setup, rand::random(), relay));
        }

        // Both parties output the same (Signature, RecoveryId); take either.
        let mut result = None;
        while let Some(joined) = parties.join_next().await {
            let (sig, recid) = joined
                .map_err(|e| MpcError::Sign(e.to_string()))?
                .map_err(|e| MpcError::Sign(format!("{e:?}")))?;
            result = Some((sig, recid));
        }

        let (sig, recid) = result.ok_or(MpcError::NoSignature)?;
        Ok(to_ecdsa_parts(&sig, recid))
    }
}

/// Ethereum address from a keyshare's shared public key. Reuses alloy's
/// keccak-based derivation — no hand-rolled hashing.
fn address_from_keyshare(keyshare: &Keyshare) -> Result<Address, MpcError> {
    let affine = keyshare.public_key().to_affine();
    let vk = VerifyingKey::from_affine(affine)
        .map_err(|e| MpcError::Dkg(format!("bad public key: {e}")))?;
    Ok(Address::from_public_key(&vk))
}
