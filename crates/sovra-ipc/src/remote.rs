//! Orchestrator side of the control plane. [`RemoteBackend`] implements the
//! `MpcBackend` trait by POSTing each operation to a set of cosigners in
//! parallel with one shared random instance id, then cross-checking the
//! responses — every asked party must succeed *and agree* (`PartyMismatch`
//! otherwise), so a buggy or compromised cosigner can't return a divergent
//! result undetected. [`fetch_signer`] is the startup-recovery probe.
//!
//! t-of-n (M9): DKG goes to all n parties (after a `/roster` consistency
//! pre-flight); signing goes to a subset of t, selected once by liveness in
//! config preference order — the cold recovery party sits last, so it is only
//! drawn in when a preferred cosigner is down. Selection happens BEFORE any
//! `/sign` POST and is never revisited: failover keyed on outcome would let
//! this process route around a policy veto, failover keyed on liveness
//! cannot (a vetoing party is alive, gets selected, and its veto is final).
//!
//! Why reqwest/JSON: plain HTTP keeps the cosigner API curl-debuggable and
//! reuses the workspace HTTP stack; no streaming is needed on this plane.
//! `fetch_signer` takes the caller's `reqwest::Client` rather than the
//! backend's because recovery wants its own short probe timeout, not the
//! 90s operation timeout below.
//! Pattern: hexagonal port/adapter — the remote implementation of the
//! `MpcBackend` port (the test-only in-process one lives in
//! `sovra-mpc-dkls23-silence`).

use std::time::Duration;

use alloy_primitives::{B256, Bytes};
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError, Veto};
use sovra_types::{NetworkId, PubkeySec1};
use url::Url;

use crate::{
    control::{
        CORRELATION_HEADER, CORRELATION_ID, PublicKeyInfo, RosterInfo, SignaturesInfo,
        StartDkgRequest, StartRefreshRequest, StartSignRequest,
    },
    tls::TlsMaterials,
    types::IpcError,
};

/// Above the cosigner-side MPC timeout (60s TTL) so a live run is never cut
/// mid-flight; this only catches a cosigner that stops responding entirely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(90);

/// Per-request bound on the pre-sign readiness probes: a down party should
/// cost seconds, not the 90s operation timeout.
const READY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

pub struct RemoteBackend {
    /// Preference order, NOT id order: the first `threshold` ready parties
    /// sign. `(global party id, control-plane base url)`.
    cosigners: Vec<(u8, Url)>,
    threshold: usize,
    http: reqwest::Client,
}

impl MpcBackend for RemoteBackend {
    async fn dkg(&self) -> Result<PubkeySec1, MpcError> {
        // Pre-flight: a mismatched roster otherwise fails as an opaque MPC
        // timeout (wrong vks change MsgId routing) — catch it as config.
        self.preflight_roster().await?;
        let req = StartDkgRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            n_parties: self.cosigners.len() as u8,
            threshold: self.threshold as u8,
        };
        self.broadcast::<_, PublicKeyInfo>(&self.cosigners, "dkg", &req)
            .await
            .map(|i| i.public_key)
    }

    async fn sign(
        &self,
        network: NetworkId,
        unsigned_tx: &[u8],
    ) -> Result<Vec<EcdsaParts>, MpcError> {
        let signers = self.select_signers().await?;
        // Selection is by preference; the wire order is canonical (ascending)
        // so every party derives the identical subset vector.
        let mut participants: Vec<u8> = signers.iter().map(|(id, _)| *id).collect();
        participants.sort_unstable();
        tracing::info!(?participants, "signing subset selected");
        let req = StartSignRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            network,
            unsigned_transaction: Bytes::copy_from_slice(unsigned_tx),
            participants,
        };
        // `combine`'s equality cross-check covers the whole vector: parties
        // must agree on every digest's signature, in order.
        self.broadcast::<_, SignaturesInfo>(&signers, "sign", &req)
            .await
            .map(|i| i.signatures.into_iter().map(Into::into).collect())
    }

    async fn refresh(&self, lost_party: u8) -> Result<PubkeySec1, MpcError> {
        if !self.cosigners.iter().any(|(party, _)| *party == lost_party) {
            return Err(MpcError::Dkg(format!(
                "lost party {lost_party} is not in the cosigner set"
            )));
        }
        // Same pre-flight as DKG — here it additionally catches rosters not
        // yet updated with the replacement party's new identity.
        self.preflight_roster().await?;

        // The ceremony's anchor: every survivor must report the same wallet
        // public key, which the lost party will adopt as its reconstruction
        // target. Disagreement here means shard stores have diverged.
        let fetches = self
            .cosigners
            .iter()
            .filter(|(party, _)| *party != lost_party)
            .map(|(party, url)| async move {
                (
                    *party,
                    self.get_json::<PublicKeyInfo>(*party, url, "pubkey").await,
                )
            });
        let results = futures_util::future::join_all(fetches).await;
        let mut infos = Vec::with_capacity(results.len());
        for (party, result) in results {
            infos.push((party, result?));
        }
        let (first_party, first) = &infos[0];
        for (party, info) in &infos[1..] {
            if info != first {
                return Err(MpcError::PartyMismatch(format!(
                    "survivors disagree on the wallet public key: \
                     cosigner{first_party} vs cosigner{party}"
                )));
            }
        }

        let req = StartRefreshRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            n_parties: self.cosigners.len() as u8,
            threshold: self.threshold as u8,
            lost_party,
            public_key: first.public_key,
        };
        self.broadcast::<_, PublicKeyInfo>(&self.cosigners, "refresh", &req)
            .await
            .map(|i| i.public_key)
    }
}

impl RemoteBackend {
    /// The client pins the project CA and presents the orchestrator's leaf
    /// (mTLS on the control plane); a non-`https` cosigner URL, a duplicate
    /// party id, or an out-of-bounds threshold is refused here so
    /// misconfiguration fails at startup, not as a mid-operation error.
    pub fn new(
        cosigners: Vec<(u8, Url)>,
        threshold: usize,
        materials: &TlsMaterials,
    ) -> Result<Self, IpcError> {
        let mut seen = std::collections::HashSet::new();
        for (id, url) in &cosigners {
            if url.scheme() != "https" {
                return Err(crate::tls::TlsError::PlainScheme {
                    url: url.to_string(),
                    expected: "https",
                }
                .into());
            }
            if !seen.insert(id) {
                return Err(IpcError::Config(format!("duplicate party id {id}")));
            }
        }
        if !(2..=cosigners.len()).contains(&threshold) {
            return Err(IpcError::Config(format!(
                "threshold {threshold} out of bounds for {} cosigners",
                cosigners.len()
            )));
        }
        Ok(Self {
            cosigners,
            threshold,
            http: materials.http_client(HTTP_TIMEOUT)?,
        })
    }

    /// `GET /roster` on all n: every party must be reachable (DKG needs all
    /// of them) and report the same (n, threshold, roster_hash), which must
    /// also match this process's own config.
    async fn preflight_roster(&self) -> Result<(), MpcError> {
        let probes = self
            .cosigners
            .iter()
            .map(|(party, url)| self.get_json::<RosterInfo>(*party, url, "roster"));
        let results = futures_util::future::join_all(probes).await;

        let mut infos = Vec::with_capacity(results.len());
        for ((party, _), result) in self.cosigners.iter().zip(results) {
            let info = result.map_err(|e| match e {
                MpcError::Transport(msg) => MpcError::Transport(format!(
                    "{msg} — all {} parties must be online for this ceremony",
                    self.cosigners.len()
                )),
                other => other,
            })?;
            if info.n as usize != self.cosigners.len() || info.threshold as usize != self.threshold
            {
                return Err(MpcError::PartyMismatch(format!(
                    "cosigner{party} is configured {}-of-{}, orchestrator expects {}-of-{}",
                    info.threshold,
                    info.n,
                    self.threshold,
                    self.cosigners.len()
                )));
            }
            infos.push((*party, info));
        }
        let (first_party, first_info) = infos[0];
        for (party, info) in &infos[1..] {
            if *info != first_info {
                return Err(MpcError::PartyMismatch(format!(
                    "roster mismatch: cosigner{first_party} reports {first_info:?}, \
                     cosigner{party} reports {info:?} — the participant lists diverge"
                )));
            }
        }
        Ok(())
    }

    /// Probe `GET /signer` on all n concurrently and take the first
    /// `threshold` ready parties in config preference order. Readiness (alive
    /// AND provisioned) is the ONLY selection input — outcomes never are.
    async fn select_signers(&self) -> Result<Vec<(u8, Url)>, MpcError> {
        let probes = self.cosigners.iter().map(|(party, url)| async move {
            let ready = match url.join("signer") {
                Ok(u) => self
                    .http
                    .get(u)
                    .timeout(READY_PROBE_TIMEOUT)
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false),
                Err(_) => false,
            };
            (*party, url.clone(), ready)
        });
        let results = futures_util::future::join_all(probes).await;
        let ready: Vec<(u8, Url)> = results
            .into_iter()
            .filter(|(_, _, ready)| *ready)
            .map(|(party, url, _)| (party, url))
            .collect();
        if ready.len() < self.threshold {
            return Err(MpcError::Transport(format!(
                "only {} of {} cosigners ready; need {}",
                ready.len(),
                self.cosigners.len(),
                self.threshold
            )));
        }
        Ok(ready.into_iter().take(self.threshold).collect())
    }

    /// One authenticated GET with the standard per-party error framing —
    /// shared by the roster pre-flight and the pubkey fetch.
    async fn get_json<T: DeserializeOwned>(
        &self,
        party: u8,
        base: &Url,
        path: &str,
    ) -> Result<T, MpcError> {
        let url = base
            .join(path)
            .map_err(|e| MpcError::Transport(format!("cosigner{party} url: {e}")))?;
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Transport(format!(
                "cosigner{party} {path}: {status}: {text}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: bad response: {e}")))
    }

    /// POST the same request to every target; all must succeed and agree.
    async fn broadcast<Req, Resp>(
        &self,
        targets: &[(u8, Url)],
        path: &str,
        req: &Req,
    ) -> Result<Resp, MpcError>
    where
        Req: Serialize,
        Resp: DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let posts = targets.iter().map(|(party, url)| async move {
            (*party, self.post::<_, Resp>(*party, url, path, req).await)
        });
        combine(futures_util::future::join_all(posts).await)
    }

    async fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        party: u8,
        base: &Url,
        path: &str,
        body: &Req,
    ) -> Result<Resp, MpcError> {
        let url = base
            .join(path)
            .map_err(|e| MpcError::Transport(format!("cosigner{party} url: {e}")))?;
        let correlation_id = CORRELATION_ID
            .try_with(Clone::clone)
            .unwrap_or_else(|_| format!("{:032x}", rand::random::<u128>()));

        let resp = self
            .http
            .post(url)
            .header(CORRELATION_HEADER, correlation_id)
            .json(body)
            .send()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: {e}")))?;

        let status = resp.status();
        if status == StatusCode::FORBIDDEN {
            // A policy veto is a decision, not a transport failure: keep it
            // typed so the orchestrator can attribute the 403 to this party.
            let text = resp.text().await.unwrap_or_default();
            let reason = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["reason"].as_str().map(str::to_owned))
                .unwrap_or(text);
            return Err(MpcError::Rejected {
                vetoes: vec![Veto { party, reason }],
            });
        }
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(MpcError::Transport(format!(
                "cosigner{party} {path}: {status}: {text}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| MpcError::Transport(format!("cosigner{party} {path}: bad response: {e}")))
    }
}

/// Merge the per-party outcomes of one broadcast into a single result.
///
/// Any asked party alone blocks a signature, and when policies differ the
/// vetoing party answers 403 quickly while the allowing parties wait alone in
/// the hub until their ttl expires into a timeout/502 — so which error this
/// function surfaces decides whether a policy veto is visible or buried in
/// transport noise. Precedence: every veto collected and reported together
/// (sorted by party id) > any veto outranks any other error > first
/// transport/protocol error > all Ok, in which case every value must be
/// pairwise equal (`PartyMismatch` otherwise).
fn combine<Resp>(results: Vec<(u8, Result<Resp, MpcError>)>) -> Result<Resp, MpcError>
where
    Resp: PartialEq + std::fmt::Debug,
{
    let mut vetoes = Vec::new();
    let mut first_error = None;
    let mut oks = Vec::new();
    for (party, result) in results {
        match result {
            Ok(value) => oks.push((party, value)),
            // A Rejected may already carry several vetoes (nested combines
            // never happen today, but the type allows it) — extend, not push.
            Err(MpcError::Rejected { vetoes: v }) => vetoes.extend(v),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    if !vetoes.is_empty() {
        vetoes.sort_by_key(|v| v.party);
        return Err(MpcError::Rejected { vetoes });
    }
    if let Some(e) = first_error {
        return Err(e);
    }
    let mut oks = oks.into_iter();
    let (first_party, first_value) = oks.next().expect("broadcast targets are never empty");
    for (party, value) in oks {
        if value != first_value {
            return Err(MpcError::PartyMismatch(format!(
                "cosigner{first_party} returned {first_value:?}, \
                 cosigner{party} returned {value:?}"
            )));
        }
    }
    Ok(first_value)
}

/// Startup-recovery probe: 200 → active public key, 404 → no shard,
/// anything else → error.
pub async fn fetch_signer(
    http: &reqwest::Client,
    cosigner: &Url,
) -> Result<Option<PubkeySec1>, IpcError> {
    let url = cosigner
        .join("signer")
        .map_err(|e| IpcError::Http(format!("bad url: {e}")))?;
    let resp = http
        .get(url)
        .send()
        .await
        .map_err(|e| IpcError::Http(e.to_string()))?;
    match resp.status() {
        StatusCode::NOT_FOUND => Ok(None),
        s if s.is_success() => {
            let info: PublicKeyInfo = resp
                .json()
                .await
                .map_err(|e| IpcError::Http(e.to_string()))?;
            Ok(Some(info.public_key))
        }
        s => Err(IpcError::Http(format!("GET /signer returned {s}"))),
    }
}
