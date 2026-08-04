//! Orchestrator side of the control plane. [`RemoteBackend`] implements the
//! `MpcBackend` trait by POSTing each operation to **both** cosigners in
//! parallel with one shared random instance id, then cross-checking the two
//! responses — both parties must succeed *and agree* (`PartyMismatch`
//! otherwise), so a buggy or compromised cosigner can't return a divergent
//! result undetected. [`fetch_signer`] is the startup-recovery probe.
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

use alloy_primitives::{Address, B256, Bytes};
use reqwest::StatusCode;
use serde::{Serialize, de::DeserializeOwned};
use sovra_mpc::{EcdsaParts, MpcBackend, MpcError, Veto};
use url::Url;

use crate::{
    control::{
        CORRELATION_HEADER, CORRELATION_ID, SignParts, SignerInfo, StartDkgRequest,
        StartSignRequest,
    },
    tls::{TlsError, TlsMaterials},
    types::IpcError,
};

/// Above the cosigner-side MPC timeout (60s TTL) so a live run is never cut
/// mid-flight; this only catches a cosigner that stops responding entirely.
const HTTP_TIMEOUT: Duration = Duration::from_secs(90);

pub struct RemoteBackend {
    cosigners: [Url; 2],
    http: reqwest::Client,
}

impl MpcBackend for RemoteBackend {
    async fn dkg(&self) -> Result<Address, MpcError> {
        let req = StartDkgRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
        };
        self.broadcast::<_, SignerInfo>("dkg", &req)
            .await
            .map(|i| i.address)
    }

    async fn sign(&self, unsigned_tx: &[u8]) -> Result<EcdsaParts, MpcError> {
        let req = StartSignRequest {
            instance: B256::from(rand::random::<[u8; 32]>()),
            unsigned_transaction: Bytes::copy_from_slice(unsigned_tx),
        };
        self.broadcast::<_, SignParts>("sign", &req)
            .await
            .map(Into::into)
    }
}

impl RemoteBackend {
    /// The client pins the project CA and presents the orchestrator's leaf
    /// (mTLS on the control plane); a non-`https` cosigner URL is refused
    /// here so misconfiguration fails at startup, not as a handshake error.
    pub fn new(cosigner0: Url, cosigner1: Url, materials: &TlsMaterials) -> Result<Self, TlsError> {
        for url in [&cosigner0, &cosigner1] {
            if url.scheme() != "https" {
                return Err(TlsError::PlainScheme {
                    url: url.to_string(),
                    expected: "https",
                });
            }
        }
        Ok(Self {
            cosigners: [cosigner0, cosigner1],
            http: materials.http_client(HTTP_TIMEOUT)?,
        })
    }

    /// POST the same request to both cosigners; both must succeed and agree.
    async fn broadcast<Req, Resp>(&self, path: &str, req: &Req) -> Result<Resp, MpcError>
    where
        Req: Serialize,
        Resp: DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let (r0, r1) = tokio::join!(
            self.post::<_, Resp>(0, path, req),
            self.post::<_, Resp>(1, path, req)
        );
        let (a, b) = combine(r0, r1)?;
        if a != b {
            return Err(MpcError::PartyMismatch(format!("{path}: {a:?} != {b:?}")));
        }
        Ok(a)
    }

    async fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        party: usize,
        path: &str,
        body: &Req,
    ) -> Result<Resp, MpcError> {
        let url = self.cosigners[party]
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
                vetoes: vec![Veto {
                    party: party as u8,
                    reason,
                }],
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

/// Merge the two per-party outcomes of one broadcast into a single result.
///
/// In 2-of-2 either cosigner alone blocks a signature, and when policies
/// differ the vetoing party answers 403 quickly while the allowing party
/// waits alone in the hub until its ttl expires into a timeout/502 — so
/// which error this function surfaces decides whether a policy veto is
/// visible or buried in transport noise.
fn combine<Resp>(
    r0: Result<Resp, MpcError>,
    r1: Result<Resp, MpcError>,
) -> Result<(Resp, Resp), MpcError> {
    match (r0, r1) {
        (Ok(a), Ok(b)) => Ok((a, b)),
        // Both vetoed: one Rejected carrying every veto, party 0 first.
        // This arm must precede the single-Rejected arms to ever match.
        (Err(MpcError::Rejected { vetoes: mut v0 }), Err(MpcError::Rejected { vetoes: v1 })) => {
            v0.extend(v1);
            Err(MpcError::Rejected { vetoes: v0 })
        }
        // A veto outranks whatever happened to the other party — typically
        // the allowing cosigner's ttl timeout while it waited alone.
        (Err(e @ MpcError::Rejected { .. }), _) | (_, Err(e @ MpcError::Rejected { .. })) => Err(e),
        (Err(e), _) | (_, Err(e)) => Err(e),
    }
}

/// Startup-recovery probe: 200 → active address, 404 → no shard, anything else → error.
pub async fn fetch_signer(
    http: &reqwest::Client,
    cosigner: &Url,
) -> Result<Option<Address>, IpcError> {
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
            let info: SignerInfo = resp
                .json()
                .await
                .map_err(|e| IpcError::Http(e.to_string()))?;
            Ok(Some(info.address))
        }
        s => Err(IpcError::Http(format!("GET /signer returned {s}"))),
    }
}
