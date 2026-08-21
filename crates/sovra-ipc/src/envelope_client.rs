//! Cosigner-side relay client: [`WsEnvelopeRelay`] adapts a client WebSocket
//! into the `sovra_mpc::EnvelopeRelay` a party runner drives. One connection
//! is dialed per ceremony and dropped when the run ends; connecting sends the
//! [`Join`] frame that claims this party's `(instance, party)` mailbox on the
//! hub.
//!
//! `EnvelopeRelay` is plain async send/recv, so no hand-written
//! `Stream`/`Sink` impls are needed (the sl-era relay trait forced them).
//! Byte/frame counters are logged on drop so every ceremony leaves a
//! bandwidth line.
//! Pattern: adapter (client half; server half in [`crate::hub`]).

use std::sync::Arc;

use alloy_primitives::B256;
use futures_util::{SinkExt, StreamExt};
use sovra_mpc::{EnvelopeRelay, MpcError, SignedEnvelope};
use tokio::net::TcpStream;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream, tungstenite::Message};

use crate::{hub::Join, types::IpcError};

pub struct WsEnvelopeRelay {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
    party_id: u8,
    sent: (u64, u64), // (frames, bytes)
    received: (u64, u64),
}

impl WsEnvelopeRelay {
    /// Dial the hub over mTLS and claim this party's mailbox. `tls` pins the
    /// project CA and presents this party's leaf — tungstenite's built-in
    /// webpki roots are never consulted. Callers pass `wss://` URLs
    /// (validated at startup); a `ws://` URL here would silently skip TLS.
    pub async fn connect(
        url: &str,
        tls: Arc<rustls::ClientConfig>,
        instance: B256,
        party_id: u8,
    ) -> Result<Self, IpcError> {
        let (mut inner, _response) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            Some(Connector::Rustls(tls)),
        )
        .await?;
        inner
            .send(Message::Binary(Join { instance, party_id }.encode().into()))
            .await?;
        Ok(Self {
            inner,
            party_id,
            sent: (0, 0),
            received: (0, 0),
        })
    }
}

impl EnvelopeRelay for WsEnvelopeRelay {
    async fn send(&mut self, env: SignedEnvelope) -> Result<(), MpcError> {
        let frame = env.encode();
        self.sent = (self.sent.0 + 1, self.sent.1 + frame.len() as u64);
        self.inner
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|e| MpcError::Transport(format!("relay send failed: {e}")))
    }

    async fn recv(&mut self) -> Result<SignedEnvelope, MpcError> {
        loop {
            match self.inner.next().await {
                Some(Ok(Message::Binary(bytes))) => {
                    self.received = (self.received.0 + 1, self.received.1 + bytes.len() as u64);
                    return SignedEnvelope::decode(&bytes);
                }
                Some(Ok(_)) => continue, // ping/pong/text
                Some(Err(e)) => {
                    return Err(MpcError::Transport(format!("relay stream error: {e}")));
                }
                None => return Err(MpcError::Transport("relay hub closed the socket".into())),
            }
        }
    }
}

impl Drop for WsEnvelopeRelay {
    fn drop(&mut self) {
        tracing::info!(
            party = self.party_id,
            send_kb = self.sent.1 as f64 / 1024.0,
            recv_kb = self.received.1 as f64 / 1024.0,
            send_count = self.sent.0,
            recv_count = self.received.0,
            "relay bandwidth",
        );
    }
}
