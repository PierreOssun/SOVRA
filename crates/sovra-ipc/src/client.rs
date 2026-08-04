//! Cosigner-side relay client: [`WsRelay`] adapts a client WebSocket into the
//! `sl_mpc_mate::coord::Relay` a party runner drives. One connection is dialed
//! per keygen/sign run and dropped when the run ends.
//!
//! Why hand-written `Stream`/`Sink` impls: `Relay` requires a single *named*
//! type that is both `Stream<Item = Vec<u8>>` and `Sink<Vec<u8>>`; combinator
//! chains can't produce that. `tokio-tungstenite` is used because reqwest has
//! no stable WebSocket client. `WebSocketStream` is `Unpin`, so plain
//! `Pin::new` delegation suffices — no pin-project needed.
//!
//! Error policy: `Relay`'s `Stream` has no error channel, so a transport
//! error logs a warning and ends the stream; the MPC run then fails or hits
//! its TTL. Non-binary frames (ping/pong/text) are protocol noise and are
//! skipped. Pattern: adapter (client half; server half in [`crate::hub`]).

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use futures_util::{Sink, Stream};
use sl_mpc_mate::coord::{MessageSendError, Relay};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, tungstenite, tungstenite::Message,
};

use crate::types::IpcError;

pub struct WsRelay {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WsRelay {
    /// Dial the hub over mTLS: `tls` pins the project CA and presents this
    /// party's leaf. The explicit connector is the whole point — tungstenite's
    /// built-in webpki roots are never consulted. Callers pass `wss://` URLs
    /// (validated at startup); a `ws://` URL here would silently skip TLS.
    pub async fn connect(url: &str, tls: Arc<rustls::ClientConfig>) -> Result<Self, IpcError> {
        let (inner, _response) = tokio_tungstenite::connect_async_tls_with_config(
            url,
            None,
            false,
            Some(Connector::Rustls(tls)),
        )
        .await?;
        Ok(Self { inner })
    }
}

fn to_send_error(e: tungstenite::Error) -> MessageSendError {
    tracing::warn!(error = %e, "ws relay send failed");
    MessageSendError
}

impl Stream for WsRelay {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        loop {
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => return Poll::Ready(Some(b.into())),
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "ws relay stream error");
                    return Poll::Ready(None);
                }
                None => return Poll::Ready(None),
            }
        }
    }
}

impl Sink<Vec<u8>> for WsRelay {
    type Error = MessageSendError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), MessageSendError>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(to_send_error)
    }
    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), MessageSendError> {
        Pin::new(&mut self.inner)
            .start_send(Message::Binary(item.into()))
            .map_err(to_send_error)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), MessageSendError>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(to_send_error)
    }
    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), MessageSendError>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(to_send_error)
    }
}

impl Relay for WsRelay {}
