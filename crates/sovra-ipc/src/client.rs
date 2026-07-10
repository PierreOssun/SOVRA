use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_util::{Sink, Stream};
use sl_mpc_mate::coord::{MessageSendError, Relay};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, tungstenite, tungstenite::Message};

use crate::types::IpcError;

pub struct WsRelay {
    inner: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WsRelay {
    pub async fn connect(url: &str) -> Result<Self, IpcError> {
        let (inner, _response) = tokio_tungstenite::connect_async(url).await?;
        Ok(Self { inner })
    }
}

fn to_send_error(e: tungstenite::Error) -> MessageSendError {
    tracing::warn!(error = %e, "ws relay send failed"); // last place the detail exists
    MessageSendError
}

impl Stream for WsRelay {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        loop {
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => return Poll::Ready(Some(b.into())),
                Some(Ok(_)) => continue, // text/ping/pong/close frame — not protocol data
                Some(Err(e)) => {
                    tracing::warn!(error = %e, "ws relay stream error"); // watch-point 3
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
