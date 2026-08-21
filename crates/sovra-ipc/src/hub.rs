//! Server side of the relay plane, hosted inside the sovra-api process
//! (bound before the API router, since cosigners dial in mid-operation).
//!
//! [`EnvelopeHub`] (`GET /env`) is a mailbox broker: a peer's first frame is
//! a [`Join`] claiming `(instance, party)`; thereafter the hub delivers that
//! mailbox and routes inbound envelope frames by their peeked
//! `(instance, to)` header. Mail sent before the recipient joins buffers in
//! the mailbox (parties start at different times); unclaimed mailboxes are
//! swept after a TTL. The hub verifies nothing — it has no roster; envelope
//! signatures and sealing are checked by recipients. A `Join` is unsigned by
//! design: a rogue project-CA peer claiming another party id is an
//! availability attack only, never a secrecy one.
//!
//! Pattern: message broker (server half of the [`crate::envelope_client`]
//! adapter pair).

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
    routing::get,
};
use sovra_mpc::SignedEnvelope;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// The relay plane's join frame: a peer's first (and only) non-envelope
/// frame, claiming one `(instance, party)` mailbox. Hand-encoded like the
/// envelope itself — one byte layout, spelled out where it is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Join {
    pub instance: B256,
    pub party_id: u8,
}

const JOIN_DOMAIN: &[u8; 13] = b"SOVRA-JOIN-V1";

impl Join {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(JOIN_DOMAIN.len() + 33);
        out.extend_from_slice(JOIN_DOMAIN);
        out.extend_from_slice(self.instance.as_slice());
        out.push(self.party_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let rest = bytes.strip_prefix(JOIN_DOMAIN)?;
        let (instance, rest) = rest.split_first_chunk::<32>()?;
        match rest {
            [party_id] => Some(Self {
                instance: B256::from(instance),
                party_id: *party_id,
            }),
            _ => None,
        }
    }
}

/// How long an unclaimed mailbox (mail buffered for a party that never
/// joined) survives. Comfortably above the ceremony TTL (60 s): a mailbox
/// this old belongs to a run that already failed.
const DEFAULT_UNCLAIMED_TTL: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct EnvelopeHub {
    mailboxes: Arc<Mutex<HashMap<(B256, u8), Mailbox>>>,
    unclaimed_ttl: Duration,
}

struct Mailbox {
    tx: UnboundedSender<Vec<u8>>,
    // Present until the party joins; buffered frames wait inside the channel
    // itself, so store-and-forward needs no separate queue.
    rx: Option<UnboundedReceiver<Vec<u8>>>,
    created: Instant,
}

impl Mailbox {
    fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self {
            tx,
            rx: Some(rx),
            created: Instant::now(),
        }
    }
}

impl Default for EnvelopeHub {
    fn default() -> Self {
        Self::new(DEFAULT_UNCLAIMED_TTL)
    }
}

impl EnvelopeHub {
    pub fn new(unclaimed_ttl: Duration) -> Self {
        Self {
            mailboxes: Arc::new(Mutex::new(HashMap::new())),
            unclaimed_ttl,
        }
    }

    /// Opportunistic GC (no background task): drop unclaimed mailboxes past
    /// the TTL. Claimed ones are removed by their serving socket's cleanup.
    fn sweep(&self, boxes: &mut HashMap<(B256, u8), Mailbox>) {
        boxes.retain(|_, m| m.rx.is_none() || m.created.elapsed() < self.unclaimed_ttl);
    }

    /// Claim `(instance, party)`'s receiver. `None` = already claimed — two
    /// sockets draining one mailbox would split a ceremony's mail, so the
    /// second claimer is refused.
    fn claim(&self, key: (B256, u8)) -> Option<UnboundedReceiver<Vec<u8>>> {
        let mut boxes = self.mailboxes.lock().expect("hub mutex poisoned");
        self.sweep(&mut boxes);
        boxes.entry(key).or_insert_with(Mailbox::new).rx.take()
    }

    fn deliver(&self, key: (B256, u8), frame: Vec<u8>) {
        let mut boxes = self.mailboxes.lock().expect("hub mutex poisoned");
        self.sweep(&mut boxes);
        // A send can only fail if the claimer's socket died mid-ceremony;
        // the run is doomed either way, so the frame is dropped with a log.
        if boxes
            .entry(key)
            .or_insert_with(Mailbox::new)
            .tx
            .send(frame)
            .is_err()
        {
            tracing::warn!(party = key.1, "dropping envelope for a disconnected party");
        }
    }

    fn remove(&self, key: (B256, u8)) {
        self.mailboxes
            .lock()
            .expect("hub mutex poisoned")
            .remove(&key);
    }
}

pub fn env_router(hub: EnvelopeHub) -> Router {
    Router::new()
        .route("/env", get(env_handler))
        .with_state(hub)
}

async fn env_handler(State(hub): State<EnvelopeHub>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| serve_env(hub, socket))
}

async fn serve_env(hub: EnvelopeHub, mut socket: WebSocket) {
    // First frame must be the Join claiming this peer's mailbox.
    let key = loop {
        match socket.recv().await {
            Some(Ok(Message::Binary(bytes))) => match Join::decode(&bytes) {
                Some(join) => break (join.instance, join.party_id),
                None => {
                    tracing::warn!("closing env socket: first frame was not a join");
                    return;
                }
            },
            Some(Ok(_)) => continue, // ping/pong/text
            _ => return,
        }
    };
    let Some(mut rx) = hub.claim(key) else {
        tracing::warn!(party = key.1, "closing env socket: mailbox already claimed");
        return;
    };

    loop {
        tokio::select! {
            frame = socket.recv() => {
                let Some(Ok(msg)) = frame else { break };
                let Message::Binary(bytes) = msg else { continue };
                match SignedEnvelope::peek_route(&bytes) {
                    Some((instance, to)) => hub.deliver((instance, to), bytes.into()),
                    None => tracing::warn!("dropping unroutable frame on env socket"),
                }
            }
            out = rx.recv() => {
                let Some(frame) = out else { break };
                if socket.send(Message::Binary(frame.into())).await.is_err() { break }
            }
        }
    }
    // This party's ceremony participation is over; its mailbox goes with it.
    hub.remove(key);
}
