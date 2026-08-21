//! In-process relay: [`MemoryHub`] hands out one [`MemoryRelay`] per party
//! and routes envelopes between them over unbounded mpsc channels. This is
//! what backend tests and the in-process backend run over — the in-memory
//! twin of the WebSocket hub in `sovra-ipc`, with the same semantics that
//! matter to a runner: unicast routing on `env.to`, store-and-forward (a
//! mailbox exists from the first send, so early senders don't race late
//! joiners), no verification (the hub is untrusted by design — recipients
//! authenticate). Pattern: message broker, test double.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::{MpcError, envelope::SignedEnvelope, runner::EnvelopeRelay};

#[derive(Clone, Default)]
pub struct MemoryHub {
    mailboxes: Arc<Mutex<HashMap<u8, Mailbox>>>,
}

struct Mailbox {
    tx: UnboundedSender<SignedEnvelope>,
    // Present until the party connects; buffered envelopes wait inside the
    // channel itself, so store-and-forward needs no separate queue.
    rx: Option<UnboundedReceiver<SignedEnvelope>>,
}

impl Mailbox {
    fn new() -> Self {
        let (tx, rx) = unbounded_channel();
        Self { tx, rx: Some(rx) }
    }
}

impl MemoryHub {
    pub fn new() -> Self {
        Self::default()
    }

    /// Claim `party_id`'s mailbox. Panics on a double connect — two relays
    /// draining one party's mail is always a test-harness bug, and a silent
    /// split would surface as an unrelated ceremony timeout.
    pub fn connect(&self, party_id: u8) -> MemoryRelay {
        let mut boxes = self.mailboxes.lock().expect("hub mutex poisoned");
        let rx = boxes
            .entry(party_id)
            .or_insert_with(Mailbox::new)
            .rx
            .take()
            .unwrap_or_else(|| panic!("party {party_id} connected twice"));
        MemoryRelay {
            hub: self.clone(),
            rx,
        }
    }
}

pub struct MemoryRelay {
    hub: MemoryHub,
    rx: UnboundedReceiver<SignedEnvelope>,
}

impl EnvelopeRelay for MemoryRelay {
    async fn send(&mut self, env: SignedEnvelope) -> Result<(), MpcError> {
        let mut boxes = self.hub.mailboxes.lock().expect("hub mutex poisoned");
        boxes
            .entry(env.env.to)
            .or_insert_with(Mailbox::new)
            .tx
            .send(env)
            .map_err(|_| MpcError::Transport("recipient's mailbox is closed".into()))
    }

    async fn recv(&mut self) -> Result<SignedEnvelope, MpcError> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| MpcError::Transport("relay hub dropped".into()))
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::envelope::{Envelope, op};

    fn signed(from: u8, to: u8, round: u8) -> SignedEnvelope {
        Envelope::broadcast(B256::repeat_byte(1), op::DKG, round, from, to, vec![round])
            .sign(&SigningKey::from_bytes(&[from; 32]))
    }

    #[tokio::test]
    async fn routes_by_recipient() {
        let hub = MemoryHub::new();
        let mut a = hub.connect(0);
        let mut b = hub.connect(1);
        a.send(signed(0, 1, 1)).await.unwrap();
        assert_eq!(b.recv().await.unwrap().env.from, 0);
    }

    #[tokio::test]
    async fn buffers_before_the_recipient_connects() {
        // The property the WS hub must also have: parties join at different
        // times, so mail sent early waits instead of vanishing.
        let hub = MemoryHub::new();
        let mut a = hub.connect(0);
        a.send(signed(0, 1, 1)).await.unwrap();
        a.send(signed(0, 1, 2)).await.unwrap();
        let mut b = hub.connect(1);
        assert_eq!(b.recv().await.unwrap().env.round, 1);
        assert_eq!(b.recv().await.unwrap().env.round, 2);
    }

    #[tokio::test]
    #[should_panic(expected = "connected twice")]
    async fn double_connect_panics() {
        let hub = MemoryHub::new();
        let _first = hub.connect(0);
        let _second = hub.connect(0);
    }
}
