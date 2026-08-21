//! [`Exchange`] — the shared round-driver every backend adapter uses to move
//! one ceremony's messages over an [`EnvelopeRelay`]. It owns the traffic
//! rules so adapters only map protocol phases to payload bytes: sealing p2p
//! payloads, fanning broadcasts out as unicasts, verifying every inbound
//! envelope against the pinned roster on arrival, deduplicating, buffering
//! messages that arrive for a *later* round (parties run rounds at slightly
//! different times), and bounding every round by the ceremony TTL.
//!
//! One Exchange = one (instance, op) ceremony for one party. The
//! communicating set is fixed per ceremony (full roster for DKG/refresh, the
//! subset for sign) — only which *kinds* flow varies by round, which is what
//! [`Expect`] names. Round state is per-call; only the ahead-of-round buffer
//! crosses calls.

use std::collections::BTreeMap;

use tokio::time::Instant;

use crate::{
    MpcError,
    envelope::{Envelope, SignedEnvelope},
    runner::{EnvelopeRelay, PartyContext},
};

/// What one party emits in one round: at most one protocol-public broadcast
/// (fanned out to every peer) and per-recipient secret payloads (sealed to
/// each). Backends concatenate a phase's structs into these blobs.
#[derive(Default)]
pub struct RoundOutbox {
    pub broadcast: Option<Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>, // recipient -> plaintext (sealed in transit)
}

/// What one party collected in one round, keyed by sender. Sealed payloads
/// arrive already opened.
#[derive(Default, Debug)]
pub struct RoundInbox {
    pub broadcasts: BTreeMap<u8, Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>,
}

/// Which message kinds this round expects from every peer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    Broadcasts,
    P2p,
    Both,
}

impl Expect {
    fn broadcasts(self) -> bool {
        self != Self::P2p
    }

    fn p2p(self) -> bool {
        self != Self::Broadcasts
    }
}

pub struct Exchange<'a, R: EnvelopeRelay> {
    relay: &'a mut R,
    ctx: &'a PartyContext,
    op: u8,
    /// The ceremony's participants minus this party — the only parties mail
    /// is sent to or accepted from.
    peers: Vec<u8>,
    /// Verified envelopes that arrived for a later round of this ceremony,
    /// drained when their round starts.
    ahead: Vec<SignedEnvelope>,
}

impl<'a, R: EnvelopeRelay> Exchange<'a, R> {
    /// `participants`: the ceremony's member set (this party included) —
    /// the full roster for DKG/refresh, the signing subset for sign.
    pub fn new(relay: &'a mut R, ctx: &'a PartyContext, op: u8, participants: &[u8]) -> Self {
        let peers = participants
            .iter()
            .copied()
            .filter(|&p| p != ctx.party_id)
            .collect();
        Self {
            relay,
            ctx,
            op,
            peers,
            ahead: Vec::new(),
        }
    }

    /// Send this round's outbox: the broadcast fans out to every peer (a
    /// party's own broadcast never crosses the relay — the backend keeps it),
    /// p2p payloads are sealed to their recipients.
    pub async fn send_round(&mut self, round: u8, outbox: RoundOutbox) -> Result<(), MpcError> {
        if let Some(payload) = outbox.broadcast {
            for &to in &self.peers {
                let env = Envelope::broadcast(
                    self.ctx.instance,
                    self.op,
                    round,
                    self.ctx.party_id,
                    to,
                    payload.clone(),
                );
                self.relay.send(env.sign(&self.ctx.signing_key)).await?;
            }
        }
        for (to, plaintext) in outbox.p2p {
            if !self.peers.contains(&to) {
                return Err(MpcError::EnvelopeAuth(format!(
                    "p2p recipient {to} is not a ceremony peer"
                )));
            }
            let vk = &self.ctx.party_vks[to as usize]; // peers ⊆ roster by construction
            let env = Envelope::sealed(
                self.ctx.instance,
                self.op,
                round,
                self.ctx.party_id,
                to,
                vk,
                &plaintext,
            )?;
            self.relay.send(env.sign(&self.ctx.signing_key)).await?;
        }
        Ok(())
    }

    /// Collect this round until every peer delivered every expected kind, or
    /// the ceremony TTL elapses. First message of a (sender, kind) wins;
    /// duplicates are dropped with a warning.
    pub async fn recv_round(&mut self, round: u8, expect: Expect) -> Result<RoundInbox, MpcError> {
        let deadline = Instant::now() + self.ctx.ttl;
        let mut inbox = RoundInbox::default();

        for env in std::mem::take(&mut self.ahead) {
            self.admit(round, env, &mut inbox, expect)?;
        }
        while !self.complete(&inbox, expect) {
            let env = tokio::time::timeout_at(deadline, self.relay.recv())
                .await
                .map_err(|_| {
                    MpcError::Transport(format!(
                        "op {} round {round}: timed out with broadcasts from {:?}, p2p from {:?}, expecting {expect:?} from all of {:?}",
                        self.op,
                        inbox.broadcasts.keys().collect::<Vec<_>>(),
                        inbox.p2p.keys().collect::<Vec<_>>(),
                        self.peers,
                    ))
                })??;
            self.admit(round, env, &mut inbox, expect)?;
        }
        Ok(inbox)
    }

    /// Route one inbound envelope: drop foreign traffic, authenticate,
    /// buffer ahead-of-round, file current-round. (Drained buffer entries
    /// re-run the cheap verification; ahead-of-round mail is rare.)
    fn admit(
        &mut self,
        round: u8,
        senv: SignedEnvelope,
        inbox: &mut RoundInbox,
        expect: Expect,
    ) -> Result<(), MpcError> {
        let env = &senv.env;
        if env.instance != self.ctx.instance
            || env.op != self.op
            || env.to != self.ctx.party_id
            || !self.peers.contains(&env.from)
        {
            tracing::warn!(
                from = env.from,
                op = env.op,
                "dropping envelope from outside this ceremony"
            );
            return Ok(());
        }
        if let Err(err) = senv.verify(&self.ctx.party_vks) {
            // Fail-closed: this envelope already matched our instance, op,
            // recipient, and a ceremony peer — a bad signature here is roster
            // drift or an active forgery, never routine noise. Abort now with
            // the claimed party named, instead of burning the TTL and
            // disguising the event as a timeout. Ceremonies are retryable;
            // an unnoticed forgery attempt is not.
            tracing::error!(claimed_from = env.from, round = env.round, %err, "aborting ceremony: envelope failed roster authentication");
            return Err(err);
        }
        match env.round.cmp(&round) {
            std::cmp::Ordering::Greater => {
                self.ahead.push(senv);
                Ok(())
            }
            std::cmp::Ordering::Less => {
                tracing::warn!(
                    from = env.from,
                    round = env.round,
                    "dropping late-round envelope"
                );
                Ok(())
            }
            std::cmp::Ordering::Equal => self.file(senv, inbox, expect),
        }
    }

    /// File a verified current-round envelope into the inbox.
    fn file(
        &self,
        senv: SignedEnvelope,
        inbox: &mut RoundInbox,
        expect: Expect,
    ) -> Result<(), MpcError> {
        let (wanted, kind) = if senv.env.sealed {
            (expect.p2p(), "p2p")
        } else {
            (expect.broadcasts(), "broadcast")
        };
        if !wanted {
            tracing::warn!(
                from = senv.env.from,
                kind,
                "dropping envelope of unexpected kind"
            );
            return Ok(());
        }
        let slot = if senv.env.sealed {
            &mut inbox.p2p
        } else {
            &mut inbox.broadcasts
        };
        if slot.contains_key(&senv.env.from) {
            tracing::warn!(
                from = senv.env.from,
                kind,
                "dropping duplicate envelope (first wins)"
            );
            return Ok(());
        }
        let payload = if senv.env.sealed {
            senv.env.open(&self.ctx.signing_key)?
        } else {
            senv.env.payload
        };
        slot.insert(senv.env.from, payload);
        Ok(())
    }

    fn complete(&self, inbox: &RoundInbox, expect: Expect) -> bool {
        (!expect.broadcasts() || self.peers.iter().all(|p| inbox.broadcasts.contains_key(p)))
            && (!expect.p2p() || self.peers.iter().all(|p| inbox.p2p.contains_key(p)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_primitives::B256;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{MemoryHub, envelope::op};

    fn contexts(n: u8, ttl_ms: u64) -> Vec<PartyContext> {
        let keys: Vec<SigningKey> = (0..n)
            .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
            .collect();
        let vks = keys.iter().map(|k| k.verifying_key()).collect::<Vec<_>>();
        keys.into_iter()
            .enumerate()
            .map(|(i, signing_key)| PartyContext {
                party_id: i as u8,
                instance: B256::repeat_byte(0xAA),
                signing_key,
                party_vks: vks.clone(),
                threshold: 2,
                ttl: Duration::from_millis(ttl_ms),
            })
            .collect()
    }

    fn broadcast_only(payload: &[u8]) -> RoundOutbox {
        RoundOutbox {
            broadcast: Some(payload.to_vec()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn three_party_round_delivers_broadcasts_and_sealed_p2p() {
        let hub = MemoryHub::new();
        let all = [0, 1, 2];
        let mut tasks = Vec::new();
        for ctx in contexts(3, 2_000) {
            let mut relay = hub.connect(ctx.party_id);
            tasks.push(tokio::spawn(async move {
                let me = ctx.party_id;
                let mut ex = Exchange::new(&mut relay, &ctx, op::DKG, &all);
                let outbox = RoundOutbox {
                    broadcast: Some(vec![b'B', me]),
                    p2p: all
                        .iter()
                        .filter(|&&p| p != me)
                        .map(|&p| (p, vec![b'S', me, p]))
                        .collect(),
                };
                ex.send_round(1, outbox).await.unwrap();
                ex.recv_round(1, Expect::Both).await.unwrap()
            }));
        }
        for (me, task) in tasks.into_iter().enumerate() {
            let inbox = task.await.unwrap();
            for p in all.iter().copied().filter(|&p| p != me as u8) {
                assert_eq!(inbox.broadcasts[&p], vec![b'B', p]);
                assert_eq!(
                    inbox.p2p[&p],
                    vec![b'S', p, me as u8],
                    "sealed payload opened per-recipient"
                );
            }
        }
    }

    #[tokio::test]
    async fn ahead_of_round_traffic_is_buffered_not_lost() {
        let hub = MemoryHub::new();
        let ctxs = contexts(2, 2_000);
        let (mut r0, mut r1) = (hub.connect(0), hub.connect(1));

        // Party 0 races ahead: its round-2 broadcast lands before party 1
        // has finished round 1.
        let mut ex0 = Exchange::new(&mut r0, &ctxs[0], op::SIGN, &[0, 1]);
        ex0.send_round(2, broadcast_only(b"r2")).await.unwrap();
        ex0.send_round(1, broadcast_only(b"r1")).await.unwrap();

        let mut ex1 = Exchange::new(&mut r1, &ctxs[1], op::SIGN, &[0, 1]);
        assert_eq!(
            ex1.recv_round(1, Expect::Broadcasts)
                .await
                .unwrap()
                .broadcasts[&0],
            b"r1"
        );
        // Round 2 completes purely from the buffer — nothing further on the wire.
        assert_eq!(
            ex1.recv_round(2, Expect::Broadcasts)
                .await
                .unwrap()
                .broadcasts[&0],
            b"r2"
        );
    }

    #[tokio::test]
    async fn duplicates_are_dropped_first_wins() {
        let hub = MemoryHub::new();
        let ctxs = contexts(2, 2_000);
        let (mut r0, mut r1) = (hub.connect(0), hub.connect(1));

        let mut ex0 = Exchange::new(&mut r0, &ctxs[0], op::DKG, &[0, 1]);
        ex0.send_round(1, broadcast_only(b"first")).await.unwrap();
        ex0.send_round(1, broadcast_only(b"second")).await.unwrap();

        let mut ex1 = Exchange::new(&mut r1, &ctxs[1], op::DKG, &[0, 1]);
        assert_eq!(
            ex1.recv_round(1, Expect::Broadcasts)
                .await
                .unwrap()
                .broadcasts[&0],
            b"first"
        );
    }

    #[tokio::test]
    async fn non_participants_are_ignored() {
        // Party 2 is in the roster but not in this ceremony's subset: its
        // (validly signed) traffic must not satisfy the round.
        let hub = MemoryHub::new();
        let ctxs = contexts(3, 100);
        let (mut r1, mut r2) = (hub.connect(1), hub.connect(2));

        let mut ex2 = Exchange::new(&mut r2, &ctxs[2], op::SIGN, &[0, 1, 2]);
        ex2.send_round(1, broadcast_only(b"intruder"))
            .await
            .unwrap();

        let mut ex1 = Exchange::new(&mut r1, &ctxs[1], op::SIGN, &[0, 1]);
        let err = ex1.recv_round(1, Expect::Broadcasts).await.unwrap_err();
        assert!(matches!(err, MpcError::Transport(msg) if msg.contains("timed out")));
    }

    #[tokio::test]
    async fn forged_envelope_aborts_the_ceremony_immediately() {
        // Fail-closed policy: an envelope claiming a ceremony peer but signed
        // by the wrong key must surface as an auth error at once — with a
        // 60s-scale TTL this must never be a timeout. Also the envelope-layer
        // half of wrong_peer_vk_breaks_keygen: same wire, mispinned roster.
        let hub = MemoryHub::new();
        let ctxs = contexts(2, 60_000);
        let (mut r0, mut r1) = (hub.connect(0), hub.connect(1));

        let forged = Envelope::broadcast(ctxs[0].instance, op::DKG, 1, 0, 1, b"evil".to_vec())
            .sign(&SigningKey::from_bytes(&[0xEE; 32])); // not party 0's key
        r0.send(forged).await.unwrap();

        let started = std::time::Instant::now();
        let mut ex1 = Exchange::new(&mut r1, &ctxs[1], op::DKG, &[0, 1]);
        let err = ex1.recv_round(1, Expect::Broadcasts).await.unwrap_err();
        assert!(matches!(err, MpcError::EnvelopeAuth(_)), "got: {err}");
        assert!(
            started.elapsed().as_secs() < 5,
            "must abort, not wait for the TTL"
        );
    }

    #[tokio::test]
    async fn missing_sender_times_out_with_a_named_gap() {
        let hub = MemoryHub::new();
        let ctxs = contexts(2, 100);
        let mut r1 = hub.connect(1);
        let mut ex1 = Exchange::new(&mut r1, &ctxs[1], op::DKG, &[0, 1]);
        let err = ex1.recv_round(1, Expect::Broadcasts).await.unwrap_err();
        assert!(matches!(err, MpcError::Transport(msg) if msg.contains("timed out")));
    }
}
