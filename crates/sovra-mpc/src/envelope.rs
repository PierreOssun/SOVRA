//! Sovra-owned relay envelope: the frame every MPC round message travels in
//! once the backend no longer brings its own transport security (sl-dkls23
//! signed and encrypted round messages internally; 0xCarbon hands the caller
//! raw bytes — including secret Shamir fragments and OT payloads).
//!
//! Authenticity: every envelope is ed25519-signed by the sender's party
//! identity and verified by the *recipient* against its pinned roster. The
//! hub verifies nothing — it has no roster and stays a dumb broker, keeping
//! the existing "trust lives in the protocol, not the broker" stance.
//! Confidentiality: p2p payloads are sealed to the recipient with an
//! ephemeral-x25519 + XChaCha20-Poly1305 box derived from the same ed25519
//! identities (no extra key material to provision), with the envelope header
//! as AAD so a ciphertext cannot be replayed under different routing
//! metadata. Broadcast payloads are protocol-public and stay plaintext.
//! A broadcast is sender-side fan-out: one signed envelope per recipient,
//! so the hub only ever routes unicast.
//!
//! The wire encoding is hand-written, not a serde format: a signed frame
//! should have exactly one byte layout, spelled out where it is verified.

use alloy_primitives::B256;
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::MpcError;

/// Protocol-operation discriminants for [`Envelope::op`]: domain separation so
/// a round-r message of one ceremony type can never satisfy another's.
pub mod op {
    pub const DKG: u8 = 0;
    pub const SIGN: u8 = 1;
    pub const REFRESH: u8 = 2;
}

/// Version prefix of every signature preimage, seal AAD, and wire frame;
/// bump on any layout change so nothing old validates the new layout.
const DOMAIN: &[u8; 12] = b"SOVRA-ENV-V1";
/// KDF domain for the sealed-box key, separate from the signature domain.
const SEAL_DOMAIN: &[u8; 13] = b"SOVRA-SEAL-V1";
const HEADER_LEN: usize = DOMAIN.len() + 32 + 5;
const NONCE_LEN: usize = 24;
const EPH_PK_LEN: usize = 32;
const SIG_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub instance: B256, // ceremony instance (already sub_instance-derived per digest)
    pub op: u8,         // see [`op`]
    pub round: u8,      // protocol round within `op`
    pub from: u8,       // global 0-based party id — index into the pinned roster
    pub to: u8,         // global 0-based recipient id
    pub payload: Vec<u8>,
    pub sealed: bool, // true ⇒ payload = eph_x25519_pk(32) ‖ xnonce(24) ‖ ciphertext
}

/// An [`Envelope`] plus its sender's ed25519 signature — the only thing that
/// ever crosses a relay. Canonical wire encoding is [`Self::encode`].
#[derive(Clone, Debug)]
pub struct SignedEnvelope {
    pub env: Envelope,
    pub sig: Signature,
}

impl Envelope {
    /// A plaintext (broadcast-kind) envelope. Callers fan one out per peer.
    pub fn broadcast(
        instance: B256,
        op: u8,
        round: u8,
        from: u8,
        to: u8,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            instance,
            op,
            round,
            from,
            to,
            payload,
            sealed: false,
        }
    }

    /// A p2p envelope whose payload only `recipient_vk`'s holder can open.
    pub fn sealed(
        instance: B256,
        op: u8,
        round: u8,
        from: u8,
        to: u8,
        recipient_vk: &VerifyingKey,
        plaintext: &[u8],
    ) -> Result<Self, MpcError> {
        let mut env = Self {
            instance,
            op,
            round,
            from,
            to,
            payload: Vec::new(),
            sealed: true,
        };

        let eph = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pk = x25519_dalek::PublicKey::from(&eph);
        let recipient_pk = x25519_public_of(recipient_vk);
        let shared = eph.diffie_hellman(&recipient_pk);
        // The roster is operator-pinned, but a torsion-point vk would yield a
        // predictable shared secret — refuse rather than seal to it.
        if !shared.was_contributory() {
            return Err(MpcError::EnvelopeAuth(format!(
                "party {to}'s pinned key maps to a non-contributory x25519 point"
            )));
        }
        let cipher =
            XChaCha20Poly1305::new(&box_key(shared.as_bytes(), &eph_pk, &recipient_pk).into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &env.header_bytes(),
                },
            )
            .map_err(|_| MpcError::EnvelopeAuth("sealing failed".into()))?;

        env.payload = Vec::with_capacity(EPH_PK_LEN + NONCE_LEN + ciphertext.len());
        env.payload.extend_from_slice(eph_pk.as_bytes());
        env.payload.extend_from_slice(&nonce);
        env.payload.extend_from_slice(&ciphertext);
        Ok(env)
    }

    /// Unseal a p2p payload with the recipient's ed25519 identity key.
    /// Fails on a plaintext envelope, truncation, or any tampering with the
    /// ciphertext *or* the header (it is the AAD).
    pub fn open(&self, sk: &SigningKey) -> Result<Vec<u8>, MpcError> {
        if !self.sealed {
            return Err(MpcError::EnvelopeAuth(
                "open() on a plaintext envelope".into(),
            ));
        }
        if self.payload.len() < EPH_PK_LEN + NONCE_LEN {
            return Err(MpcError::EnvelopeAuth("sealed payload truncated".into()));
        }
        let (eph_pk_bytes, rest) = self.payload.split_at(EPH_PK_LEN);
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let eph_pk = x25519_dalek::PublicKey::from(
            <[u8; 32]>::try_from(eph_pk_bytes).expect("split_at yields EPH_PK_LEN bytes"),
        );
        let secret = x25519_secret_of(sk);
        let my_pk = x25519_dalek::PublicKey::from(&secret);
        let shared = secret.diffie_hellman(&eph_pk);
        if !shared.was_contributory() {
            return Err(MpcError::EnvelopeAuth(
                "non-contributory ephemeral key".into(),
            ));
        }
        let cipher = XChaCha20Poly1305::new(&box_key(shared.as_bytes(), &eph_pk, &my_pk).into());
        let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("split_at yields NONCE_LEN bytes");
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.header_bytes(),
                },
            )
            .map_err(|_| {
                MpcError::EnvelopeAuth("unsealing failed — tampered or misaddressed".into())
            })
    }

    pub fn sign(self, sk: &SigningKey) -> SignedEnvelope {
        let sig = sk.sign(&self.signing_preimage());
        SignedEnvelope { env: self, sig }
    }

    /// Fixed-size routing header; doubles as the seal AAD and the wire prefix.
    fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..DOMAIN.len()].copy_from_slice(DOMAIN);
        out[DOMAIN.len()..DOMAIN.len() + 32].copy_from_slice(self.instance.as_slice());
        out[HEADER_LEN - 5..].copy_from_slice(&[
            self.op,
            self.round,
            self.from,
            self.to,
            self.sealed as u8,
        ]);
        out
    }

    /// Header ‖ SHA-512(payload): hashing keeps the preimage fixed-size even
    /// for the multi-hundred-KB OT rounds, while still binding every byte.
    fn signing_preimage(&self) -> [u8; HEADER_LEN + 64] {
        let mut out = [0u8; HEADER_LEN + 64];
        out[..HEADER_LEN].copy_from_slice(&self.header_bytes());
        out[HEADER_LEN..].copy_from_slice(&Sha512::digest(&self.payload));
        out
    }
}

impl SignedEnvelope {
    /// Verify against the pinned roster (positional by party id). Rejects an
    /// out-of-roster `from` and any forged or tampered field — `verify_strict`
    /// so malleable/small-order signatures are refused too.
    pub fn verify(&self, roster: &[VerifyingKey]) -> Result<(), MpcError> {
        let vk = roster.get(self.env.from as usize).ok_or_else(|| {
            MpcError::EnvelopeAuth(format!(
                "sender {} is not in the {}-party roster",
                self.env.from,
                roster.len()
            ))
        })?;
        vk.verify_strict(&self.env.signing_preimage(), &self.sig)
            .map_err(|_| {
                MpcError::EnvelopeAuth(format!(
                    "bad signature on envelope claiming party {}",
                    self.env.from
                ))
            })
    }

    /// Canonical wire frame: `header(49) ‖ u32-be payload len ‖ payload ‖
    /// sig(64)`. The header's leading domain doubles as the frame magic.
    pub fn encode(&self) -> Vec<u8> {
        let payload = &self.env.payload;
        let mut out = Vec::with_capacity(HEADER_LEN + 4 + payload.len() + SIG_LEN);
        out.extend_from_slice(&self.env.header_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out.extend_from_slice(&self.sig.to_bytes());
        out
    }

    /// Routing peek for hubs: `(instance, to)` straight from a wire frame,
    /// without the full decode's payload copy and without any trust — hubs
    /// route on this, recipients still verify everything. `None` means "not
    /// an envelope frame" (hubs drop it).
    pub fn peek_route(bytes: &[u8]) -> Option<(B256, u8)> {
        let header = bytes.get(..HEADER_LEN)?;
        let (domain, fields) = header.split_at(DOMAIN.len());
        if domain != DOMAIN {
            return None;
        }
        Some((B256::from_slice(&fields[..32]), fields[35]))
    }

    /// Strict inverse of [`Self::encode`]: exact length, known domain, and a
    /// canonical (0/1) sealed flag — anything else is rejected, never coerced.
    pub fn decode(bytes: &[u8]) -> Result<Self, MpcError> {
        let malformed = |what: &str| MpcError::Transport(format!("undecodable envelope: {what}"));
        if bytes.len() < HEADER_LEN + 4 + SIG_LEN {
            return Err(malformed("truncated"));
        }
        let (header, rest) = bytes.split_at(HEADER_LEN);
        let (domain, fields) = header.split_at(DOMAIN.len());
        if domain != DOMAIN {
            return Err(malformed("unknown domain/version"));
        }
        let sealed = match fields[36] {
            0 => false,
            1 => true,
            _ => return Err(malformed("non-canonical sealed flag")),
        };
        let (len_bytes, rest) = rest.split_at(4);
        let payload_len =
            u32::from_be_bytes(len_bytes.try_into().expect("split_at yields 4 bytes")) as usize;
        if rest.len() != payload_len + SIG_LEN {
            return Err(malformed("length mismatch"));
        }
        let (payload, sig) = rest.split_at(payload_len);
        Ok(Self {
            env: Envelope {
                instance: B256::from_slice(&fields[..32]),
                op: fields[32],
                round: fields[33],
                from: fields[34],
                to: fields[35],
                payload: payload.to_vec(),
                sealed,
            },
            sig: Signature::from_bytes(sig.try_into().expect("split_at yields SIG_LEN bytes")),
        })
    }
}

/// The standard ed25519→x25519 birational map, applied to both key halves so
/// parties can seal to each other with no key material beyond `identity.key`.
fn x25519_public_of(vk: &VerifyingKey) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(vk.to_montgomery().to_bytes())
}

fn x25519_secret_of(sk: &SigningKey) -> x25519_dalek::StaticSecret {
    // to_scalar_bytes() is the clamped secret scalar; StaticSecret re-clamps,
    // which is idempotent — the derived public key equals to_montgomery().
    x25519_dalek::StaticSecret::from(sk.to_scalar_bytes())
}

/// Sealed-box key: hash the ECDH output together with both public keys so the
/// key binds the exact pair of participants (textbook DH-to-AEAD hygiene).
fn box_key(
    shared: &[u8; 32],
    eph_pk: &x25519_dalek::PublicKey,
    recipient_pk: &x25519_dalek::PublicKey,
) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(SEAL_DOMAIN);
    h.update(shared);
    h.update(eph_pk.as_bytes());
    h.update(recipient_pk.as_bytes());
    h.finalize()[..32]
        .try_into()
        .expect("SHA-512 yields 64 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn plain(from: u8, to: u8) -> Envelope {
        Envelope::broadcast(
            B256::repeat_byte(7),
            op::DKG,
            1,
            from,
            to,
            b"round-1".to_vec(),
        )
    }

    #[test]
    fn ed25519_to_x25519_halves_agree() {
        // The linchpin of sealing: secret-side and public-side conversions
        // must land on the same x25519 public key.
        let sk = key(9);
        let via_secret = x25519_dalek::PublicKey::from(&x25519_secret_of(&sk));
        assert_eq!(
            via_secret.as_bytes(),
            x25519_public_of(&sk.verifying_key()).as_bytes()
        );
    }

    #[test]
    fn sign_verify_roundtrip_and_wire_encoding() {
        let sk = key(0);
        let roster = vec![sk.verifying_key(), key(1).verifying_key()];
        let signed = plain(0, 1).sign(&sk);
        signed.verify(&roster).expect("genuine envelope verifies");
        let decoded = SignedEnvelope::decode(&signed.encode()).expect("wire roundtrip");
        decoded
            .verify(&roster)
            .expect("decoded envelope still verifies");
        assert_eq!(decoded.env, signed.env);
    }

    #[test]
    fn peek_route_matches_the_full_decode() {
        let wire = plain(0, 1).sign(&key(0)).encode();
        let (instance, to) = SignedEnvelope::peek_route(&wire).expect("routable");
        assert_eq!(instance, B256::repeat_byte(7));
        assert_eq!(to, 1);
        assert!(
            SignedEnvelope::peek_route(&wire[..10]).is_none(),
            "truncated"
        );
        assert!(
            SignedEnvelope::peek_route(b"SOVRA-JOIN-V1 not an envelope frame padding").is_none()
        );
    }

    #[test]
    fn decode_rejects_malformed_frames() {
        let wire = plain(0, 1).sign(&key(0)).encode();
        assert!(
            SignedEnvelope::decode(&wire[..HEADER_LEN]).is_err(),
            "truncated"
        );
        assert!(
            SignedEnvelope::decode(&wire[..wire.len() - 1]).is_err(),
            "length mismatch"
        );
        let mut wrong_domain = wire.clone();
        wrong_domain[0] ^= 1;
        assert!(
            SignedEnvelope::decode(&wrong_domain).is_err(),
            "unknown domain"
        );
        let mut bad_flag = wire.clone();
        bad_flag[HEADER_LEN - 1] = 2;
        assert!(
            SignedEnvelope::decode(&bad_flag).is_err(),
            "non-canonical sealed flag"
        );
    }

    #[test]
    fn any_tampered_field_breaks_verification() {
        let sk = key(0);
        let roster = vec![sk.verifying_key(), key(1).verifying_key()];
        let signed = plain(0, 1).sign(&sk);
        let tampers: [fn(&mut Envelope); 6] = [
            |e| e.instance = B256::repeat_byte(8),
            |e| e.op = op::SIGN,
            |e| e.round = 2,
            |e| e.to = 0,
            |e| e.sealed = true,
            |e| e.payload.push(0),
        ];
        for tamper in tampers {
            let mut forged = signed.clone();
            tamper(&mut forged.env);
            assert!(
                forged.verify(&roster).is_err(),
                "tamper went unnoticed: {:?}",
                forged.env
            );
        }
        // `from` tamper: points the lookup at a different pinned key.
        let mut forged = signed.clone();
        forged.env.from = 1;
        assert!(forged.verify(&roster).is_err());
    }

    #[test]
    fn wrong_pinned_roster_key_is_rejected() {
        // The envelope-layer version of wrong_peer_vk_breaks_keygen: a roster
        // that pins the wrong key for the sender fails fast with an auth error.
        let sk = key(0);
        let wrong_roster = vec![key(2).verifying_key(), key(1).verifying_key()];
        let err = plain(0, 1).sign(&sk).verify(&wrong_roster).unwrap_err();
        assert!(matches!(err, MpcError::EnvelopeAuth(_)));
    }

    #[test]
    fn out_of_roster_sender_is_rejected() {
        let sk = key(0);
        let mut env = plain(0, 1);
        env.from = 5;
        let err = env.sign(&sk).verify(&[sk.verifying_key()]).unwrap_err();
        assert!(matches!(err, MpcError::EnvelopeAuth(_)));
    }

    #[test]
    fn seal_open_roundtrip() {
        let (alice, bob) = (key(1), key(2));
        let env = Envelope::sealed(
            B256::repeat_byte(7),
            op::DKG,
            1,
            0,
            1,
            &bob.verifying_key(),
            b"shamir fragment",
        )
        .expect("seal");
        assert!(env.sealed);
        assert_eq!(env.open(&bob).expect("recipient opens"), b"shamir fragment");
        assert!(
            env.open(&alice).is_err(),
            "only the addressed recipient can open"
        );
    }

    #[test]
    fn tampered_header_breaks_open() {
        // The header is the AAD: re-routing a sealed payload must fail even
        // though the ciphertext itself is untouched.
        let bob = key(2);
        let mut env = Envelope::sealed(
            B256::repeat_byte(7),
            op::DKG,
            1,
            0,
            1,
            &bob.verifying_key(),
            b"secret",
        )
        .expect("seal");
        env.round = 3;
        assert!(env.open(&bob).is_err());
    }

    #[test]
    fn open_rejects_plaintext_and_truncated_payloads() {
        let bob = key(2);
        assert!(plain(0, 1).open(&bob).is_err());
        let mut env = Envelope::sealed(
            B256::repeat_byte(7),
            op::DKG,
            1,
            0,
            1,
            &bob.verifying_key(),
            b"secret",
        )
        .expect("seal");
        env.payload.truncate(EPH_PK_LEN + NONCE_LEN - 1);
        assert!(env.open(&bob).is_err());
    }
}
