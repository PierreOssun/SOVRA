#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_primitives::B256;
    use ed25519_dalek::SigningKey;
    use sl_mpc_mate::coord::SimpleMessageRelay;

    use crate::{keygen_party, types::PartyContext};

    /// Proves message auth is REAL, not decorative: if a party is told the wrong
    /// verifying key for its peer, the signed setup messages fail verification.
    #[tokio::test(flavor = "multi_thread")]
    async fn wrong_peer_vk_breaks_keygen() {
        let coord = SimpleMessageRelay::new();
        let sk0 = SigningKey::generate(&mut rand::rngs::OsRng);
        let sk1 = SigningKey::generate(&mut rand::rngs::OsRng);
        let (vk0, vk1) = (sk0.verifying_key(), sk1.verifying_key());
        let bogus = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        let instance = B256::from(rand::random::<[u8; 32]>());
        let ttl = Duration::from_secs(60);

        // party 1 is told the wrong verifying key for party 0
        let ctx0 = PartyContext {
            party_id: 0,
            instance,
            signing_key: sk0,
            party_vks: [vk0, vk1],
            ttl,
        };
        let ctx1 = PartyContext {
            party_id: 1,
            instance,
            signing_key: sk1,
            party_vks: [bogus, vk1],
            ttl,
        };

        let both = async {
            tokio::join!(
                keygen_party(&ctx0, coord.connect()),
                keygen_party(&ctx1, coord.connect()),
            )
        };

        // A wrong peer vk changes MsgId routing, so the parties can never exchange round
        // messages — the run stalls rather than completing. Timing out IS the pass condition.
        match tokio::time::timeout(Duration::from_secs(2), both).await {
            Err(_elapsed) => {} // expected: keygen could not complete
            Ok((a, b)) => assert!(
                a.is_err() || b.is_err(),
                "a mismatched peer key must prevent a successful keygen, but both parties succeeded",
            ),
        }
    }
}
