#[cfg(test)]
mod tests {
    use alloy_primitives::Address;
    use sovra_types::{KeyShare, SignerId, SignerMetadata};

    use crate::{
        SHARD_FILE, SignerStore,
        types::{ShardSealer, StateError},
    };

    fn signer(id: &str, byte: u8) -> SignerMetadata {
        SignerMetadata {
            signer_id: SignerId::new(id),
            address: Address::from([byte; 20]),
        }
    }

    fn shard(bytes: &[u8]) -> KeyShare {
        KeyShare::from(bytes.to_vec())
    }

    /// Invertible non-identity sealer — proves seal/open are actually wired.
    struct Reverse;
    impl ShardSealer for Reverse {
        fn seal(&self, p: &[u8]) -> Result<Vec<u8>, StateError> {
            Ok(p.iter().rev().copied().collect())
        }
        fn open(&self, s: &[u8]) -> Result<Vec<u8>, StateError> {
            Ok(s.iter().rev().copied().collect())
        }
    }

    #[test]
    fn round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SignerStore::open(tmp.path()).unwrap();
        let meta = signer("signer-1", 0x11);
        let sh = shard(b"party-0-share-bytes");

        store.save_shard(&meta, &sh).unwrap();

        assert_eq!(store.load_shard(&meta.signer_id).unwrap(), sh);
        assert_eq!(store.load_metadata(&meta.signer_id).unwrap(), meta);
    }

    #[test]
    fn two_party_separate_roots() {
        let root0 = tempfile::tempdir().unwrap();
        let root1 = tempfile::tempdir().unwrap();
        let pi = SignerStore::open(root0.path()).unwrap();
        let phone = SignerStore::open(root1.path()).unwrap();

        let meta = signer("signer-1", 0x11);
        let s0 = shard(b"shard-for-party-0");
        let s1 = shard(b"shard-for-party-1");

        pi.save_shard(&meta, &s0).unwrap();
        phone.save_shard(&meta, &s1).unwrap();

        // Each store holds only its own shard, byte-identical on reload.
        assert_eq!(pi.load_shard(&meta.signer_id).unwrap(), s0);
        assert_eq!(phone.load_shard(&meta.signer_id).unwrap(), s1);
        assert_ne!(s0, s1);
    }

    #[test]
    fn address_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SignerStore::open(tmp.path()).unwrap();
        let meta = signer("signer-1", 0x11);
        store.save_shard(&meta, &shard(b"x")).unwrap();

        assert_eq!(
            store.find_by_address(&meta.address).unwrap(),
            meta.signer_id
        );

        let missing = Address::from([0xAB; 20]);
        assert!(matches!(
            store.find_by_address(&missing),
            Err(StateError::AddressNotFound(_))
        ));
    }

    #[test]
    fn not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SignerStore::open(tmp.path()).unwrap();
        let unknown = SignerId::new("nope");

        assert!(matches!(
            store.load_shard(&unknown),
            Err(StateError::NotFound(_))
        ));
        assert!(matches!(
            store.load_metadata(&unknown),
            Err(StateError::NotFound(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shard_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let store = SignerStore::open(tmp.path()).unwrap();
        let meta = signer("signer-1", 0x11);
        store.save_shard(&meta, &shard(b"secret")).unwrap();

        let shard_path = tmp.path().join("signer-1").join(SHARD_FILE);
        let mode = std::fs::metadata(&shard_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn sealer_is_applied() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SignerStore::open_with_sealer(tmp.path(), Box::new(Reverse)).unwrap();
        let meta = signer("signer-1", 0x11);
        let sh = shard(b"abcdef");

        store.save_shard(&meta, &sh).unwrap();

        // Round-trips through the same sealer...
        assert_eq!(store.load_shard(&meta.signer_id).unwrap(), sh);

        // ...but the on-disk bytes are transformed, not the raw shard.
        let raw = std::fs::read(tmp.path().join("signer-1").join(SHARD_FILE)).unwrap();
        assert_ne!(raw, sh.as_bytes());
        assert_eq!(raw, b"fedcba"); // reversed
    }
}
