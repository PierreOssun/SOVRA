use alloy_consensus::{
    Transaction, TxEnvelope, TxLegacy, private::alloy_eips::Decodable2718,
    transaction::SignerRecoverable,
};
use alloy_primitives::{Address, Bytes, TxKind, U256, b256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

use crate::{encoding::*, prepare::*, types::*, *};

#[test]
fn returns_the_correct_prepared_tx() {
    let tx_intent = TxIntent {
        chain_id: 11155111,
        nonce: 0,
        kind: TxKind::Call(Default::default()),
        value: Default::default(),
        gas_limit: 1,
        data: Default::default(),
        params: TxParams::Eip1559 {
            max_fee_per_gas: 3,
            max_priority_fee_per_gas: 2,
            access_list: Default::default(),
        },
    };
    let prepared_tx = prepare(tx_intent).unwrap();

    // Pinned before the EthTx refactor: proves the 1559 signing preimage is
    // byte-identical to the TxEip1559-only implementation.
    assert_eq!(
        prepared_tx.signing_hash,
        b256!("0x2b22ba8a95f228787769996a2eb1b4a6f235ef0eb951258a3438aa13f080bfcd")
    );

    let tx_intent2 = TxIntent {
        chain_id: 11155111,
        nonce: 3,
        kind: TxKind::Call(Default::default()),
        value: Default::default(),
        gas_limit: 1,
        data: Default::default(),
        params: TxParams::Eip1559 {
            max_fee_per_gas: 3,
            max_priority_fee_per_gas: 2,
            access_list: Default::default(),
        },
    };
    let prepared_tx = prepare(tx_intent2).unwrap();

    assert_eq!(
        prepared_tx.signing_hash,
        b256!("0x8f6d844ba2949eb9f557f6936c8c948934d9bcacfc56fa181a446f463936968b")
    );
}

#[test]
fn invalid_inputs_return_error() {
    let mut intent = base_intent();
    intent.chain_id = 0;
    assert!(matches!(
        prepare(intent).unwrap_err(),
        PrepareError::ZeroChainId
    ));

    let mut intent = base_intent();
    intent.gas_limit = 0;
    assert!(matches!(
        prepare(intent).unwrap_err(),
        PrepareError::ZeroGasLimit
    ));

    let mut intent = base_intent();
    intent.params = TxParams::Eip1559 {
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 2,
        access_list: Default::default(),
    };
    assert!(matches!(
        prepare(intent).unwrap_err(),
        PrepareError::MaxPriorityFeeExceedsMaxFee
    ));
}

#[test]
fn validate_rejects_pre_eip155_legacy() {
    let tx = EthTx::Legacy(TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 3,
        gas_limit: 21_000,
        to: TxKind::Call(Address::from([0x11; 20])),
        value: U256::from(1u64),
        input: Bytes::new(),
    });
    assert!(matches!(
        validate_unsigned(&tx).unwrap_err(),
        PrepareError::MissingChainId
    ));
}

#[test]
fn finalize_returns_signed_tx() {
    for intent in all_type_intents() {
        let signer = fixed_signer();
        let prepared = prepare(intent).unwrap();
        let (r, s, v) = sign(&prepared, &signer);

        let signed = finalize(prepared, r, s, v, signer.address()).unwrap();

        assert_eq!(signed.from, signer.address());
    }
}

#[test]
fn finalize_rejects_wrong_expected_from() {
    let signer = fixed_signer();
    let prepared = prepare(base_intent()).unwrap();
    let (r, s, v) = sign(&prepared, &signer);
    let wrong = Address::from([0xff; 20]);

    assert!(matches!(
        finalize(prepared, r, s, v, wrong).unwrap_err(),
        FinalizeError::AddressMismatch { expected, recovered }
            if expected == wrong && recovered == signer.address()
    ))
}

/// The per-type end-to-end proof: sign, finalize, then decode the broadcast
/// bytes with alloy's own envelope decoder and recover the signer. For
/// legacy this is what catches a wrong EIP-155 `v` (35 + 2·chain_id +
/// parity) — a bad `v` recovers a different address.
#[test]
fn finalize_roundtrips_all_types() {
    for intent in all_type_intents() {
        let signer = fixed_signer();
        let mut intent = intent;
        intent.data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
        let prepared = prepare(intent).unwrap();
        let (r, s, v) = sign(&prepared, &signer);

        let signed = finalize(prepared, r, s, v, signer.address()).unwrap();

        let decoded = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
        assert_eq!(decoded.input().as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.recover_signer().unwrap(), signer.address());
        assert_eq!(*decoded.tx_hash(), signed.tx_hash);

        // The broadcast gate's own decoder must agree with alloy's.
        let redecoded = decode_signed(&signed.raw).unwrap();
        assert_eq!(redecoded, signed);
    }
}

#[test]
fn finalize_is_deterministic() {
    let signer = fixed_signer();

    let p1 = prepare(base_intent()).unwrap();
    let (r1, s1, v1) = sign(&p1, &signer);
    let f1 = finalize(p1, r1, s1, v1, signer.address()).unwrap();

    let p2 = prepare(base_intent()).unwrap();
    let (r2, s2, v2) = sign(&p2, &signer);
    let f2 = finalize(p2, r2, s2, v2, signer.address()).unwrap();

    assert_eq!(f1.raw, f2.raw);
    assert_eq!(f1.tx_hash, f2.tx_hash);
}

#[test]
fn decoding_roundtrip_all_types() {
    for intent in all_type_intents() {
        let mut intent = intent;
        intent.data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
        let prepared = prepare(intent).unwrap();

        let raw = encode_unsigned(&prepared.tx);
        let decoded = decode_unsigned(&raw).unwrap();

        assert_eq!(decoded.tx, prepared.tx);
        assert_eq!(decoded.signing_hash, prepared.signing_hash);
    }
}

#[test]
fn decode_rejects_unsupported_type() {
    // 0x03 (EIP-4844) and 0x04 (EIP-7702) are type bytes EthTx refuses to
    // represent; 0x05 is simply unknown.
    for type_byte in [0x03u8, 0x04, 0x05] {
        let prepared = prepare(base_intent()).unwrap();
        let mut raw = encode_unsigned(&prepared.tx).to_vec();
        raw[0] = type_byte;

        assert!(matches!(
            decode_unsigned(&raw).unwrap_err(),
            DecodeError::UnsupportedType(b) if b == type_byte
        ));
    }
}

#[test]
fn decode_rejects_empty_input() {
    assert!(matches!(
        decode_unsigned(&[]).unwrap_err(),
        DecodeError::Empty
    ));
}

#[test]
fn decode_rejects_trailing_bytes() {
    for intent in all_type_intents() {
        let prepared = prepare(intent).unwrap();
        let mut raw = encode_unsigned(&prepared.tx).to_vec();
        raw.push(0x00);

        assert!(matches!(
            decode_unsigned(&raw).unwrap_err(),
            DecodeError::TrailingBytes
        ));
    }
}

#[test]
fn decode_rejects_truncated_body() {
    let prepared = prepare(base_intent()).unwrap();
    let raw = encode_unsigned(&prepared.tx);
    let truncated = &raw[..raw.len() - 1];

    assert!(matches!(
        decode_unsigned(truncated).unwrap_err(),
        DecodeError::Rlp(_)
    ));
}

#[test]
fn contract_creation_roundtrips() {
    let mut intent = base_intent();
    intent.kind = TxKind::Create;
    intent.data = Bytes::from_static(&[0x60, 0x80]); // init code
    let prepared = prepare(intent).unwrap();
    assert_eq!(prepared.tx.to(), None);

    let decoded = decode_unsigned(&encode_unsigned(&prepared.tx)).unwrap();
    assert_eq!(decoded.tx, prepared.tx);
}

fn intent(params: TxParams) -> TxIntent {
    TxIntent {
        chain_id: 11155111,
        nonce: 0,
        kind: TxKind::Call(Address::from([0x11; 20])),
        value: U256::from(1_000_000_000u64),
        gas_limit: 21_000,
        data: Default::default(),
        params,
    }
}

fn base_intent() -> TxIntent {
    intent(TxParams::Eip1559 {
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        access_list: Default::default(),
    })
}

/// One intent per supported tx type, same common fields.
fn all_type_intents() -> [TxIntent; 3] {
    [
        intent(TxParams::Legacy { gas_price: 3 }),
        intent(TxParams::Eip2930 {
            gas_price: 3,
            access_list: Default::default(),
        }),
        base_intent(),
    ]
}

fn fixed_signer() -> PrivateKeySigner {
    let key = b256!("0x0101010101010101010101010101010101010101010101010101010101010101");
    PrivateKeySigner::from_bytes(&key).unwrap()
}

fn sign(prepared: &PreparedTx, signer: &PrivateKeySigner) -> (U256, U256, bool) {
    let sig = signer.sign_hash_sync(&prepared.signing_hash).unwrap();
    (sig.r(), sig.s(), sig.v())
}
