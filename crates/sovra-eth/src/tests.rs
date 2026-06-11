use crate::*;
use alloy_consensus::private::alloy_eips::Decodable2718;
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{Transaction, TxEnvelope};
use alloy_primitives::b256;
use alloy_primitives::{Address, Bytes, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

#[test]
fn returns_the_correct_prepared_tx() {
    let tx_intent = TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 1,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    };
    let prepared_tx = prepare(tx_intent).unwrap();

    assert_eq!(
        prepared_tx.signing_hash,
        b256!("0x2b22ba8a95f228787769996a2eb1b4a6f235ef0eb951258a3438aa13f080bfcd")
    );

    let tx_intent2 = TxIntent {
        chain_id: 11155111,
        nonce: 3,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 1,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    };
    let prepared_tx = prepare(tx_intent2).unwrap();

    assert_eq!(
        prepared_tx.signing_hash,
        b256!("0x8f6d844ba2949eb9f557f6936c8c948934d9bcacfc56fa181a446f463936968b")
    );
}

#[test]
fn invalid_inputs_return_error() {
    let tx_intent = TxIntent {
        chain_id: 0,
        nonce: 0,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 1,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    };
    assert_eq!(prepare(tx_intent).unwrap_err(), PrepareError::ZeroChainId);

    let tx_intent_2 = TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 0,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    };
    assert_eq!(
        prepare(tx_intent_2).unwrap_err(),
        PrepareError::ZeroGasLimit
    );

    let tx_intent_3 = TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Default::default(),
        value: Default::default(),
        gas_limit: 1,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    };
    assert_eq!(
        prepare(tx_intent_3).unwrap_err(),
        PrepareError::MaxPriorityFeeExceedsMaxFee
    );
}

#[test]
fn finalize_returns_signed_tx() {
    let signer = fixed_signer();
    let prepared = prepare(base_intent()).unwrap();
    let (r, s, v) = sign(&prepared, &signer);

    let signed = finalize(prepared, r, s, v, signer.address()).unwrap();

    assert_eq!(signed.from, signer.address());
}

#[test]
fn finalize_rejects_wrong_expected_from() {
    let signer = fixed_signer();
    let prepared = prepare(base_intent()).unwrap();
    let (r, s, v) = sign(&prepared, &signer);
    let wrong = Address::from([0xff; 20]);

    assert_eq!(
        finalize(prepared, r, s, v, wrong).unwrap_err(),
        FinalizeError::AddressMismatch {
            expected: wrong,
            recovered: signer.address()
        }
    );
}

#[test]
fn finalize_roundtrips_calldata() {
    let signer = fixed_signer();
    let mut intent = base_intent();
    intent.data = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]);
    let prepared = prepare(intent).unwrap();
    let (r, s, v) = sign(&prepared, &signer);

    let signed = finalize(prepared, r, s, v, signer.address()).unwrap();

    // Decode the broadcast bytes back and confirm the payload survived the trip.
    let decoded = TxEnvelope::decode_2718(&mut signed.raw.as_ref()).unwrap();
    assert_eq!(decoded.input().as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.recover_signer().unwrap(), signer.address());
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

fn base_intent() -> TxIntent {
    TxIntent {
        chain_id: 11155111,
        nonce: 0,
        to: Address::from([0x11; 20]),
        value: U256::from(1_000_000_000u64),
        gas_limit: 21_000,
        max_fee_per_gas: 3,
        max_priority_fee_per_gas: 2,
        data: Default::default(),
    }
}

fn fixed_signer() -> PrivateKeySigner {
    let key = b256!("0x0101010101010101010101010101010101010101010101010101010101010101");
    PrivateKeySigner::from_bytes(&key).unwrap()
}

fn sign(prepared: &PreparedTx, signer: &PrivateKeySigner) -> (U256, U256, bool) {
    let sig = signer.sign_hash_sync(&prepared.signing_hash).unwrap();
    (sig.r(), sig.s(), sig.v())
}
