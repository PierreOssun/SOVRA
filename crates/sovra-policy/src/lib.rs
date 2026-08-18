//! Pure signing policy for a cosigner: a decoded transaction view goes in, a
//! verdict comes out. No I/O and no TOML dependency — the cosigner reads the
//! file and hands the string to serde — so evaluation is exhaustively
//! unit-testable and the crate stays lean enough for an embedded build.
//!
//! The grammar is fail-closed at every edge: every field is required and a
//! misspelled key refuses to parse (`deny_unknown_fields`), an empty
//! recipient list denies everyone, and only an explicit `"*"` opens a
//! dimension. `max_value_wei` is a decimal *string* — a TOML integer is i64
//! and would silently cap a ceiling at ~9.2 ETH in wei.
//! Pattern: parse, don't validate — a `Policy` can only exist fully formed.

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Deserializer};

/// The policy-relevant slice of a decoded EIP-1559 transaction.
#[derive(Debug, Clone, Copy)]
pub struct TxView<'a> {
    pub chain_id: u64,
    /// `None` means contract creation (`TxKind::Create`).
    pub to: Option<Address>,
    pub value: U256,
    pub data: &'a [u8],
}

/// The outcome of a policy evaluation. A deny carries the first violated
/// rule; the cosigner maps it to a 403 and the orchestrator relays it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny(DenyReason),
}

/// Why a transaction was refused. `Display` (via thiserror) is the exact
/// string that crosses the wire in the 403 body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    #[error("chain id {0} not allowed")]
    ChainId(u64),
    #[error("recipient {0} not allowed")]
    Recipient(Address),
    #[error("value {value} wei exceeds ceiling {max}")]
    ValueCeiling { value: U256, max: U256 },
    #[error("calldata not allowed")]
    Calldata,
    #[error("contract creation not allowed")]
    ContractCreation,
}

/// `allowed_recipients` in the TOML: a list of addresses, or the single
/// entry `"*"`. An empty list is a valid policy that denies every recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipients {
    Any,
    List(Vec<Address>),
}

impl<'de> Deserialize<'de> for Recipients {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Vec::<String>::deserialize(d)?;
        if raw.iter().any(|s| s == "*") {
            // "*" alongside addresses is almost certainly a mistake — refuse
            // rather than guess which half the operator meant.
            if raw.len() > 1 {
                return Err(serde::de::Error::custom(
                    "\"*\" must be the only allowed_recipients entry",
                ));
            }
            return Ok(Recipients::Any);
        }
        raw.iter()
            .map(|s| {
                s.parse::<Address>()
                    .map_err(|e| serde::de::Error::custom(format!("bad address {s}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Recipients::List)
    }
}

/// One cosigner's local signing policy, deserialized from its TOML file.
/// The two cosigners' policies may legitimately differ — heterogeneous
/// policy mirroring heterogeneous trust is the point of enforcing at each
/// shard.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allowed_chain_ids: Vec<u64>,
    pub allowed_recipients: Recipients,
    #[serde(deserialize_with = "u256_from_dec_string")]
    pub max_value_wei: U256,
    pub allow_calldata: bool,
    /// The one defaulted field: absent means `false`, so every policy file
    /// written before this knob existed keeps denying creation unchanged.
    /// Note creation carries init code in `data`, so allowing it in practice
    /// also requires `allow_calldata = true`.
    #[serde(default)]
    pub allow_contract_creation: bool,
}

/// A TOML integer deserializes through i64 and caps at ~9.2 ETH in wei;
/// requiring a string keeps large ceilings representable and the intent
/// explicit. Accepts what `U256: FromStr` accepts (decimal, or 0x-hex).
fn u256_from_dec_string<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
    let s = String::deserialize(d)?;
    s.parse::<U256>().map_err(serde::de::Error::custom)
}

impl Policy {
    /// Evaluate one decoded transaction against this policy. Fixed check
    /// order (chain, destination shape, recipient, value, calldata) so the
    /// reported reason is deterministic; the first violation wins.
    pub fn evaluate(&self, tx: &TxView<'_>) -> Verdict {
        if !self.allowed_chain_ids.contains(&tx.chain_id) {
            return Verdict::Deny(DenyReason::ChainId(tx.chain_id));
        }
        match tx.to {
            // Creation has no recipient to allowlist — the knob is the
            // whole decision (value ceiling and calldata still apply below).
            None if !self.allow_contract_creation => {
                return Verdict::Deny(DenyReason::ContractCreation);
            }
            None => {}
            Some(to) => match &self.allowed_recipients {
                Recipients::Any => {}
                // An empty list falls through to Deny for every address.
                Recipients::List(allowed) if allowed.contains(&to) => {}
                Recipients::List(_) => return Verdict::Deny(DenyReason::Recipient(to)),
            },
        }
        if tx.value > self.max_value_wei {
            return Verdict::Deny(DenyReason::ValueCeiling {
                value: tx.value,
                max: self.max_value_wei,
            });
        }
        if !self.allow_calldata && !tx.data.is_empty() {
            return Verdict::Deny(DenyReason::Calldata);
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;

    use super::*;

    const RECIPIENT: Address = address!("1111111111111111111111111111111111111111");
    const OTHER: Address = address!("2222222222222222222222222222222222222222");

    fn policy() -> Policy {
        Policy {
            allowed_chain_ids: vec![11155111],
            allowed_recipients: Recipients::List(vec![RECIPIENT]),
            max_value_wei: U256::from(1_000_000u64),
            allow_calldata: false,
            allow_contract_creation: false,
        }
    }

    fn tx(chain_id: u64, to: Option<Address>, value: u64, data: &'static [u8]) -> TxView<'static> {
        TxView {
            chain_id,
            to,
            value: U256::from(value),
            data,
        }
    }

    #[test]
    fn allows_compliant_tx() {
        let v = policy().evaluate(&tx(11155111, Some(RECIPIENT), 999_999, &[]));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn allows_value_exactly_at_ceiling() {
        let v = policy().evaluate(&tx(11155111, Some(RECIPIENT), 1_000_000, &[]));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn denies_wrong_chain() {
        let v = policy().evaluate(&tx(1, Some(RECIPIENT), 1, &[]));
        assert_eq!(v, Verdict::Deny(DenyReason::ChainId(1)));
    }

    #[test]
    fn denies_contract_creation() {
        let v = policy().evaluate(&tx(11155111, None, 1, &[]));
        assert_eq!(v, Verdict::Deny(DenyReason::ContractCreation));
    }

    #[test]
    fn creation_knob_allows_creation() {
        let mut p = policy();
        p.allow_contract_creation = true;
        p.allow_calldata = true; // init code travels in `data`
        let v = p.evaluate(&tx(11155111, None, 1, b"\x60\x80"));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn creation_still_subject_to_calldata_knob() {
        let mut p = policy();
        p.allow_contract_creation = true;
        let v = p.evaluate(&tx(11155111, None, 1, b"\x60\x80"));
        assert_eq!(v, Verdict::Deny(DenyReason::Calldata));
    }

    #[test]
    fn denies_unlisted_recipient() {
        let v = policy().evaluate(&tx(11155111, Some(OTHER), 1, &[]));
        assert_eq!(v, Verdict::Deny(DenyReason::Recipient(OTHER)));
    }

    #[test]
    fn empty_recipient_list_denies_everyone() {
        let mut p = policy();
        p.allowed_recipients = Recipients::List(vec![]);
        let v = p.evaluate(&tx(11155111, Some(RECIPIENT), 1, &[]));
        assert_eq!(v, Verdict::Deny(DenyReason::Recipient(RECIPIENT)));
    }

    #[test]
    fn wildcard_allows_any_recipient() {
        let mut p = policy();
        p.allowed_recipients = Recipients::Any;
        assert_eq!(
            p.evaluate(&tx(11155111, Some(OTHER), 1, &[])),
            Verdict::Allow
        );
    }

    #[test]
    fn denies_value_over_ceiling() {
        let v = policy().evaluate(&tx(11155111, Some(RECIPIENT), 1_000_001, &[]));
        assert_eq!(
            v,
            Verdict::Deny(DenyReason::ValueCeiling {
                value: U256::from(1_000_001u64),
                max: U256::from(1_000_000u64),
            })
        );
    }

    #[test]
    fn denies_calldata_when_disallowed() {
        let v = policy().evaluate(&tx(11155111, Some(RECIPIENT), 1, b"\x01"));
        assert_eq!(v, Verdict::Deny(DenyReason::Calldata));
    }

    #[test]
    fn allows_calldata_when_enabled() {
        let mut p = policy();
        p.allow_calldata = true;
        let v = p.evaluate(&tx(11155111, Some(RECIPIENT), 1, b"\x01"));
        assert_eq!(v, Verdict::Allow);
    }

    #[test]
    fn first_violation_wins() {
        // Wrong chain AND over ceiling: the fixed check order reports chain.
        let v = policy().evaluate(&tx(1, Some(RECIPIENT), 2_000_000, &[]));
        assert_eq!(v, Verdict::Deny(DenyReason::ChainId(1)));
    }

    // -- TOML grammar ------------------------------------------------------

    #[test]
    fn parses_policy_with_ceiling_beyond_u64() {
        let p: Policy = toml::from_str(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["0x1111111111111111111111111111111111111111"]
            max_value_wei = "36893488147419103232" # 2^65
            allow_calldata = false
            "#,
        )
        .unwrap();
        assert_eq!(p.max_value_wei, U256::from(2u8).pow(U256::from(65u8)));
        assert_eq!(p.allowed_recipients, Recipients::List(vec![RECIPIENT]));
    }

    #[test]
    fn parses_wildcard_recipients() {
        let p: Policy = toml::from_str(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*"]
            max_value_wei = "1"
            allow_calldata = false
            "#,
        )
        .unwrap();
        assert_eq!(p.allowed_recipients, Recipients::Any);
    }

    #[test]
    fn rejects_integer_ceiling() {
        // A TOML integer is i64 — the silent ~9.2 ETH cap the string avoids.
        let r = toml::from_str::<Policy>(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*"]
            max_value_wei = 1000000
            allow_calldata = false
            "#,
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_wildcard_mixed_with_addresses() {
        let r = toml::from_str::<Policy>(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*", "0x1111111111111111111111111111111111111111"]
            max_value_wei = "1"
            allow_calldata = false
            "#,
        );
        assert!(r.is_err());
    }

    #[test]
    fn absent_creation_knob_defaults_to_deny() {
        // The pre-knob policy file grammar must keep parsing byte-for-byte,
        // and keep refusing creation.
        let p: Policy = toml::from_str(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*"]
            max_value_wei = "1"
            allow_calldata = true
            "#,
        )
        .unwrap();
        assert!(!p.allow_contract_creation);
        assert_eq!(
            p.evaluate(&tx(11155111, None, 1, b"\x01")),
            Verdict::Deny(DenyReason::ContractCreation)
        );
    }

    #[test]
    fn rejects_missing_key() {
        let r = toml::from_str::<Policy>(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*"]
            max_value_wei = "1"
            "#, // allow_calldata missing
        );
        assert!(r.is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        let r = toml::from_str::<Policy>(
            r#"
            allowed_chain_ids = [11155111]
            allowed_recipients = ["*"]
            max_value_wei = "1"
            allow_calldata = false
            allow_caldata = true # typo must not parse
            "#,
        );
        assert!(r.is_err());
    }
}
