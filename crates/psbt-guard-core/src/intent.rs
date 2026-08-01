//! User-declared payment intent.
//!
//! TOML is the primary manifest format; JSON with the same shape is also
//! accepted. Parsing validates network/address compatibility, rejects unknown
//! fields and prevents ambiguous duplicate-recipient declarations.

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{Address, Network};
use serde::Deserialize;
use thiserror::Error;

/// Supported intent-manifest encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntentFormat {
    /// TOML manifest.
    Toml,
    /// JSON manifest.
    Json,
}

/// A validated payment intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    network: Network,
    recipients: Vec<RecipientIntent>,
    fee_policy: FeePolicy,
    change_policy: ChangePolicy,
}

impl Intent {
    /// Network all recipient addresses must belong to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Declared recipients, preserved in manifest order.
    pub fn recipients(&self) -> &[RecipientIntent] {
        &self.recipients
    }

    /// Absolute-fee policy.
    pub fn fee_policy(&self) -> &FeePolicy {
        &self.fee_policy
    }

    /// Count-based change policy used until descriptor verification lands.
    pub fn change_policy(&self) -> &ChangePolicy {
        &self.change_policy
    }
}

/// One declared recipient and the amount expected at its script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientIntent {
    address: Address<NetworkChecked>,
    amount_sat: u64,
    amount_tolerance_sat: u64,
}

impl RecipientIntent {
    /// Validated recipient address.
    pub fn address(&self) -> &Address<NetworkChecked> {
        &self.address
    }

    /// Expected aggregate amount paid to this address.
    pub fn amount_sat(&self) -> u64 {
        self.amount_sat
    }

    /// Allowed absolute difference from the expected amount.
    pub fn amount_tolerance_sat(&self) -> u64 {
        self.amount_tolerance_sat
    }
}

/// Absolute-fee ceiling.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicy {
    max_absolute_fee_sat: u64,
}

impl FeePolicy {
    /// Maximum fee the transaction may pay.
    pub fn max_absolute_fee_sat(&self) -> u64 {
        self.max_absolute_fee_sat
    }
}

/// Count-based allowance for outputs not assigned to declared recipients.
///
/// This does not prove those outputs belong to the user's wallet. Descriptor-
/// based change verification is intentionally deferred to M4.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePolicy {
    max_change_outputs: usize,
}

impl ChangePolicy {
    /// Maximum number of undeclared outputs tolerated as change candidates.
    pub fn max_change_outputs(&self) -> usize {
        self.max_change_outputs
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIntent {
    network: String,
    recipients: Vec<RawRecipientIntent>,
    fee_policy: FeePolicy,
    change_policy: ChangePolicy,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecipientIntent {
    address: String,
    amount_sat: u64,
    #[serde(default)]
    amount_tolerance_sat: u64,
}

/// Intent-manifest validation errors.
#[derive(Debug, Error)]
pub enum IntentError {
    /// TOML syntax or schema error.
    #[error("invalid TOML intent manifest: {0}")]
    Toml(#[from] toml::de::Error),
    /// JSON syntax or schema error.
    #[error("invalid JSON intent manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// Unsupported network name.
    #[error("unsupported intent network `{0}`; expected bitcoin, testnet, signet or regtest")]
    UnsupportedNetwork(String),
    /// At least one recipient is required.
    #[error("intent must declare at least one recipient")]
    NoRecipients,
    /// Address text was malformed or belonged to another network.
    #[error("invalid recipient address `{address}`: {reason}")]
    InvalidAddress { address: String, reason: String },
    /// Duplicate recipient declarations make matching ambiguous.
    #[error("recipient address `{0}` is declared more than once")]
    DuplicateRecipient(String),
    /// Zero-value recipients are rejected as likely manifest mistakes.
    #[error("recipient `{0}` must declare an amount greater than zero")]
    ZeroRecipientAmount(String),
    /// A tolerance larger than the expected amount could accept a zero payment.
    #[error(
        "recipient `{address}` has tolerance {tolerance_sat} sat greater than expected amount {amount_sat} sat"
    )]
    ExcessiveTolerance {
        address: String,
        tolerance_sat: u64,
        amount_sat: u64,
    },
}

/// Parse and validate an intent manifest in the selected format.
pub fn parse_intent(text: &str, format: IntentFormat) -> Result<Intent, IntentError> {
    let raw = match format {
        IntentFormat::Toml => toml::from_str(text)?,
        IntentFormat::Json => serde_json::from_str(text)?,
    };

    validate(raw)
}

/// Parse and validate a TOML intent manifest.
pub fn parse_intent_toml(text: &str) -> Result<Intent, IntentError> {
    parse_intent(text, IntentFormat::Toml)
}

/// Parse and validate a JSON intent manifest.
pub fn parse_intent_json(text: &str) -> Result<Intent, IntentError> {
    parse_intent(text, IntentFormat::Json)
}

fn validate(raw: RawIntent) -> Result<Intent, IntentError> {
    let network = parse_network(&raw.network)?;
    if raw.recipients.is_empty() {
        return Err(IntentError::NoRecipients);
    }

    let mut seen = HashSet::new();
    let mut recipients = Vec::with_capacity(raw.recipients.len());

    for recipient in raw.recipients {
        let unchecked =
            Address::<NetworkUnchecked>::from_str(&recipient.address).map_err(|error| {
                IntentError::InvalidAddress {
                    address: recipient.address.clone(),
                    reason: error.to_string(),
                }
            })?;
        let address =
            unchecked
                .require_network(network)
                .map_err(|error| IntentError::InvalidAddress {
                    address: recipient.address.clone(),
                    reason: error.to_string(),
                })?;
        let canonical = address.to_string();

        if !seen.insert(canonical.clone()) {
            return Err(IntentError::DuplicateRecipient(canonical));
        }
        if recipient.amount_sat == 0 {
            return Err(IntentError::ZeroRecipientAmount(canonical));
        }
        if recipient.amount_tolerance_sat > recipient.amount_sat {
            return Err(IntentError::ExcessiveTolerance {
                address: canonical,
                tolerance_sat: recipient.amount_tolerance_sat,
                amount_sat: recipient.amount_sat,
            });
        }

        recipients.push(RecipientIntent {
            address,
            amount_sat: recipient.amount_sat,
            amount_tolerance_sat: recipient.amount_tolerance_sat,
        });
    }

    Ok(Intent {
        network,
        recipients,
        fee_policy: raw.fee_policy,
        change_policy: raw.change_policy,
    })
}

fn parse_network(value: &str) -> Result<Network, IntentError> {
    match value {
        "bitcoin" => Ok(Network::Bitcoin),
        "testnet" => Ok(Network::Testnet),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(IntentError::UnsupportedNetwork(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_intent_json, parse_intent_toml, IntentError};

    const TESTNET_ADDRESS: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";

    fn toml_manifest(address: &str) -> String {
        format!(
            r#"network = "testnet"

[[recipients]]
address = "{address}"
amount_sat = 60000

[fee_policy]
max_absolute_fee_sat = 2000

[change_policy]
max_change_outputs = 1
"#
        )
    }

    #[test]
    fn parses_and_validates_toml() {
        let intent = parse_intent_toml(&toml_manifest(TESTNET_ADDRESS)).expect("valid intent");

        assert_eq!(intent.recipients().len(), 1);
        assert_eq!(intent.recipients()[0].amount_sat(), 60_000);
        assert_eq!(intent.fee_policy().max_absolute_fee_sat(), 2_000);
        assert_eq!(intent.change_policy().max_change_outputs(), 1);
    }

    #[test]
    fn parses_json_with_same_schema() {
        let manifest = format!(
            r#"{{
  "network": "testnet",
  "recipients": [{{"address": "{TESTNET_ADDRESS}", "amount_sat": 60000}}],
  "fee_policy": {{"max_absolute_fee_sat": 2000}},
  "change_policy": {{"max_change_outputs": 1}}
}}"#
        );

        let intent = parse_intent_json(&manifest).expect("valid JSON intent");
        assert_eq!(intent.recipients()[0].amount_tolerance_sat(), 0);
    }

    #[test]
    fn rejects_wrong_network_address() {
        let manifest = toml_manifest("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        assert!(matches!(
            parse_intent_toml(&manifest),
            Err(IntentError::InvalidAddress { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields_to_catch_policy_typos() {
        let manifest = toml_manifest(TESTNET_ADDRESS).replace(
            "max_absolute_fee_sat = 2000",
            "max_absolute_fee_sat = 2000\nmax_fee_typo = 10",
        );

        assert!(matches!(
            parse_intent_toml(&manifest),
            Err(IntentError::Toml(_))
        ));
    }

    #[test]
    fn checked_in_example_manifest_stays_valid() {
        let manifest = include_str!("../../../examples/intent.toml");
        parse_intent_toml(manifest).expect("examples/intent.toml must remain valid");
    }
}
