//! Core analysis vocabulary: severities, finding codes, findings, and context.

use bitcoin::Psbt;
use serde::{Deserialize, Serialize};

/// How much attention a finding deserves before signing.
///
/// The ordering is semantic: greater means more severe. The CLI maps any
/// finding at [`Severity::Violation`] or above to exit code `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Neutral observation; useful context, no action required.
    Info,
    /// Deserves human review, but does not contradict the declared intent.
    Warning,
    /// Contradicts the user-declared intent or policy.
    Violation,
    /// Unsafe to sign regardless of intent (e.g. non-standard sighash).
    Critical,
}

impl Severity {
    /// Whether this severity should cause a non-zero (failure) exit code.
    pub fn is_blocking(self) -> bool {
        self >= Severity::Violation
    }
}

/// Stable machine-readable finding identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FindingCode {
    /// Missing UTXO information.
    #[serde(rename = "PG101")]
    Pg101,
    /// Unknown PSBT fields.
    #[serde(rename = "PG102")]
    Pg102,
    /// Proprietary PSBT fields.
    #[serde(rename = "PG103")]
    Pg103,
    /// Invalid or non-standard sighash information.
    #[serde(rename = "PG104")]
    Pg104,
    /// Input finalization or partial-signature status.
    #[serde(rename = "PG105")]
    Pg105,
}

impl FindingCode {
    /// Human-readable stable code.
    pub fn as_str(self) -> &'static str {
        match self {
            FindingCode::Pg101 => "PG101",
            FindingCode::Pg102 => "PG102",
            FindingCode::Pg103 => "PG103",
            FindingCode::Pg104 => "PG104",
            FindingCode::Pg105 => "PG105",
        }
    }
}

impl std::fmt::Display for FindingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where in the PSBT a finding points.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    /// The PSBT global map.
    Global,
    /// A PSBT input map.
    Input,
    /// A PSBT output map.
    Output,
}

/// Structured pointer to the thing a finding noticed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Which PSBT map the evidence comes from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<EvidenceScope>,
    /// Input index when `scope` is `input`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_index: Option<usize>,
    /// Output index when `scope` is `output`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<usize>,
    /// Field name or grouped field family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Short deterministic detail value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

impl Evidence {
    /// Evidence in the global PSBT map.
    pub fn global(field: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            scope: Some(EvidenceScope::Global),
            field: Some(field.into()),
            actual: Some(actual.into()),
            ..Self::default()
        }
    }

    /// Evidence in an input map.
    pub fn input(index: usize, field: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            scope: Some(EvidenceScope::Input),
            input_index: Some(index),
            field: Some(field.into()),
            actual: Some(actual.into()),
            ..Self::default()
        }
    }

    /// Evidence in an output map.
    pub fn output(index: usize, field: impl Into<String>, actual: impl Into<String>) -> Self {
        Self {
            scope: Some(EvidenceScope::Output),
            output_index: Some(index),
            field: Some(field.into()),
            actual: Some(actual.into()),
            ..Self::default()
        }
    }
}

/// One advisory observation produced by a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable machine identifier.
    pub code: FindingCode,
    /// Review severity.
    pub severity: Severity,
    /// Short human title.
    pub title: String,
    /// Plain-language explanation.
    pub explanation: String,
    /// Structured pointer to what was observed.
    pub evidence: Evidence,
    /// What the reviewer should do next.
    pub suggested_action: String,
}

/// Parsed PSBT plus any shared derived facts rules need.
pub struct AnalysisContext {
    psbt: Psbt,
}

impl AnalysisContext {
    /// Build a read-only analysis context from a parsed PSBT.
    pub fn from_psbt(psbt: Psbt) -> Self {
        Self { psbt }
    }

    /// The parsed PSBT under review.
    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }
}

#[cfg(test)]
mod tests {
    use super::{Evidence, EvidenceScope, FindingCode, Severity};

    #[test]
    fn severity_orders_from_info_to_critical() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Violation);
        assert!(Severity::Violation < Severity::Critical);
    }

    #[test]
    fn only_violation_and_critical_block() {
        assert!(!Severity::Info.is_blocking());
        assert!(!Severity::Warning.is_blocking());
        assert!(Severity::Violation.is_blocking());
        assert!(Severity::Critical.is_blocking());
    }

    #[test]
    fn severity_serializes_as_snake_case() {
        let json = serde_json::to_string(&Severity::Critical).expect("serialize");
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn finding_code_serializes_as_stable_catalogue_code() {
        let json = serde_json::to_string(&FindingCode::Pg101).expect("serialize");
        assert_eq!(json, "\"PG101\"");
    }

    #[test]
    fn evidence_skips_empty_optional_fields() {
        let evidence = Evidence {
            scope: Some(EvidenceScope::Global),
            field: Some("unknown".to_owned()),
            actual: Some("1 field".to_owned()),
            ..Evidence::default()
        };

        let json = serde_json::to_string(&evidence).expect("serialize");
        assert_eq!(
            json,
            r#"{"scope":"global","field":"unknown","actual":"1 field"}"#
        );
    }
}
