//! Core analysis vocabulary: severities, finding codes, and findings.
//!
//! Only the settled, load-bearing types are defined at milestone M0. The
//! richer types (`AnalysisContext`, `Finding`, `FindingCode`) land in M1
//! together with the PSBT parsing that gives them meaning.

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

#[cfg(test)]
mod tests {
    use super::Severity;

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
}
