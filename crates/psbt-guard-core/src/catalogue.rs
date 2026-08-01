//! Stable, machine-owned explanations for every finding code.

use crate::model::{FindingCode, Severity};

/// Human-readable catalogue entry used by the CLI and other callers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleExplanation {
    /// Permanent finding identifier.
    pub code: FindingCode,
    /// Short rule name.
    pub name: &'static str,
    /// Normal severity; individual findings may escalate for malformed data.
    pub typical_severity: Severity,
    /// Plain-language description of the check.
    pub what_it_checks: &'static str,
    /// Threat or review failure the check addresses.
    pub why_it_matters: &'static str,
    /// Default reviewer response.
    pub suggested_action: &'static str,
}

/// Return the catalogue entry for an implemented finding code.
pub fn explanation(code: FindingCode) -> RuleExplanation {
    match code {
        FindingCode::Pg101 => RuleExplanation {
            code,
            name: "Missing UTXO information",
            typical_severity: Severity::Warning,
            what_it_checks: "Every input includes witness_utxo or non_witness_utxo funding data.",
            why_it_matters: "Without the spent output value, the signer cannot independently calculate the transaction fee.",
            suggested_action: "Require complete UTXO information before reviewing fees or signing.",
        },
        FindingCode::Pg102 => RuleExplanation {
            code,
            name: "Unknown PSBT fields",
            typical_severity: Severity::Warning,
            what_it_checks: "Global, input and output unknown-field maps are empty.",
            why_it_matters: "psbt-guard cannot interpret unknown extensions for the reviewer.",
            suggested_action: "Confirm the PSBT source and independently review why the fields are present.",
        },
        FindingCode::Pg103 => RuleExplanation {
            code,
            name: "Proprietary PSBT fields",
            typical_severity: Severity::Warning,
            what_it_checks: "Global, input and output proprietary-field maps are empty.",
            why_it_matters: "Application-specific metadata may be legitimate but is outside standard PSBT semantics.",
            suggested_action: "Confirm the wallet or coordinator intentionally added each proprietary field.",
        },
        FindingCode::Pg104 => RuleExplanation {
            code,
            name: "Non-standard sighash information",
            typical_severity: Severity::Critical,
            what_it_checks: "Explicit sighash values use safe defaults: ECDSA SIGHASH_ALL or Taproot SIGHASH_DEFAULT.",
            why_it_matters: "Other sighash modes can leave parts of the transaction changeable after signing.",
            suggested_action: "Do not sign until the non-default sighash requirement is fully understood.",
        },
        FindingCode::Pg105 => RuleExplanation {
            code,
            name: "Input signing status",
            typical_severity: Severity::Info,
            what_it_checks: "Inputs containing final scripts, partial ECDSA signatures or Taproot signatures.",
            why_it_matters: "Existing signature material shows where the PSBT is in its signing workflow.",
            suggested_action: "Confirm the signing state is expected for this review step.",
        },
        FindingCode::Pg201 => RuleExplanation {
            code,
            name: "Absolute fee calculation",
            typical_severity: Severity::Info,
            what_it_checks: "Funding input totals minus transaction output totals, reconciling both UTXO fields and rejecting witness-only legacy funding data.",
            why_it_matters: "The fee is implicit and must be calculated before it can be reviewed against policy.",
            suggested_action: "Compare the calculated fee with the declared ceiling and expected transaction size.",
        },
        FindingCode::Pg301 => RuleExplanation {
            code,
            name: "Declared recipient address missing",
            typical_severity: Severity::Violation,
            what_it_checks: "Every recipient address in the intent has a matching transaction output script.",
            why_it_matters: "A missing intended address can indicate recipient substitution.",
            suggested_action: "Do not sign until the independently verified recipient appears.",
        },
        FindingCode::Pg302 => RuleExplanation {
            code,
            name: "Recipient amount mismatch",
            typical_severity: Severity::Violation,
            what_it_checks: "Aggregate output value paid to each declared recipient matches its amount and tolerance.",
            why_it_matters: "A correct recipient can still receive an incorrect amount.",
            suggested_action: "Do not sign until the payment amount matches independently confirmed intent.",
        },
        FindingCode::Pg303 => RuleExplanation {
            code,
            name: "Undeclared output",
            typical_severity: Severity::Violation,
            what_it_checks: "Outputs not assigned to declared recipients do not exceed the count-based change allowance.",
            why_it_matters: "Extra outputs can redirect funds, and a count allowance does not prove change ownership.",
            suggested_action: "Identify every extra output before signing; keep the allowance minimal.",
        },
        FindingCode::Pg304 => RuleExplanation {
            code,
            name: "Maximum absolute fee",
            typical_severity: Severity::Violation,
            what_it_checks: "The calculated fee does not exceed max_absolute_fee_sat and remains independently calculable.",
            why_it_matters: "An excessive or concealed fee can siphon transaction value.",
            suggested_action: "Do not sign until the fee is calculable and within the declared ceiling.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::explanation;
    use crate::model::FindingCode;

    #[test]
    fn every_finding_code_has_a_stable_explanation() {
        let codes = [
            FindingCode::Pg101,
            FindingCode::Pg102,
            FindingCode::Pg103,
            FindingCode::Pg104,
            FindingCode::Pg105,
            FindingCode::Pg201,
            FindingCode::Pg301,
            FindingCode::Pg302,
            FindingCode::Pg303,
            FindingCode::Pg304,
        ];

        for code in codes {
            let entry = explanation(code);
            assert_eq!(entry.code, code);
            assert!(!entry.name.is_empty());
            assert!(!entry.what_it_checks.is_empty());
            assert!(!entry.why_it_matters.is_empty());
            assert!(!entry.suggested_action.is_empty());
        }
    }
}
