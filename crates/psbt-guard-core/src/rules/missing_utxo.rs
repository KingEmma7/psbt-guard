use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};
use crate::rules::AnalysisRule;

/// PG101: inputs must include enough UTXO information for fee review.
pub struct MissingUtxoRule;

impl AnalysisRule for MissingUtxoRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg101
    }

    fn name(&self) -> &'static str {
        "Missing UTXO information"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        ctx.psbt()
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.witness_utxo.is_none() && input.non_witness_utxo.is_none())
            .map(|(input_index, _)| Finding {
                code: self.code(),
                severity: Severity::Warning,
                title: "Input is missing UTXO information".to_owned(),
                explanation: "This input does not include witness_utxo or non_witness_utxo, so a signer cannot independently confirm the amount being spent by that input.".to_owned(),
                evidence: Evidence::input(
                    input_index,
                    "witness_utxo/non_witness_utxo",
                    "both missing",
                ),
                suggested_action:
                    "Ask the PSBT creator to include UTXO information before reviewing fees or signing.".to_owned(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::MissingUtxoRule;
    use crate::model::{AnalysisContext, FindingCode, Severity};
    use crate::rules::AnalysisRule;
    use crate::test_support::{minimal_psbt, minimal_psbt_with_witness_utxo};

    #[test]
    fn passes_when_input_has_witness_utxo() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt_with_witness_utxo());

        assert!(MissingUtxoRule.evaluate(&ctx).is_empty());
    }

    #[test]
    fn warns_when_input_has_no_utxo_information() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt());
        let findings = MissingUtxoRule.evaluate(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::Pg101);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].evidence.input_index, Some(0));
    }
}
