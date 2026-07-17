use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};
use crate::rules::AnalysisRule;

/// PG102: surface unknown PSBT fields.
pub struct UnknownFieldsRule;

impl AnalysisRule for UnknownFieldsRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg102
    }

    fn name(&self) -> &'static str {
        "Unknown global/input/output fields"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let psbt = ctx.psbt();
        let mut findings = Vec::new();

        if !psbt.unknown.is_empty() {
            findings.push(self.finding(Evidence::global(
                "unknown",
                format!("{} field(s)", psbt.unknown.len()),
            )));
        }

        for (index, input) in psbt.inputs.iter().enumerate() {
            if !input.unknown.is_empty() {
                findings.push(self.finding(Evidence::input(
                    index,
                    "unknown",
                    format!("{} field(s)", input.unknown.len()),
                )));
            }
        }

        for (index, output) in psbt.outputs.iter().enumerate() {
            if !output.unknown.is_empty() {
                findings.push(self.finding(Evidence::output(
                    index,
                    "unknown",
                    format!("{} field(s)", output.unknown.len()),
                )));
            }
        }

        findings
    }
}

impl UnknownFieldsRule {
    fn finding(&self, evidence: Evidence) -> Finding {
        Finding {
            code: self.code(),
            severity: Severity::Warning,
            title: "PSBT contains unknown fields".to_owned(),
            explanation: "This PSBT includes key-value fields that rust-bitcoin does not recognize as standard PSBT fields.".to_owned(),
            evidence,
            suggested_action: "Review the PSBT source and decide whether these unknown fields are expected before signing.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::psbt::raw;

    use super::UnknownFieldsRule;
    use crate::model::{AnalysisContext, FindingCode, Severity};
    use crate::rules::AnalysisRule;
    use crate::test_support::minimal_psbt_with_witness_utxo;

    #[test]
    fn passes_when_no_unknown_fields_exist() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt_with_witness_utxo());

        assert!(UnknownFieldsRule.evaluate(&ctx).is_empty());
    }

    #[test]
    fn warns_for_unknown_input_fields() {
        let mut psbt = minimal_psbt_with_witness_utxo();
        psbt.inputs[0].unknown.insert(
            raw::Key {
                type_value: 0x42,
                key: vec![0x01],
            },
            vec![0x02],
        );

        let ctx = AnalysisContext::from_psbt(psbt);
        let findings = UnknownFieldsRule.evaluate(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::Pg102);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].evidence.input_index, Some(0));
    }
}
