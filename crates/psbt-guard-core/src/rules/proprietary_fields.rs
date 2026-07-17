use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};
use crate::rules::AnalysisRule;

/// PG103: surface proprietary PSBT fields.
pub struct ProprietaryFieldsRule;

impl AnalysisRule for ProprietaryFieldsRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg103
    }

    fn name(&self) -> &'static str {
        "Proprietary global/input/output fields"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let psbt = ctx.psbt();
        let mut findings = Vec::new();

        if !psbt.proprietary.is_empty() {
            findings.push(self.finding(Evidence::global(
                "proprietary",
                format!("{} field(s)", psbt.proprietary.len()),
            )));
        }

        for (index, input) in psbt.inputs.iter().enumerate() {
            if !input.proprietary.is_empty() {
                findings.push(self.finding(Evidence::input(
                    index,
                    "proprietary",
                    format!("{} field(s)", input.proprietary.len()),
                )));
            }
        }

        for (index, output) in psbt.outputs.iter().enumerate() {
            if !output.proprietary.is_empty() {
                findings.push(self.finding(Evidence::output(
                    index,
                    "proprietary",
                    format!("{} field(s)", output.proprietary.len()),
                )));
            }
        }

        findings
    }
}

impl ProprietaryFieldsRule {
    fn finding(&self, evidence: Evidence) -> Finding {
        Finding {
            code: self.code(),
            severity: Severity::Warning,
            title: "PSBT contains proprietary fields".to_owned(),
            explanation: "This PSBT includes application-specific proprietary fields. They can be legitimate, but they are not part of the standard fields psbt-guard interprets.".to_owned(),
            evidence,
            suggested_action: "Confirm the wallet or coordinator that created the PSBT intentionally added these proprietary fields.".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::psbt::raw;

    use super::ProprietaryFieldsRule;
    use crate::model::{AnalysisContext, FindingCode, Severity};
    use crate::rules::AnalysisRule;
    use crate::test_support::minimal_psbt_with_witness_utxo;

    #[test]
    fn passes_when_no_proprietary_fields_exist() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt_with_witness_utxo());

        assert!(ProprietaryFieldsRule.evaluate(&ctx).is_empty());
    }

    #[test]
    fn warns_for_proprietary_output_fields() {
        let mut psbt = minimal_psbt_with_witness_utxo();
        psbt.outputs[0].proprietary.insert(
            raw::ProprietaryKey {
                prefix: b"psbt-guard-test".to_vec(),
                subtype: 0,
                key: vec![0x01],
            },
            vec![0x02],
        );

        let ctx = AnalysisContext::from_psbt(psbt);
        let findings = ProprietaryFieldsRule.evaluate(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::Pg103);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].evidence.output_index, Some(0));
    }
}
