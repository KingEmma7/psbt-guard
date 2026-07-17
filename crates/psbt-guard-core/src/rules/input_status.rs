use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};
use crate::rules::AnalysisRule;

/// PG105: report input signature/finalization status.
pub struct InputStatusRule;

impl AnalysisRule for InputStatusRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg105
    }

    fn name(&self) -> &'static str {
        "Input finalization / partial-signature status"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        ctx.psbt()
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(input_index, input)| {
                let has_final = input.final_script_sig.is_some()
                    || input.final_script_witness.is_some();
                let partial_signature_count = input.partial_sigs.len()
                    + input.tap_script_sigs.len()
                    + usize::from(input.tap_key_sig.is_some());

                (has_final || partial_signature_count > 0).then(|| {
                    let status = if has_final {
                        "finalized"
                    } else {
                        "partially signed"
                    };

                    Finding {
                        code: self.code(),
                        severity: Severity::Info,
                        title: "Input already has signature material".to_owned(),
                        explanation: "This input contains either final script data or partial signatures. psbt-guard reports this as context for review and does not modify it.".to_owned(),
                        evidence: Evidence::input(
                            input_index,
                            "input_status",
                            format!("{status}; {partial_signature_count} partial signature(s)"),
                        ),
                        suggested_action:
                            "Confirm this signing state is expected for the review step you are performing.".to_owned(),
                    }
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::ScriptBuf;

    use super::InputStatusRule;
    use crate::model::{AnalysisContext, FindingCode, Severity};
    use crate::rules::AnalysisRule;
    use crate::test_support::minimal_psbt_with_witness_utxo;

    #[test]
    fn passes_when_input_has_no_signature_material() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt_with_witness_utxo());

        assert!(InputStatusRule.evaluate(&ctx).is_empty());
    }

    #[test]
    fn reports_finalized_input_as_info() {
        let mut psbt = minimal_psbt_with_witness_utxo();
        psbt.inputs[0].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));

        let ctx = AnalysisContext::from_psbt(psbt);
        let findings = InputStatusRule.evaluate(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::Pg105);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].evidence.input_index, Some(0));
    }
}
