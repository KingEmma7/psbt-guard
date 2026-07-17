use bitcoin::EcdsaSighashType;

use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};
use crate::rules::AnalysisRule;

/// PG104: flag explicit non-default sighash modes.
pub struct SighashRule;

impl AnalysisRule for SighashRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg104
    }

    fn name(&self) -> &'static str {
        "Invalid or non-standard sighash information"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        ctx.psbt()
            .inputs
            .iter()
            .enumerate()
            .filter_map(|(input_index, input)| {
                let sighash = input.sighash_type?;
                (!is_safe_default_sighash(sighash.to_u32())).then(|| Finding {
                    code: self.code(),
                    severity: Severity::Critical,
                    title: "Input requests a non-default sighash mode".to_owned(),
                    explanation: "A non-default sighash mode can allow parts of the transaction to be changed after this input is signed.".to_owned(),
                    evidence: Evidence::input(
                        input_index,
                        "sighash_type",
                        sighash.to_string(),
                    ),
                    suggested_action:
                        "Do not sign until you understand why this PSBT needs a non-default sighash mode.".to_owned(),
                })
            })
            .collect()
    }
}

fn is_safe_default_sighash(raw: u32) -> bool {
    raw == 0 || raw == EcdsaSighashType::All as u32
}

#[cfg(test)]
mod tests {
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::EcdsaSighashType;

    use super::SighashRule;
    use crate::model::{AnalysisContext, FindingCode, Severity};
    use crate::rules::AnalysisRule;
    use crate::test_support::minimal_psbt_with_witness_utxo;

    #[test]
    fn passes_when_sighash_is_absent_or_default_all() {
        let ctx = AnalysisContext::from_psbt(minimal_psbt_with_witness_utxo());
        assert!(SighashRule.evaluate(&ctx).is_empty());

        let mut psbt = minimal_psbt_with_witness_utxo();
        psbt.inputs[0].sighash_type = Some(EcdsaSighashType::All.into());
        let ctx = AnalysisContext::from_psbt(psbt);

        assert!(SighashRule.evaluate(&ctx).is_empty());
    }

    #[test]
    fn critical_for_non_default_sighash() {
        let mut psbt = minimal_psbt_with_witness_utxo();
        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(2));

        let ctx = AnalysisContext::from_psbt(psbt);
        let findings = SighashRule.evaluate(&ctx);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::Pg104);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].evidence.input_index, Some(0));
    }
}
