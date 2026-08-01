use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};

use super::AnalysisRule;

pub struct RecipientAddressRule;

impl AnalysisRule for RecipientAddressRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg301
    }

    fn name(&self) -> &'static str {
        "Declared recipient address"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let Some(intent) = ctx.intent() else {
            return Vec::new();
        };

        intent
            .recipients()
            .iter()
            .filter(|recipient| {
                let expected_script = recipient.address().script_pubkey();
                !ctx.psbt()
                    .unsigned_tx
                    .output
                    .iter()
                    .any(|output| output.script_pubkey == expected_script)
            })
            .map(|recipient| Finding {
                code: self.code(),
                severity: Severity::Violation,
                title: "Declared recipient address missing".to_owned(),
                explanation: format!(
                    "No transaction output pays declared recipient {}. This can indicate recipient substitution or an incomplete manifest.",
                    recipient.address()
                ),
                evidence: Evidence::global(
                    "recipient_address",
                    format!("{} not found", recipient.address()),
                ),
                suggested_action: "Do not sign until the intended recipient appears exactly as independently verified."
                    .to_owned(),
            })
            .collect()
    }
}
