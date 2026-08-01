use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};

use super::AnalysisRule;

pub struct RecipientAmountRule;

impl AnalysisRule for RecipientAmountRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg302
    }

    fn name(&self) -> &'static str {
        "Recipient amount"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let Some(intent) = ctx.intent() else {
            return Vec::new();
        };
        let outputs = &ctx.psbt().unsigned_tx.output;
        let mut findings = Vec::new();

        for recipient in intent.recipients() {
            let expected_script = recipient.address().script_pubkey();
            let matching = outputs
                .iter()
                .enumerate()
                .filter(|(_, output)| output.script_pubkey == expected_script)
                .collect::<Vec<_>>();

            if matching.is_empty() {
                continue;
            }

            let actual_sat = matching.iter().try_fold(0_u64, |total, (_, output)| {
                total.checked_add(output.value.to_sat())
            });
            let Some(actual_sat) = actual_sat else {
                findings.push(Finding {
                    code: self.code(),
                    severity: Severity::Critical,
                    title: "Recipient amount overflow".to_owned(),
                    explanation: format!(
                        "Amounts paid to {} could not be summed without overflow.",
                        recipient.address()
                    ),
                    evidence: Evidence::output(
                        matching[0].0,
                        "recipient_amount",
                        "aggregate amount overflow",
                    ),
                    suggested_action: "Do not sign; treat the transaction as malformed.".to_owned(),
                });
                continue;
            };

            if actual_sat.abs_diff(recipient.amount_sat()) > recipient.amount_tolerance_sat() {
                findings.push(Finding {
                    code: self.code(),
                    severity: Severity::Violation,
                    title: "Recipient amount mismatch".to_owned(),
                    explanation: format!(
                        "Recipient {} receives {} sat in total; the declared amount is {} sat with {} sat tolerance.",
                        recipient.address(),
                        actual_sat,
                        recipient.amount_sat(),
                        recipient.amount_tolerance_sat()
                    ),
                    evidence: Evidence::output(
                        matching[0].0,
                        "recipient_amount",
                        format!(
                            "address={} expected_sat={} actual_sat={} tolerance_sat={}",
                            recipient.address(),
                            recipient.amount_sat(),
                            actual_sat,
                            recipient.amount_tolerance_sat()
                        ),
                    ),
                    suggested_action: "Do not sign until the amount matches the independently confirmed payment intent."
                        .to_owned(),
                });
            }
        }

        findings
    }
}
