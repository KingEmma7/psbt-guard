use bitcoin::Address;

use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};

use super::AnalysisRule;

pub struct UndeclaredOutputRule;

impl AnalysisRule for UndeclaredOutputRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg303
    }

    fn name(&self) -> &'static str {
        "Undeclared output"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let Some(intent) = ctx.intent() else {
            return Vec::new();
        };

        let undeclared =
            ctx.psbt()
                .unsigned_tx
                .output
                .iter()
                .enumerate()
                .filter(|(_, output)| {
                    !intent.recipients().iter().any(|recipient| {
                        output.script_pubkey == recipient.address().script_pubkey()
                    })
                })
                .collect::<Vec<_>>();

        let undeclared_count = undeclared.len();
        if undeclared_count <= intent.change_policy().max_change_outputs() {
            return Vec::new();
        }

        undeclared
            .into_iter()
            .map(|(output_index, output)| {
                let destination = Address::from_script(&output.script_pubkey, intent.network())
                    .map(|address| address.to_string())
                    .unwrap_or_else(|_| format!("script_hex={}", script_hex(&output.script_pubkey)));
                Finding {
                    code: self.code(),
                    severity: Severity::Violation,
                    title: "Undeclared output exceeds change allowance".to_owned(),
                    explanation: format!(
                        "The transaction has {} output(s) not assigned to declared recipients, exceeding the allowed {} change output(s).",
                        undeclared_count,
                        intent.change_policy().max_change_outputs()
                    ),
                    evidence: Evidence::output(
                        output_index,
                        "undeclared_output",
                        format!(
                            "destination={} amount_sat={} undeclared_count={} max_change_outputs={}",
                            destination,
                            output.value.to_sat(),
                            undeclared_count,
                            intent.change_policy().max_change_outputs()
                        ),
                    ),
                    suggested_action: "Do not sign until every extra output is identified; count-based change allowance does not prove wallet ownership."
                        .to_owned(),
                }
            })
            .collect()
    }
}

fn script_hex(script: &bitcoin::Script) -> String {
    script
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
