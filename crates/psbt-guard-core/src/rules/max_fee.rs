use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};

use super::absolute_fee::calculate_absolute_fee;
use super::AnalysisRule;

pub struct MaximumFeeRule;

impl AnalysisRule for MaximumFeeRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg304
    }

    fn name(&self) -> &'static str {
        "Maximum absolute fee"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let Some(intent) = ctx.intent() else {
            return Vec::new();
        };
        let maximum_sat = intent.fee_policy().max_absolute_fee_sat();

        match calculate_absolute_fee(ctx) {
            Ok(fee) if fee.fee_sat <= maximum_sat => Vec::new(),
            Ok(fee) => vec![Finding {
                code: self.code(),
                severity: Severity::Violation,
                title: "Maximum absolute fee exceeded".to_owned(),
                explanation: format!(
                    "The transaction fee is {} sat, exceeding the declared maximum of {} sat.",
                    fee.fee_sat, maximum_sat
                ),
                evidence: Evidence::global(
                    "max_absolute_fee",
                    format!("fee_sat={} max_absolute_fee_sat={maximum_sat}", fee.fee_sat),
                ),
                suggested_action: "Do not sign until the fee is reduced or you independently update the intent policy."
                    .to_owned(),
            }],
            Err(error) => vec![Finding {
                code: self.code(),
                severity: Severity::Violation,
                title: "Maximum absolute fee could not be verified".to_owned(),
                explanation: format!(
                    "The declared fee ceiling of {maximum_sat} sat could not be enforced because {error}."
                ),
                evidence: Evidence::global(
                    "max_absolute_fee",
                    format!("max_absolute_fee_sat={maximum_sat}; unavailable: {error}"),
                ),
                suggested_action: "Do not sign until complete, matching UTXO data makes fee verification possible."
                    .to_owned(),
            }],
        }
    }
}
