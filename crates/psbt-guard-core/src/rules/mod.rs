//! The extensible rule engine.
//!
//! Each rule is a pure read-only check from [`AnalysisContext`] to zero or more
//! [`Finding`] values.

mod input_status;
mod missing_utxo;
mod proprietary_fields;
mod sighash;
mod unknown_fields;

use crate::model::{AnalysisContext, Finding, FindingCode};

pub use input_status::InputStatusRule;
pub use missing_utxo::MissingUtxoRule;
pub use proprietary_fields::ProprietaryFieldsRule;
pub use sighash::SighashRule;
pub use unknown_fields::UnknownFieldsRule;

/// One analysis rule.
pub trait AnalysisRule {
    /// Stable machine identifier for the rule.
    fn code(&self) -> FindingCode;
    /// Human-readable rule name.
    fn name(&self) -> &'static str;
    /// Evaluate the rule.
    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding>;
}

/// Structural PSBT rules that do not require an intent manifest.
pub fn structural_registry() -> Vec<Box<dyn AnalysisRule>> {
    vec![
        Box::new(MissingUtxoRule),
        Box::new(UnknownFieldsRule),
        Box::new(ProprietaryFieldsRule),
        Box::new(SighashRule),
        Box::new(InputStatusRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::structural_registry;
    use crate::model::FindingCode;

    #[test]
    fn registry_order_matches_catalogue_order() {
        let codes = structural_registry()
            .iter()
            .map(|rule| rule.code())
            .collect::<Vec<_>>();

        assert_eq!(
            codes,
            vec![
                FindingCode::Pg101,
                FindingCode::Pg102,
                FindingCode::Pg103,
                FindingCode::Pg104,
                FindingCode::Pg105,
            ]
        );
    }
}
