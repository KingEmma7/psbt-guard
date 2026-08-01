//! The extensible rule engine.
//!
//! Each rule is a pure read-only check from [`AnalysisContext`] to zero or more
//! [`Finding`] values.

mod absolute_fee;
mod input_status;
mod max_fee;
mod missing_utxo;
mod proprietary_fields;
mod recipient_address;
mod recipient_amount;
mod sighash;
mod undeclared_output;
mod unknown_fields;

use crate::model::{AnalysisContext, Finding, FindingCode};

pub use absolute_fee::AbsoluteFeeRule;
pub use input_status::InputStatusRule;
pub use max_fee::MaximumFeeRule;
pub use missing_utxo::MissingUtxoRule;
pub use proprietary_fields::ProprietaryFieldsRule;
pub use recipient_address::RecipientAddressRule;
pub use recipient_amount::RecipientAmountRule;
pub use sighash::SighashRule;
pub use undeclared_output::UndeclaredOutputRule;
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

/// Structural and intent-aware rules in stable catalogue order.
pub fn verification_registry() -> Vec<Box<dyn AnalysisRule>> {
    let mut rules = structural_registry();
    rules.extend([
        Box::new(AbsoluteFeeRule) as Box<dyn AnalysisRule>,
        Box::new(RecipientAddressRule),
        Box::new(RecipientAmountRule),
        Box::new(UndeclaredOutputRule),
        Box::new(MaximumFeeRule),
    ]);
    rules
}

#[cfg(test)]
mod tests {
    use super::{structural_registry, verification_registry};
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

    #[test]
    fn verification_registry_order_matches_catalogue_order() {
        let codes = verification_registry()
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
                FindingCode::Pg201,
                FindingCode::Pg301,
                FindingCode::Pg302,
                FindingCode::Pg303,
                FindingCode::Pg304,
            ]
        );
    }
}

#[cfg(test)]
mod m2_tests;
