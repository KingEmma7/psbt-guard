use crate::model::{AnalysisContext, Evidence, Finding, FindingCode, Severity};

use super::AnalysisRule;

/// Successful absolute-fee accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AbsoluteFee {
    pub(crate) input_total_sat: u64,
    pub(crate) output_total_sat: u64,
    pub(crate) fee_sat: u64,
}

/// Why fee accounting could not produce a non-negative absolute fee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FeeCalculationError {
    MissingUtxo {
        input_index: usize,
    },
    MismatchedNonWitnessUtxo {
        input_index: usize,
    },
    InvalidPreviousOutput {
        input_index: usize,
        vout: u32,
    },
    AmountOverflow,
    OutputsExceedInputs {
        input_total_sat: u64,
        output_total_sat: u64,
    },
}

impl std::fmt::Display for FeeCalculationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingUtxo { input_index } => {
                write!(f, "input #{input_index} has no funding UTXO")
            }
            Self::MismatchedNonWitnessUtxo { input_index } => write!(
                f,
                "input #{input_index} non_witness_utxo txid does not match its previous output"
            ),
            Self::InvalidPreviousOutput { input_index, vout } => write!(
                f,
                "input #{input_index} references missing non_witness_utxo output #{vout}"
            ),
            Self::AmountOverflow => f.write_str("transaction amount totals overflowed u64"),
            Self::OutputsExceedInputs {
                input_total_sat,
                output_total_sat,
            } => write!(
                f,
                "output total {output_total_sat} sat exceeds input total {input_total_sat} sat"
            ),
        }
    }
}

pub(crate) fn calculate_absolute_fee(
    ctx: &AnalysisContext,
) -> Result<AbsoluteFee, FeeCalculationError> {
    let psbt = ctx.psbt();
    let mut input_total_sat = 0_u64;

    for (input_index, (tx_input, psbt_input)) in psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .enumerate()
    {
        let value_sat = if let Some(output) = &psbt_input.witness_utxo {
            output.value.to_sat()
        } else if let Some(transaction) = &psbt_input.non_witness_utxo {
            if transaction.compute_txid() != tx_input.previous_output.txid {
                return Err(FeeCalculationError::MismatchedNonWitnessUtxo { input_index });
            }
            transaction
                .output
                .get(tx_input.previous_output.vout as usize)
                .ok_or(FeeCalculationError::InvalidPreviousOutput {
                    input_index,
                    vout: tx_input.previous_output.vout,
                })?
                .value
                .to_sat()
        } else {
            return Err(FeeCalculationError::MissingUtxo { input_index });
        };

        input_total_sat = input_total_sat
            .checked_add(value_sat)
            .ok_or(FeeCalculationError::AmountOverflow)?;
    }

    let output_total_sat = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0_u64, |total, output| {
            total
                .checked_add(output.value.to_sat())
                .ok_or(FeeCalculationError::AmountOverflow)
        })?;

    let fee_sat = input_total_sat.checked_sub(output_total_sat).ok_or(
        FeeCalculationError::OutputsExceedInputs {
            input_total_sat,
            output_total_sat,
        },
    )?;

    Ok(AbsoluteFee {
        input_total_sat,
        output_total_sat,
        fee_sat,
    })
}

pub struct AbsoluteFeeRule;

impl AnalysisRule for AbsoluteFeeRule {
    fn code(&self) -> FindingCode {
        FindingCode::Pg201
    }

    fn name(&self) -> &'static str {
        "Absolute fee calculation"
    }

    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        match calculate_absolute_fee(ctx) {
            Ok(fee) => vec![Finding {
                code: self.code(),
                severity: Severity::Info,
                title: "Absolute fee calculated".to_owned(),
                explanation: format!(
                    "All funding UTXOs are present. The transaction pays an absolute fee of {} sat.",
                    fee.fee_sat
                ),
                evidence: Evidence::global(
                    "absolute_fee",
                    format!(
                        "input_total_sat={} output_total_sat={} fee_sat={}",
                        fee.input_total_sat, fee.output_total_sat, fee.fee_sat
                    ),
                ),
                suggested_action: "Compare the fee with your declared ceiling and expected transaction size before signing."
                    .to_owned(),
            }],
            Err(error @ FeeCalculationError::OutputsExceedInputs { .. }) => vec![Finding {
                code: self.code(),
                severity: Severity::Critical,
                title: "Invalid transaction value balance".to_owned(),
                explanation: format!("Absolute fee accounting failed because {error}."),
                evidence: Evidence::global("absolute_fee", error.to_string()),
                suggested_action: "Do not sign; ask the PSBT creator to correct the transaction inputs and outputs."
                    .to_owned(),
            }],
            Err(error) => vec![Finding {
                code: self.code(),
                severity: Severity::Warning,
                title: "Absolute fee unavailable".to_owned(),
                explanation: format!("The absolute fee could not be calculated because {error}."),
                evidence: Evidence::global("absolute_fee", error.to_string()),
                suggested_action: "Require complete, matching funding UTXO data before relying on fee verification."
                    .to_owned(),
            }],
        }
    }
}
