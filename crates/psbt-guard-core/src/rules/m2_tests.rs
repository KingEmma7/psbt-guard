use std::str::FromStr;

use bitcoin::absolute;
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::transaction;
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::intent::parse_intent_toml;
use crate::model::{AnalysisContext, FindingCode, Severity};

use super::absolute_fee::{calculate_absolute_fee, FeeCalculationError};
use super::{
    AbsoluteFeeRule, AnalysisRule, MaximumFeeRule, RecipientAddressRule, RecipientAmountRule,
    UndeclaredOutputRule,
};

const RECIPIENT: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
const OTHER: &str = "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";

fn checked_address(value: &str) -> Address<NetworkChecked> {
    Address::<NetworkUnchecked>::from_str(value)
        .expect("valid address")
        .require_network(Network::Testnet)
        .expect("testnet address")
}

fn segwit_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend([0_u8; 20]);
    ScriptBuf::from_bytes(bytes)
}

fn alternate_segwit_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend([1_u8; 20]);
    ScriptBuf::from_bytes(bytes)
}

fn intent(
    recipient: &str,
    amount_sat: u64,
    tolerance_sat: u64,
    max_fee_sat: u64,
    max_change_outputs: usize,
) -> crate::intent::Intent {
    parse_intent_toml(&format!(
        r#"network = "testnet"

[[recipients]]
address = "{recipient}"
amount_sat = {amount_sat}
amount_tolerance_sat = {tolerance_sat}

[fee_policy]
max_absolute_fee_sat = {max_fee_sat}

[change_policy]
max_change_outputs = {max_change_outputs}
"#
    ))
    .expect("valid test intent")
}

fn psbt(input_sat: Option<u64>, outputs: Vec<(&str, u64)>) -> Psbt {
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: outputs
            .into_iter()
            .map(|(address, amount_sat)| TxOut {
                value: Amount::from_sat(amount_sat),
                script_pubkey: checked_address(address).script_pubkey(),
            })
            .collect(),
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("valid unsigned transaction");
    psbt.inputs[0].witness_utxo = input_sat.map(|amount_sat| TxOut {
        value: Amount::from_sat(amount_sat),
        script_pubkey: segwit_script(),
    });
    psbt
}

fn psbt_with_both_utxos(actual_input_sat: u64, witness_input_sat: u64) -> Psbt {
    let previous_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(actual_input_sat),
            script_pubkey: segwit_script(),
        }],
    };
    let previous_output = OutPoint {
        txid: previous_tx.compute_txid(),
        vout: 0,
    };
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(60_000),
            script_pubkey: checked_address(RECIPIENT).script_pubkey(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("valid unsigned transaction");
    psbt.inputs[0].non_witness_utxo = Some(previous_tx);
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(witness_input_sat),
        script_pubkey: segwit_script(),
    });
    psbt
}

fn context(
    input_sat: Option<u64>,
    outputs: Vec<(&str, u64)>,
    declared_amount_sat: u64,
    max_fee_sat: u64,
    max_change_outputs: usize,
) -> AnalysisContext {
    AnalysisContext::with_intent(
        psbt(input_sat, outputs),
        intent(
            RECIPIENT,
            declared_amount_sat,
            0,
            max_fee_sat,
            max_change_outputs,
        ),
    )
}

#[test]
fn pg201_reports_absolute_fee_when_all_utxos_are_present() {
    let ctx = context(
        Some(100_000),
        vec![(RECIPIENT, 60_000), (OTHER, 39_000)],
        60_000,
        2_000,
        1,
    );

    let findings = AbsoluteFeeRule.evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::Pg201);
    assert_eq!(findings[0].severity, Severity::Info);
    assert_eq!(
        findings[0].evidence.actual.as_deref(),
        Some("input_total_sat=100000 output_total_sat=99000 fee_sat=1000")
    );
}

#[test]
fn pg201_warns_when_fee_is_unavailable() {
    let ctx = context(None, vec![(RECIPIENT, 60_000)], 60_000, 2_000, 0);

    let findings = AbsoluteFeeRule.evaluate(&ctx);
    assert_eq!(findings[0].severity, Severity::Warning);
}

#[test]
fn fee_accounting_rejects_conflicting_witness_and_non_witness_utxos() {
    let ctx = AnalysisContext::from_psbt(psbt_with_both_utxos(100_000, 61_000));

    assert!(matches!(
        calculate_absolute_fee(&ctx),
        Err(FeeCalculationError::InconsistentUtxoData { input_index: 0 })
    ));
}

#[test]
fn fee_accounting_accepts_matching_witness_and_non_witness_utxos() {
    let ctx = AnalysisContext::from_psbt(psbt_with_both_utxos(61_000, 61_000));

    let fee = calculate_absolute_fee(&ctx).expect("matching UTXO data");
    assert_eq!(fee.fee_sat, 1_000);
}

#[test]
fn fee_accounting_rejects_witness_only_legacy_funding_data() {
    let mut psbt = psbt(Some(61_000), vec![(RECIPIENT, 60_000)]);
    psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("witness UTXO")
        .script_pubkey = ScriptBuf::new();
    let ctx = AnalysisContext::from_psbt(psbt);

    assert!(matches!(
        calculate_absolute_fee(&ctx),
        Err(FeeCalculationError::WitnessUtxoForLegacyInput { input_index: 0 })
    ));
}

#[test]
fn fee_accounting_accepts_witness_only_wrapped_segwit_funding_data() {
    let mut psbt = psbt(Some(61_000), vec![(RECIPIENT, 60_000)]);
    let redeem_script = segwit_script();
    psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("witness UTXO")
        .script_pubkey = redeem_script.to_p2sh();
    psbt.inputs[0].redeem_script = Some(redeem_script);
    let ctx = AnalysisContext::from_psbt(psbt);

    let fee = calculate_absolute_fee(&ctx).expect("matching wrapped SegWit funding data");
    assert_eq!(fee.fee_sat, 1_000);
}

#[test]
fn fee_accounting_rejects_mismatched_wrapped_segwit_redeem_script() {
    let mut psbt = psbt(Some(61_000), vec![(RECIPIENT, 60_000)]);
    psbt.inputs[0]
        .witness_utxo
        .as_mut()
        .expect("witness UTXO")
        .script_pubkey = segwit_script().to_p2sh();
    psbt.inputs[0].redeem_script = Some(alternate_segwit_script());
    let ctx = AnalysisContext::from_psbt(psbt);

    assert!(matches!(
        calculate_absolute_fee(&ctx),
        Err(FeeCalculationError::WitnessUtxoForLegacyInput { input_index: 0 })
    ));
}

#[test]
fn pg301_passes_when_declared_recipient_is_present() {
    let ctx = context(Some(61_000), vec![(RECIPIENT, 60_000)], 60_000, 2_000, 0);
    assert!(RecipientAddressRule.evaluate(&ctx).is_empty());
}

#[test]
fn pg301_blocks_when_declared_recipient_is_missing() {
    let ctx = context(Some(61_000), vec![(OTHER, 60_000)], 60_000, 2_000, 1);

    let findings = RecipientAddressRule.evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::Pg301);
    assert_eq!(findings[0].severity, Severity::Violation);
}

#[test]
fn pg302_passes_for_amount_within_tolerance() {
    let psbt = psbt(Some(61_000), vec![(RECIPIENT, 60_050)]);
    let intent = intent(RECIPIENT, 60_000, 50, 2_000, 0);
    let ctx = AnalysisContext::with_intent(psbt, intent);

    assert!(RecipientAmountRule.evaluate(&ctx).is_empty());
}

#[test]
fn pg302_blocks_recipient_amount_mismatch() {
    let ctx = context(Some(61_000), vec![(RECIPIENT, 59_000)], 60_000, 2_000, 0);

    let findings = RecipientAmountRule.evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::Pg302);
    assert_eq!(findings[0].severity, Severity::Violation);
}

#[test]
fn pg303_allows_declared_count_of_change_candidates() {
    let ctx = context(
        Some(100_000),
        vec![(RECIPIENT, 60_000), (OTHER, 39_000)],
        60_000,
        2_000,
        1,
    );

    assert!(UndeclaredOutputRule.evaluate(&ctx).is_empty());
}

#[test]
fn pg303_blocks_all_undeclared_outputs_when_count_exceeds_policy() {
    let ctx = context(
        Some(100_000),
        vec![(RECIPIENT, 60_000), (OTHER, 20_000), (OTHER, 19_000)],
        60_000,
        2_000,
        1,
    );

    let findings = UndeclaredOutputRule.evaluate(&ctx);
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| {
        finding.code == FindingCode::Pg303 && finding.severity == Severity::Violation
    }));
}

#[test]
fn pg304_passes_when_fee_is_within_policy() {
    let ctx = context(Some(61_000), vec![(RECIPIENT, 60_000)], 60_000, 1_000, 0);
    assert!(MaximumFeeRule.evaluate(&ctx).is_empty());
}

#[test]
fn pg304_blocks_when_fee_exceeds_policy() {
    let ctx = context(Some(65_000), vec![(RECIPIENT, 60_000)], 60_000, 1_000, 0);

    let findings = MaximumFeeRule.evaluate(&ctx);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::Pg304);
    assert_eq!(findings[0].severity, Severity::Violation);
}

#[test]
fn pg304_blocks_when_fee_policy_cannot_be_evaluated() {
    let ctx = context(None, vec![(RECIPIENT, 60_000)], 60_000, 1_000, 0);
    let findings = MaximumFeeRule.evaluate(&ctx);
    assert_eq!(findings[0].severity, Severity::Violation);
}
