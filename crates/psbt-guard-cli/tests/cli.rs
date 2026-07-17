//! CLI integration tests.

use assert_cmd::Command;
use bitcoin::absolute;
use bitcoin::psbt::PsbtSighashType;
use bitcoin::transaction;
use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use predicates::prelude::*;

fn psbt_guard() -> Command {
    Command::cargo_bin("psbt-guard").expect("binary `psbt-guard` builds")
}

fn minimal_psbt() -> Psbt {
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };

    Psbt::from_unsigned_tx(unsigned_tx).expect("minimal unsigned transaction is valid")
}

fn minimal_psbt_base64_with_witness_utxo() -> String {
    let mut psbt = minimal_psbt();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: ScriptBuf::new(),
    });
    psbt.to_string()
}

#[test]
fn help_lists_all_subcommands_and_exit_codes() {
    psbt_guard()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("inspect"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("explain"))
        .stdout(predicate::str::contains("Exit codes"))
        .stdout(predicate::str::contains("not a guarantee of safety"));
}

#[test]
fn version_flag_works() {
    psbt_guard()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("psbt-guard"));
}

#[test]
fn no_arguments_is_a_usage_error_with_exit_code_2() {
    // clap uses exit code 2 for usage errors, matching our operational-error code.
    psbt_guard()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn inspect_clean_psbt_exits_0() {
    psbt_guard()
        .args(["inspect", &minimal_psbt_base64_with_witness_utxo()])
        .assert()
        .success()
        .stdout(predicate::str::contains("no structural findings"))
        .stdout(predicate::str::contains("not a guarantee of safety"));
}

#[test]
fn inspect_json_reports_missing_utxo() {
    psbt_guard()
        .args(["inspect", &minimal_psbt().to_string(), "--format", "json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""code": "PG101""#))
        .stdout(predicate::str::contains(r#""warning": 1"#));
}

#[test]
fn inspect_critical_sighash_exits_1() {
    let mut psbt = minimal_psbt();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: ScriptBuf::new(),
    });
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(2));

    psbt_guard()
        .args(["inspect", &psbt.to_string()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PG104"));
}

#[test]
fn unimplemented_verify_exits_2_and_says_so() {
    psbt_guard()
        .args(["verify", "-", "--intent", "examples/intent.toml"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not implemented"));
}

#[test]
fn unimplemented_explain_exits_2_and_says_so() {
    psbt_guard()
        .args(["explain", "PG301"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not implemented"));
}
