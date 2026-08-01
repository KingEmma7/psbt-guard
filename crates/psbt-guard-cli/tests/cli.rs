//! CLI integration tests.

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;
use bitcoin::absolute;
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::psbt::PsbtSighashType;
use bitcoin::transaction;
use bitcoin::{
    Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use predicates::prelude::*;

const RECIPIENT: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
const CHANGE: &str = "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi";
static NEXT_FILE_ID: AtomicUsize = AtomicUsize::new(0);

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

fn segwit_script() -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend([0_u8; 20]);
    ScriptBuf::from_bytes(bytes)
}

fn minimal_psbt_base64_with_witness_utxo() -> String {
    let mut psbt = minimal_psbt();
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(20_000),
        script_pubkey: segwit_script(),
    });
    psbt.to_string()
}

fn checked_address(value: &str) -> Address<NetworkChecked> {
    Address::<NetworkUnchecked>::from_str(value)
        .expect("valid address")
        .require_network(Network::Testnet)
        .expect("testnet address")
}

fn verification_psbt_base64(recipient_amount_sat: u64, change_amount_sat: u64) -> String {
    let unsigned_tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(recipient_amount_sat),
                script_pubkey: checked_address(RECIPIENT).script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(change_amount_sat),
                script_pubkey: checked_address(CHANGE).script_pubkey(),
            },
        ],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("valid unsigned transaction");
    psbt.inputs[0].witness_utxo = Some(TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: segwit_script(),
    });
    psbt.to_string()
}

fn write_intent(expected_amount_sat: u64, max_fee_sat: u64) -> PathBuf {
    let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "psbt-guard-cli-intent-{}-{id}.toml",
        std::process::id()
    ));
    fs::write(
        &path,
        format!(
            r#"network = "testnet"

[[recipients]]
address = "{RECIPIENT}"
amount_sat = {expected_amount_sat}

[fee_policy]
max_absolute_fee_sat = {max_fee_sat}

[change_policy]
max_change_outputs = 1
"#
        ),
    )
    .expect("write intent fixture");
    path
}

fn write_psbt_file() -> PathBuf {
    let id = NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "psbt-guard-cli-input-{}-{id}.psbt",
        std::process::id()
    ));
    fs::write(&path, minimal_psbt_base64_with_witness_utxo()).expect("write PSBT fixture");
    path
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
fn inspect_reads_psbt_from_file() {
    let psbt_path = write_psbt_file();

    psbt_guard()
        .args(["inspect", psbt_path.to_str().expect("UTF-8 temp path")])
        .assert()
        .success()
        .stdout(predicate::str::contains("no structural findings"));

    fs::remove_file(psbt_path).expect("remove PSBT fixture");
}

#[test]
fn inspect_reads_psbt_from_stdin() {
    psbt_guard()
        .args(["inspect", "-"])
        .write_stdin(minimal_psbt_base64_with_witness_utxo())
        .assert()
        .success()
        .stdout(predicate::str::contains("no structural findings"));
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
        script_pubkey: segwit_script(),
    });
    psbt.inputs[0].sighash_type = Some(PsbtSighashType::from_u32(2));

    psbt_guard()
        .args(["inspect", &psbt.to_string()])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PG104"));
}

#[test]
fn verify_matching_intent_exits_0() {
    let intent = write_intent(60_000, 2_000);

    psbt_guard()
        .args([
            "verify",
            &verification_psbt_base64(60_000, 39_000),
            "--intent",
            intent.to_str().expect("UTF-8 temp path"),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("psbt-guard verify report"))
        .stdout(predicate::str::contains("PG201"))
        .stdout(predicate::str::contains("0 violation"));

    fs::remove_file(intent).expect("remove intent fixture");
}

#[test]
fn verify_amount_mismatch_exits_1() {
    let intent = write_intent(61_000, 2_000);

    psbt_guard()
        .args([
            "verify",
            &verification_psbt_base64(60_000, 39_000),
            "--intent",
            intent.to_str().expect("UTF-8 temp path"),
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PG302"));

    fs::remove_file(intent).expect("remove intent fixture");
}

#[test]
fn verify_json_is_machine_readable() {
    let intent = write_intent(60_000, 2_000);

    psbt_guard()
        .args([
            "verify",
            &verification_psbt_base64(60_000, 39_000),
            "--intent",
            intent.to_str().expect("UTF-8 temp path"),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""code": "PG201""#))
        .stdout(predicate::str::contains(
            r#""has_blocking_findings": false"#,
        ));

    fs::remove_file(intent).expect("remove intent fixture");
}

#[test]
fn verify_json_is_byte_for_byte_deterministic() {
    let intent = write_intent(60_000, 2_000);
    let psbt = verification_psbt_base64(60_000, 39_000);
    let args = [
        "verify",
        psbt.as_str(),
        "--intent",
        intent.to_str().expect("UTF-8 temp path"),
        "--format",
        "json",
    ];

    let first = psbt_guard().args(args).output().expect("first verify run");
    let second = psbt_guard().args(args).output().expect("second verify run");

    assert!(first.status.success());
    assert!(second.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);

    fs::remove_file(intent).expect("remove intent fixture");
}

#[test]
fn malformed_intent_exits_2() {
    let intent = write_intent(60_000, 2_000);
    fs::write(&intent, "not valid = [toml").expect("replace intent fixture");

    psbt_guard()
        .args([
            "verify",
            &verification_psbt_base64(60_000, 39_000),
            "--intent",
            intent.to_str().expect("UTF-8 temp path"),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("failed to parse intent file"));

    fs::remove_file(intent).expect("remove intent fixture");
}

#[test]
fn explain_returns_catalogue_entry() {
    psbt_guard()
        .args(["explain", "pg301"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PG301"))
        .stdout(predicate::str::contains(
            "Declared recipient address missing",
        ))
        .stdout(predicate::str::contains("typical severity: Violation"))
        .stdout(predicate::str::contains("not a guarantee of safety"));
}

#[test]
fn explain_rejects_unknown_code_with_exit_2() {
    psbt_guard()
        .args(["explain", "PG999"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown finding code `PG999`"));
}
