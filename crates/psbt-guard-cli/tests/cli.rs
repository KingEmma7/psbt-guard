//! CLI integration tests for the M0 scaffold.
//!
//! `assert_cmd` builds and runs the real `psbt-guard` binary; `predicates`
//! matches on its output. These tests pin the public contract that already
//! exists at M0: the documented command surface and the exit-code semantics
//! for operational errors.

use assert_cmd::Command;
use predicates::prelude::*;

fn psbt_guard() -> Command {
    Command::cargo_bin("psbt-guard").expect("binary `psbt-guard` builds")
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
fn unimplemented_inspect_exits_2_and_says_so() {
    psbt_guard()
        .args(["inspect", "cHNidP8BAAAA"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not implemented"));
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
