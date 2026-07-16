//! `psbt-guard` command-line interface.
//!
//! Milestone M0: the command surface exists and is documented, but analysis is
//! not implemented yet — every subcommand reports that honestly and exits with
//! code 2 (operational error), per the exit-code contract in `PLAN.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

const AFTER_HELP: &str = "\
Exit codes:
  0  analysis completed with no policy violations
  1  policy violations or critical findings
  2  malformed input or operational error

psbt-guard is offline and read-only. It never handles private keys, never
signs, never broadcasts, and makes no network requests. Its output is advisory
review guidance — not a guarantee of safety.";

#[derive(Parser)]
#[command(name = "psbt-guard", version, about, after_help = AFTER_HELP)]
#[command(
    long_about = "Offline, read-only PSBT intent verifier: checks a Partially Signed \
Bitcoin Transaction against a user-declared payment intent and highlights conditions \
that deserve review before signing."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode a PSBT and report structural findings (no intent required)
    Inspect {
        /// PSBT as a file path, base64 string, or `-` for stdin
        psbt: String,
    },
    /// Verify a PSBT against a declared payment intent
    Verify {
        /// PSBT as a file path, base64 string, or `-` for stdin
        psbt: String,
        /// Intent manifest (TOML primary; JSON accepted by extension)
        #[arg(long, value_name = "FILE")]
        intent: PathBuf,
    },
    /// Explain a finding code from the rule catalogue
    Explain {
        /// Stable finding code, e.g. PG301
        finding_code: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Inspect { psbt } => not_implemented("inspect", &input_summary(&psbt)),
        Command::Verify { psbt, intent } => not_implemented(
            "verify",
            &format!("{}, intent {}", input_summary(&psbt), intent.display()),
        ),
        Command::Explain { finding_code } => {
            not_implemented("explain", &format!("finding code {finding_code}"))
        }
    }
}

/// Describe the PSBT argument without echoing a potentially huge blob.
fn input_summary(psbt_arg: &str) -> String {
    if psbt_arg == "-" {
        "PSBT from stdin".to_owned()
    } else {
        format!("PSBT argument of {} chars", psbt_arg.chars().count())
    }
}

fn not_implemented(subcommand: &str, received: &str) -> ExitCode {
    eprintln!(
        "psbt-guard: `{subcommand}` is not implemented yet (scaffold milestone M0); \
received {received}. See PLAN.md for the milestone schedule."
    );
    ExitCode::from(2)
}
