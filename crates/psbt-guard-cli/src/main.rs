//! `psbt-guard` command-line interface.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use psbt_guard_core::model::AnalysisContext;
use psbt_guard_core::model::Finding;
use psbt_guard_core::parse::{parse_psbt_base64, parse_psbt_bytes};
use psbt_guard_core::report::{analyze, AnalysisReport};
use psbt_guard_core::rules::structural_registry;

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
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
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

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    /// Human-readable text.
    Text,
    /// Deterministic JSON.
    Json,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("psbt-guard: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Inspect { psbt, format } => inspect(&psbt, format),
        Command::Verify { psbt, intent } => not_implemented(
            "verify",
            &format!("{}, intent {}", input_summary(&psbt), intent.display()),
        ),
        Command::Explain { finding_code } => {
            not_implemented("explain", &format!("finding code {finding_code}"))
        }
    }
}

fn inspect(psbt_arg: &str, format: OutputFormat) -> Result<ExitCode> {
    let psbt = load_psbt(psbt_arg)?;
    let ctx = AnalysisContext::from_psbt(psbt);
    let rules = structural_registry();
    let report = analyze(&ctx, &rules);

    match format {
        OutputFormat::Text => print_text_report(&report),
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&report)
                .context("failed to serialize analysis report as JSON")?;
            println!("{json}");
        }
    }

    if report.has_blocking_findings {
        Ok(ExitCode::from(1))
    } else {
        Ok(ExitCode::from(0))
    }
}

fn load_psbt(psbt_arg: &str) -> Result<bitcoin::Psbt> {
    if psbt_arg == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .context("failed to read PSBT from stdin")?;
        return parse_psbt_from_bytes_or_text(&bytes);
    }

    let path = PathBuf::from(psbt_arg);
    if path.exists() {
        let bytes = fs::read(&path)
            .with_context(|| format!("failed to read PSBT file {}", path.display()))?;
        return parse_psbt_from_bytes_or_text(&bytes)
            .with_context(|| format!("failed to parse PSBT file {}", path.display()));
    }

    parse_psbt_base64(psbt_arg).context("failed to parse PSBT argument as base64")
}

fn parse_psbt_from_bytes_or_text(bytes: &[u8]) -> Result<bitcoin::Psbt> {
    match parse_psbt_bytes(bytes) {
        Ok(psbt) => Ok(psbt),
        Err(bytes_error) => {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| anyhow!("failed to parse binary PSBT bytes: {bytes_error}"))?;
            parse_psbt_base64(text).map_err(|base64_error| {
                anyhow!("failed to parse PSBT as binary bytes or base64 text: {bytes_error}; {base64_error}")
            })
        }
    }
}

fn print_text_report(report: &AnalysisReport) {
    println!("psbt-guard inspect report");
    println!(
        "summary: {} finding(s): {} info, {} warning, {} violation, {} critical",
        report.summary.total,
        report.summary.info,
        report.summary.warning,
        report.summary.violation,
        report.summary.critical
    );
    println!("advisory: review guidance only, not a guarantee of safety");

    if report.findings.is_empty() {
        println!("no structural findings");
        return;
    }

    for finding in &report.findings {
        print_finding(finding);
    }
}

fn print_finding(finding: &Finding) {
    println!();
    println!(
        "{} [{:?}] {}",
        finding.code, finding.severity, finding.title
    );
    println!("{}", finding.explanation);

    if let Some(scope) = finding.evidence.scope {
        print!("evidence: {scope:?}");
        if let Some(input_index) = finding.evidence.input_index {
            print!(" input #{input_index}");
        }
        if let Some(output_index) = finding.evidence.output_index {
            print!(" output #{output_index}");
        }
        if let Some(field) = &finding.evidence.field {
            print!(" field {field}");
        }
        if let Some(actual) = &finding.evidence.actual {
            print!(" ({actual})");
        }
        println!();
    }

    println!("suggested action: {}", finding.suggested_action);
}

/// Describe the PSBT argument without echoing a potentially huge blob.
fn input_summary(psbt_arg: &str) -> String {
    if psbt_arg == "-" {
        "PSBT from stdin".to_owned()
    } else {
        format!("PSBT argument of {} chars", psbt_arg.chars().count())
    }
}

fn not_implemented(subcommand: &str, received: &str) -> Result<ExitCode> {
    eprintln!(
        "psbt-guard: `{subcommand}` is not implemented yet (planned for a later milestone); \
received {received}. See PLAN.md for the milestone schedule."
    );
    Ok(ExitCode::from(2))
}
