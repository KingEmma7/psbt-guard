//! `psbt-guard` command-line interface.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use psbt_guard_core::catalogue::explanation;
use psbt_guard_core::intent::{parse_intent, IntentFormat};
use psbt_guard_core::model::{AnalysisContext, Finding, FindingCode};
use psbt_guard_core::parse::{parse_psbt_base64, parse_psbt_bytes};
use psbt_guard_core::report::{analyze, AnalysisReport};
use psbt_guard_core::rules::{structural_registry, verification_registry};

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
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
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
        Command::Verify {
            psbt,
            intent,
            format,
        } => verify(&psbt, &intent, format),
        Command::Explain { finding_code } => explain(&finding_code),
    }
}

fn inspect(psbt_arg: &str, format: OutputFormat) -> Result<ExitCode> {
    let psbt = load_psbt(psbt_arg)?;
    let ctx = AnalysisContext::from_psbt(psbt);
    let rules = structural_registry();
    let report = analyze(&ctx, &rules);

    match format {
        OutputFormat::Text => print_text_report("inspect", "no structural findings", &report),
        OutputFormat::Json => print_json_report(&report)?,
    }

    Ok(report_exit_code(&report))
}

fn verify(psbt_arg: &str, intent_path: &Path, format: OutputFormat) -> Result<ExitCode> {
    let manifest = fs::read_to_string(intent_path)
        .with_context(|| format!("failed to read intent file {}", intent_path.display()))?;
    let intent_format = match intent_path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("json") => IntentFormat::Json,
        _ => IntentFormat::Toml,
    };
    let intent = parse_intent(&manifest, intent_format)
        .with_context(|| format!("failed to parse intent file {}", intent_path.display()))?;
    let psbt = load_psbt(psbt_arg)?;
    let ctx = AnalysisContext::with_intent(psbt, intent);
    let rules = verification_registry();
    let report = analyze(&ctx, &rules);

    match format {
        OutputFormat::Text => print_text_report("verify", "no verification findings", &report),
        OutputFormat::Json => print_json_report(&report)?,
    }

    Ok(report_exit_code(&report))
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

fn print_text_report(command: &str, clean_message: &str, report: &AnalysisReport) {
    println!("psbt-guard {command} report");
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
        println!("{clean_message}");
        return;
    }

    for finding in &report.findings {
        print_finding(finding);
    }
}

fn print_json_report(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)
        .context("failed to serialize analysis report as JSON")?;
    println!("{json}");
    Ok(())
}

fn report_exit_code(report: &AnalysisReport) -> ExitCode {
    if report.has_blocking_findings {
        ExitCode::from(1)
    } else {
        ExitCode::from(0)
    }
}

fn explain(finding_code: &str) -> Result<ExitCode> {
    let code = FindingCode::from_str(finding_code)?;
    let entry = explanation(code);

    println!("{} — {}", entry.code, entry.name);
    println!("typical severity: {:?}", entry.typical_severity);
    println!("what it checks: {}", entry.what_it_checks);
    println!("why it matters: {}", entry.why_it_matters);
    println!("suggested action: {}", entry.suggested_action);
    println!("advisory: review guidance only, not a guarantee of safety");

    Ok(ExitCode::from(0))
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
