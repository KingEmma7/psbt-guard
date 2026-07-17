//! Aggregated analysis output.
//!
//! Reports are deterministic: rules run in registry order and each rule emits
//! findings in PSBT index order.

use serde::{Deserialize, Serialize};

use crate::model::{AnalysisContext, Finding, Severity};
use crate::rules::AnalysisRule;

/// Count of findings by severity.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Total number of findings.
    pub total: usize,
    /// Informational findings.
    pub info: usize,
    /// Warning findings.
    pub warning: usize,
    /// Violation findings.
    pub violation: usize,
    /// Critical findings.
    pub critical: usize,
}

impl FindingSummary {
    fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();

        for finding in findings {
            summary.total += 1;
            match finding.severity {
                Severity::Info => summary.info += 1,
                Severity::Warning => summary.warning += 1,
                Severity::Violation => summary.violation += 1,
                Severity::Critical => summary.critical += 1,
            }
        }

        summary
    }
}

/// Full analysis result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Finding counts.
    pub summary: FindingSummary,
    /// Whether this report should map to CLI exit code 1.
    pub has_blocking_findings: bool,
    /// Ordered findings.
    pub findings: Vec<Finding>,
}

impl AnalysisReport {
    /// Build a report from findings already emitted in deterministic order.
    pub fn from_findings(findings: Vec<Finding>) -> Self {
        let summary = FindingSummary::from_findings(&findings);
        let has_blocking_findings = findings
            .iter()
            .any(|finding| finding.severity.is_blocking());

        Self {
            summary,
            has_blocking_findings,
            findings,
        }
    }
}

/// Run a list of rules against a shared context.
pub fn analyze(ctx: &AnalysisContext, rules: &[Box<dyn AnalysisRule>]) -> AnalysisReport {
    let findings = rules
        .iter()
        .flat_map(|rule| rule.evaluate(ctx))
        .collect::<Vec<_>>();

    AnalysisReport::from_findings(findings)
}

#[cfg(test)]
mod tests {
    use crate::model::{Evidence, Finding, FindingCode, Severity};

    use super::AnalysisReport;

    fn sample_finding(severity: Severity) -> Finding {
        Finding {
            code: FindingCode::Pg101,
            severity,
            title: "Sample".to_owned(),
            explanation: "Sample explanation.".to_owned(),
            evidence: Evidence::input(0, "witness_utxo/non_witness_utxo", "missing"),
            suggested_action: "Review the sample.".to_owned(),
        }
    }

    #[test]
    fn summarizes_findings_by_severity() {
        let report = AnalysisReport::from_findings(vec![
            sample_finding(Severity::Info),
            sample_finding(Severity::Warning),
            sample_finding(Severity::Critical),
        ]);

        assert_eq!(report.summary.total, 3);
        assert_eq!(report.summary.info, 1);
        assert_eq!(report.summary.warning, 1);
        assert_eq!(report.summary.critical, 1);
        assert!(report.has_blocking_findings);
    }

    #[test]
    fn json_output_is_deterministic_for_same_report() {
        let report = AnalysisReport::from_findings(vec![sample_finding(Severity::Warning)]);

        let first = serde_json::to_string_pretty(&report).expect("serialize");
        let second = serde_json::to_string_pretty(&report).expect("serialize");

        assert_eq!(first, second);
    }
}
