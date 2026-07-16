//! Aggregated analysis output.
//!
//! Milestone M1 defines here: `AnalysisReport` — the ordered, serializable
//! collection of findings plus summary counts and the overall verdict that
//! callers (such as the CLI) map to exit codes. Reports are deterministic:
//! the same input always yields byte-identical serialized output.
