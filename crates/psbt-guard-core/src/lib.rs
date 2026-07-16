//! # psbt-guard-core
//!
//! Reusable analysis library for verifying that a Partially Signed Bitcoin
//! Transaction (PSBT, BIP 174) matches a user-declared payment intent.
//!
//! This crate is **offline and read-only** by design. It never handles private
//! keys, never signs, never broadcasts, and performs no network requests. Its
//! verdicts are advisory review guidance for a human signer — never a
//! guarantee of safety.
//!
//! The crate is independent of any terminal formatting: it consumes PSBT bytes
//! and intent data and produces typed values ([`report::AnalysisReport`],
//! [`model::Finding`]) that callers render however they wish.
//!
//! Status: milestone M0 (scaffold). The module skeleton below is real; the
//! analysis pipeline lands in M1/M2 — see `PLAN.md` at the repository root.

pub mod intent;
pub mod model;
pub mod report;
pub mod rules;
