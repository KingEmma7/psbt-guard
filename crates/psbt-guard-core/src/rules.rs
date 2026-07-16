//! The extensible rule engine.
//!
//! Milestone M1 defines here: the `AnalysisRule` trait (a pure function from
//! `AnalysisContext` to zero or more `Finding`s) and a `registry()` returning
//! the default rule set in deterministic order. Each rule is independently
//! testable; adding a rule never requires changing the engine.
//!
//! Planned MVP rules and their stable codes are catalogued in
//! `docs/rule-catalogue.md`.
