# Architecture

> Placeholder — expanded during M1. The authoritative M0 description lives in
> `PLAN.md` §3–§6; this document will grow module-level detail as code lands.

Planned sections:

1. **Crate boundaries** — `psbt-guard-core` (pure analysis library) vs
   `psbt-guard-cli` (I/O, formatting, exit codes); why core performs no I/O and no
   terminal formatting.
2. **Analysis pipeline** — input bytes → `bitcoin::Psbt` → `AnalysisContext` →
   rule registry → `AnalysisReport`.
3. **Data flow for `inspect` vs `verify`** — structural rules only vs full rule set
   with intent.
4. **Determinism guarantees** — ordering of findings, stable serialization.
5. **Extension points** — adding rules, output formats, and input sources.
