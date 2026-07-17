# psbt-guard — Project Plan

## 1. Problem statement

A person about to sign a Partially Signed Bitcoin Transaction (PSBT) usually sees an
opaque base64 blob produced by wallet software they must trust. Bitcoin Core's
`decodepsbt` / `analyzepsbt` answer *"what is in this PSBT and is it structurally
complete?"* — but nothing offline answers the question that actually matters at signing
time: **"does this transaction do what I think it does?"**

A malicious or buggy coordinator can present a PSBT that:

- pays a different recipient than the one the user agreed to,
- pays the right recipient a different amount,
- includes extra outputs the user never declared,
- burns an absurd amount in fees,
- uses a non-default sighash mode that lets the transaction be altered after signing, or
- omits UTXO information so the signer cannot even compute what it is spending.

`psbt-guard` is an **offline, read-only, descriptor-aware intent verifier**. The user
declares their payment intent (recipients, amounts, fee limits, change expectations) in a
small manifest file; the tool compares the PSBT against that intent and produces
structured, plain-language findings that deserve review before signing. It is a
pre-signing review aid — not a decoder, not a signer, and never a guarantee of safety.

## 2. MVP and non-goals

### MVP

Two crates (library + CLI) implementing these rules incrementally:

| # | Rule | Code |
|---|------|------|
| 1 | Missing UTXO information | `PG101` |
| 2 | Unknown global/input/output fields | `PG102` |
| 3 | Proprietary global/input/output fields | `PG103` |
| 4 | Invalid or non-standard sighash information | `PG104` |
| 5 | Input finalization / partial-signature status | `PG105` |
| 6 | Absolute fee calculation (all funding UTXOs present) | `PG201` |
| 7 | Unexpected recipient address | `PG301` |
| 8 | Recipient amount mismatch | `PG302` |
| 9 | Undeclared output | `PG303` |
| 10 | Maximum absolute fee violation | `PG304` |

CLI commands: `inspect <PSBT>`, `verify <PSBT> --intent <FILE>`, `explain <FINDING_CODE>`.
Input via file path, base64 string, or stdin. Output human-readable or `--format json`.
Deterministic output and stable exit codes (`0` clean, `1` violations/critical, `2`
malformed input or operational error).

### Non-goals (MVP)

- **Never**: private key handling, signing, broadcasting, network requests.
- No descriptor-based change verification (milestone M4, not MVP).
- No fee-*rate* estimation (milestone M5); MVP computes absolute fee only.
- No PSBT v2 (BIP 370) support; PSBT v0 per BIP 174 only.
- No generic decoder feature-parity with Bitcoin Core.
- No GUI, no daemon mode, no wallet integration.

## 3. Architecture

```
                 ┌──────────────────────────────────────────┐
 PSBT (file /    │ psbt-guard-cli                           │
 base64 / stdin) │  input loading · clap · formatting ·     │
 intent manifest │  exit codes · anyhow error boundary      │
      ──────────►│                                          │
                 └───────────────┬──────────────────────────┘
                                 │ typed calls, no I/O
                 ┌───────────────▼──────────────────────────┐
                 │ psbt-guard-core                          │
                 │  parse PSBT ─► AnalysisContext           │
                 │  parse Intent (TOML primary, JSON accepted)
                 │  rule registry: Vec<Box<dyn AnalysisRule>>│
                 │  each rule ─► Vec<Finding>               │
                 │  aggregate ─► AnalysisReport             │
                 └──────────────────────────────────────────┘
```

Invariants:

- **Core never prints, never reads files, never formats for a terminal.** It consumes
  bytes/strings and returns typed values. All findings are data.
- **CLI never analyzes.** It loads input, calls core, renders the report, maps severity
  to exit codes.
- Rules are pure functions of the `AnalysisContext`; they never mutate it and are
  independently testable.

## 4. Domain model

- `AnalysisContext` — the parsed `bitcoin::Psbt`, derived per-input/per-output facts,
  the network, and the optional `Intent`. Built once, shared read-only by all rules.
- `AnalysisReport` — ordered list of `Finding`s plus summary counts and the overall
  verdict used for the exit code. Serializable to JSON.
- `Finding` — one observation:
  - `code: FindingCode` — stable identifier (e.g. `PG301`), never renumbered.
  - `severity: Severity` — `Info | Warning | Violation | Critical`.
  - `title` — short human title.
  - `explanation` — plain-language description of what was observed and why it matters.
  - `evidence` — structured pointer: input index, output index, field name, amounts.
  - `suggested_action` — what the reviewer should check before signing.
- `Intent` — user-declared expectation: `network`, `recipients: Vec<RecipientIntent>`,
  `fee_policy: FeePolicy`, `change_policy: ChangePolicy`.
- `RecipientIntent` — address + expected amount (with optional tolerance).
- `FeePolicy` — `max_absolute_fee` (MVP); fee-rate fields reserved for M5.
- `ChangePolicy` — how undeclared outputs are treated (MVP: allow/deny count-based;
  descriptor-based verification lands in M4).
- `AnalysisRule` — the extension point (see §5).

Severity semantics: `Info` (neutral observation), `Warning` (deserves review),
`Violation` (contradicts declared intent or policy), `Critical` (unsafe to sign
regardless of intent, e.g. non-standard sighash). Exit code 1 on any
`Violation`/`Critical`.

## 5. Rule engine design

```rust
pub trait AnalysisRule {
    /// Stable machine identifier for the rule (matches its FindingCode).
    fn code(&self) -> FindingCode;
    /// Human name for catalogues and `explain`.
    fn name(&self) -> &'static str;
    /// Evaluate against the shared context; zero findings means "nothing to report".
    fn evaluate(&self, ctx: &AnalysisContext) -> Vec<Finding>;
}
```

- A `registry()` function returns the default rule set in deterministic order; callers
  (and tests) may run any subset.
- Rules that require an `Intent` no-op with zero findings when none was provided
  (`inspect` runs structural rules only; `verify` runs everything).
- Adding a rule = one new type + tests + fixture + catalogue entry; no changes to the
  engine.
- Findings are emitted in (rule order, input/output index) order so output is
  deterministic byte-for-byte.

## 6. Error strategy

- `psbt-guard-core` defines `thiserror` enums: `ParseError` (undecodable PSBT/base64),
  `IntentError` (unreadable/invalid manifest), `AnalysisError` (internal invariant
  failures). **A suspicious PSBT is never an error** — suspicion is a `Finding`; errors
  are reserved for input we cannot analyze at all.
- `psbt-guard-cli` uses `anyhow` at the binary boundary only, attaching file/context
  information, and maps: success + no Violation/Critical → exit `0`; any
  Violation/Critical finding → exit `1`; any error (malformed input, unreadable file,
  bad flags) → exit `2`.

## 7. Testing strategy

- **Per-rule unit tests** in core: at least one non-triggering and one triggering case
  per rule, using fixtures or PSBTs constructed in-test.
- **Fixtures** under `fixtures/`: valid, invalid and suspicious PSBTs derived from
  public test vectors (BIP 174) or generated on regtest/testnet — never real funds,
  never real keys. Provenance documented in `fixtures/README.md`.
- **CLI integration tests** with `assert_cmd` + `predicates`: help output, each input
  mode, exit codes for all three classes, and `--format json` snapshot stability.
- **Determinism check**: same input twice → identical bytes out.
- Verification gate for every milestone: `cargo fmt --all -- --check`,
  `cargo check --workspace`,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --workspace`.

## 8. Security boundaries

- Never request, load, generate or store private keys.
- Never sign. Never broadcast. Never make network requests (MVP: no network
  dependencies at all).
- Operates only on: PSBT data, public wallet information (descriptors/xpubs), and the
  user-declared intent manifest.
- The verdict is **advisory review guidance, never a guarantee of safety** — all output
  and documentation must say so.
- Fixtures contain only public test data.
- Treat PSBT input as adversarial: parsing must be panic-free on arbitrary bytes.

## 9. Milestones

| ID | Scope | Exit criteria |
|----|-------|---------------|
| M0 | Scaffold: workspace, CI, docs skeleton, CLI help | help output works; verification gate green |
| M1 | PSBT loading + `inspect` with structural rules PG101–PG105 | rules tested + catalogued; JSON output |
| M2 | Intent manifest + `verify` with PG201, PG301–PG304 | intent verification end-to-end; exit codes final |
| M3 | Input ergonomics (stdin, base64 autodetect) + `explain` | all documented input modes tested |
| M4 | Descriptor-based change verification | change outputs matched against wallet descriptors |
| M5 | Fee-rate estimation and fee-rate policy | weight-based fee-rate findings |

Current status: **M1 complete**; PSBT loading and structural `inspect` rules
PG101-PG105 are implemented. M2 intent verification is next.
