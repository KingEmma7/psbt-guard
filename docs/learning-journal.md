# Learning journal

Running log of Rust constructs and Bitcoin concepts encountered while building
psbt-guard, in the order they appeared. Each entry: what it is, why we use it here,
and the alternative we did not choose.

## M0 — scaffold

### Cargo workspace (`Cargo.toml` at repo root)

A workspace compiles several crates together with one shared `Cargo.lock` and target
directory. We split `psbt-guard-core` (library) from `psbt-guard-cli` (binary) so the
analysis engine is reusable by other programs and can never accidentally grow terminal
or file I/O concerns. *Alternative not chosen*: a single binary crate — simpler, but it
makes the "core never prints" boundary a convention instead of a compiler-enforced one.
`[workspace.dependencies]` pins each dependency version once; member crates opt in with
`foo.workspace = true`, so versions cannot drift between crates.

### `thiserror` (core) vs `anyhow` (CLI)

`thiserror` derives `std::error::Error` for precise, typed error enums — callers of a
*library* need to match on error variants. `anyhow` erases error types into one
context-carrying value — fine for an *application* that only reports errors to a human.
Rule of thumb encoded in `CLAUDE.md`: typed errors in `psbt-guard-core`, `anyhow` only
in `psbt-guard-cli`'s binary boundary. *Alternative not chosen*: `anyhow` everywhere —
would make it impossible for library users to distinguish "unparseable PSBT" from
"invalid intent manifest".

### `clap` derive API (`crates/psbt-guard-cli/src/main.rs`)

`#[derive(Parser)]` / `#[derive(Subcommand)]` generate the argument parser from plain
structs and enums, so the CLI surface is readable as a type definition and doc comments
become `--help` text. *Alternative not chosen*: clap's builder API — more flexible at
runtime but the command tree is harder to read and review.

### `ExitCode` instead of `std::process::exit` (`main.rs`)

Returning `std::process::ExitCode` from `main` sets the exit status while still running
destructors; `process::exit` terminates immediately and skips them. Our exit codes
(0/1/2) are a documented public contract, so they flow through the type system rather
than being sprinkled as magic numbers. *Alternative not chosen*: `fn main() -> anyhow::Result<()>`
alone — it only distinguishes success from failure (exit 1), and we need three codes.

### Enum ordering via `derive(PartialOrd, Ord)` (`core/src/model.rs`)

For a C-like enum, deriving `Ord` orders variants by declaration order, so
`Severity::Info < Warning < Violation < Critical` holds because of how the enum is
written. This makes "is this severity blocking?" a comparison (`self >= Violation`)
instead of a match that must be updated when variants are added. *Alternative not
chosen*: explicit numeric ranks — duplicates information the declaration order already
carries.

### `assert_cmd` + `predicates` (`crates/psbt-guard-cli/tests/cli.rs`)

Integration tests that build and execute the real binary, asserting on stdout/stderr
and exit codes — this pins the *observable* contract (help text, exit codes) rather
than internal functions. *Alternative not chosen*: unit-testing the clap `Cli` struct
with `try_parse_from` — useful later for parsing edge cases, but it cannot verify exit
codes or actual process behaviour.

### Bitcoin: PSBT roles (BIP 174)

BIP 174 defines PSBT as a key-value format passed between roles: *Creator* →
*Updater* → *Signer* → *Combiner* → *Input Finalizer* → *Transaction Extractor*.
psbt-guard deliberately implements **none** of these roles — it is a read-only observer
positioned just before the Signer, which is exactly why it must never hold keys or
finalize anything. The `unknown` and `proprietary` key-value maps exposed by
`bitcoin::Psbt` exist because the format is extensible; rules PG102/PG103 will surface
them since a signer cannot review what they cannot see.

### Bitcoin: why "missing UTXO information" matters (future PG101)

A PSBT input may carry `non_witness_utxo` (the whole previous transaction) or
`witness_utxo` (just the spent output). Without one of them the signer cannot know the
amount being spent — and therefore cannot compute the fee (fee = inputs − outputs is
implicit, never stated in the transaction). Some historical hardware-wallet attacks
exploited exactly this gap.
