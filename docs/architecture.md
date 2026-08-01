# Architecture

## Crate boundaries

`psbt-guard-core` is a pure analysis library. It parses PSBT bytes/base64 text,
builds an `AnalysisContext`, runs rules, and returns typed `AnalysisReport` values.
It never reads files, prints terminal output, signs, broadcasts, or performs network
requests.

`psbt-guard-cli` owns I/O: command-line parsing, reading files/stdin, text/JSON
rendering, and exit-code mapping. The CLI calls core functions instead of
reimplementing analysis.

## Analysis pipeline

```text
PSBT bytes/base64 + optional validated TOML/JSON intent
  -> parse_psbt_bytes / parse_psbt_base64 + parse_intent
  -> bitcoin::Psbt + optional Intent
  -> AnalysisContext
  -> structural_registry() or verification_registry()
  -> AnalysisReport
  -> CLI text or JSON output
```

## `inspect` vs `verify`

`inspect` runs structural rules PG101-PG105 and does not require an intent manifest.
`verify` attaches a validated intent to the same `AnalysisContext`, then runs the
structural rules plus PG201 and PG301-PG304 in stable catalogue order.

`explain` parses a case-insensitive `FindingCode` and reads a typed, core-owned
catalogue entry. Keeping those explanations in the library prevents CLI prose from
drifting away from stable codes and rule semantics.

Intent parsing rejects unknown fields, unsupported networks, wrong-network addresses,
zero-value or duplicate recipients, and tolerances larger than their expected amount.
Fee policy enforcement becomes a violation when incomplete or inconsistent UTXO data
prevents the ceiling from being checked.

## Determinism guarantees

Findings are emitted in registry order and then PSBT index order. Serializable report
structs declare fields in stable order, so repeated JSON serialization of the same
report is byte-for-byte stable.

## Extension points

Each rule implements `AnalysisRule`. Adding a rule means adding one rule type, tests,
a stable `FindingCode`, and a catalogue entry. The rule registry is the only ordering
point for default analysis.
