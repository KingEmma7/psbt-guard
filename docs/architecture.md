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
PSBT bytes/base64
  -> parse_psbt_bytes / parse_psbt_base64
  -> bitcoin::Psbt
  -> AnalysisContext
  -> structural_registry()
  -> AnalysisReport
  -> CLI text or JSON output
```

## `inspect` vs `verify`

M1 implements `inspect`: it runs structural rules PG101-PG105 and does not require an
intent manifest. `verify` remains an M2 command; it will reuse the same
`AnalysisContext` and report machinery with intent-aware rules added.

## Determinism guarantees

Findings are emitted in registry order and then PSBT index order. Serializable report
structs declare fields in stable order, so repeated JSON serialization of the same
report is byte-for-byte stable.

## Extension points

Each rule implements `AnalysisRule`. Adding a rule means adding one rule type, tests,
a stable `FindingCode`, and a catalogue entry. The rule registry is the only ordering
point for default analysis.
