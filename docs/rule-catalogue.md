# Rule catalogue

Stable identifiers for every analysis rule. Codes are permanent: they are never
renumbered and never reused, even if a rule is retired. Each implemented rule links to
its explanation, severity mapping, evidence shape, and tests.

Code ranges:

- `PG1xx` — structural PSBT findings (no intent required).
- `PG2xx` — fee findings.
- `PG3xx` — intent-verification findings (require an intent manifest).

| Code | Name | Severity (typical) | Status |
|-------|------|--------------------|--------|
| PG101 | Missing UTXO information | Warning | Reserved (M1) |
| PG102 | Unknown global/input/output fields | Warning | Reserved (M1) |
| PG103 | Proprietary global/input/output fields | Warning | Reserved (M1) |
| PG104 | Invalid or non-standard sighash information | Critical | Reserved (M1) |
| PG105 | Input finalization / partial-signature status | Info | Reserved (M1) |
| PG201 | Absolute fee report (all funding UTXOs present) | Info | Reserved (M2) |
| PG301 | Unexpected recipient address | Violation | Reserved (M2) |
| PG302 | Recipient amount mismatch | Violation | Reserved (M2) |
| PG303 | Undeclared output | Violation | Reserved (M2) |
| PG304 | Maximum absolute fee violation | Violation | Reserved (M2) |

Entry template for implemented rules:

```markdown
## PGxxx — <name>

- **Severity**: <typical severity and when it escalates>
- **What it checks**: <plain language>
- **Why it matters**: <attack or failure scenario>
- **Evidence**: <indices/fields included in the finding>
- **Suggested action**: <what the reviewer should do>
- **Tests**: <test module path>; **Fixture**: <fixtures/... path>
```
