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
| PG101 | Missing UTXO information | Warning | Implemented (M1) |
| PG102 | Unknown global/input/output fields | Warning | Implemented (M1) |
| PG103 | Proprietary global/input/output fields | Warning | Implemented (M1) |
| PG104 | Invalid or non-standard sighash information | Critical | Implemented (M1) |
| PG105 | Input finalization / partial-signature status | Info | Implemented (M1) |
| PG201 | Absolute fee calculation | Info | Implemented (M2) |
| PG301 | Declared recipient address missing | Violation | Implemented (M2) |
| PG302 | Recipient amount mismatch | Violation | Implemented (M2) |
| PG303 | Undeclared output | Violation | Implemented (M2) |
| PG304 | Maximum absolute fee violation | Violation | Implemented (M2) |

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

## PG101 — Missing UTXO information

- **Severity**: Warning.
- **What it checks**: Every input has either `witness_utxo` or `non_witness_utxo`.
- **Why it matters**: Without UTXO data, a signer cannot independently confirm the
  amount being spent by that input, which also prevents reliable fee review.
- **Evidence**: `input_index`, field `witness_utxo/non_witness_utxo`, actual value
  `both missing`.
- **Suggested action**: Ask the PSBT creator to include UTXO information before
  reviewing fees or signing.
- **Tests**: `crates/psbt-guard-core/src/rules/missing_utxo.rs`;
  **Fixture**: constructed in-test from public dummy transaction data.

## PG102 — Unknown global/input/output fields

- **Severity**: Warning.
- **What it checks**: Global, input, and output `unknown` maps are empty.
- **Why it matters**: Unknown fields may be legitimate extensions, but psbt-guard
  cannot interpret them for the reviewer.
- **Evidence**: global scope or `input_index`/`output_index`, field `unknown`, and
  field count.
- **Suggested action**: Review the PSBT source and decide whether these unknown fields
  are expected before signing.
- **Tests**: `crates/psbt-guard-core/src/rules/unknown_fields.rs`;
  **Fixture**: constructed in-test from public dummy transaction data.

## PG103 — Proprietary global/input/output fields

- **Severity**: Warning.
- **What it checks**: Global, input, and output `proprietary` maps are empty.
- **Why it matters**: Proprietary fields are application-specific metadata; they can
  be valid, but their meaning is outside the standard fields psbt-guard interprets.
- **Evidence**: global scope or `input_index`/`output_index`, field `proprietary`,
  and field count.
- **Suggested action**: Confirm the wallet or coordinator intentionally added these
  proprietary fields.
- **Tests**: `crates/psbt-guard-core/src/rules/proprietary_fields.rs`;
  **Fixture**: constructed in-test from public dummy transaction data.

## PG104 — Invalid or non-standard sighash information

- **Severity**: Critical.
- **What it checks**: Explicit input `sighash_type` values are safe defaults only:
  absent, ECDSA `SIGHASH_ALL`, or Taproot `SIGHASH_DEFAULT`.
- **Why it matters**: Non-default sighash modes can allow parts of the transaction to
  change after an input is signed.
- **Evidence**: `input_index`, field `sighash_type`, and the requested sighash value.
- **Suggested action**: Do not sign until you understand why this PSBT needs a
  non-default sighash mode.
- **Tests**: `crates/psbt-guard-core/src/rules/sighash.rs`;
  **Fixture**: constructed in-test from public dummy transaction data.

## PG105 — Input finalization / partial-signature status

- **Severity**: Info.
- **What it checks**: Inputs that already contain final script data, partial ECDSA
  signatures, Taproot key signatures, or Taproot script signatures.
- **Why it matters**: Existing signature material is useful context during review,
  especially when a PSBT has already passed through another signer or finalizer.
- **Evidence**: `input_index`, field `input_status`, finalization state and partial
  signature count.
- **Suggested action**: Confirm the signing state is expected for the review step you
  are performing.
- **Tests**: `crates/psbt-guard-core/src/rules/input_status.rs`;
  **Fixture**: constructed in-test from public dummy transaction data.

## PG201 — Absolute fee calculation

- **Severity**: Info when complete; Warning when UTXO data is unavailable or
  inconsistent; Critical when outputs exceed inputs.
- **What it checks**: Sums every funding UTXO and transaction output, then reports the
  absolute fee. A `non_witness_utxo` must match the referenced transaction ID and
  output index.
- **Why it matters**: Reliable fee review is impossible without independently
  accounting for every input value.
- **Evidence**: Input total, output total and fee in satoshis, or the deterministic
  reason calculation was unavailable.
- **Suggested action**: Confirm the fee is expected; require complete, matching UTXO
  data before signing.
- **Tests**: `crates/psbt-guard-core/src/rules/m2_tests.rs`.

## PG301 — Declared recipient address missing

- **Severity**: Violation.
- **What it checks**: Every address in the intent has at least one matching transaction
  output script.
- **Why it matters**: A missing intended address can indicate recipient substitution
  or an incomplete intent manifest.
- **Evidence**: The canonical declared address that was not found.
- **Suggested action**: Do not sign until the independently verified recipient appears.
- **Tests**: `crates/psbt-guard-core/src/rules/m2_tests.rs`.

## PG302 — Recipient amount mismatch

- **Severity**: Violation; Critical if aggregate amount arithmetic overflows.
- **What it checks**: Aggregates all outputs paying each declared recipient and
  compares the total with the expected amount and optional tolerance.
- **Why it matters**: The correct recipient can still be paid an incorrect amount.
- **Evidence**: First matching output index, address, expected amount, actual aggregate
  amount and tolerance.
- **Suggested action**: Do not sign until the amount matches independently confirmed
  intent.
- **Tests**: `crates/psbt-guard-core/src/rules/m2_tests.rs`.

## PG303 — Undeclared output

- **Severity**: Violation when the number of outputs not assigned to recipients exceeds
  `max_change_outputs`.
- **What it checks**: Counts outputs whose scripts do not match any declared recipient.
  If the count exceeds policy, every undeclared output is reported because M2 cannot
  identify which one is genuine change.
- **Why it matters**: Extra outputs can redirect funds to an attacker. Count-based
  allowance does not prove wallet ownership.
- **Evidence**: Output index, destination address or script hex, amount, undeclared
  count and configured allowance.
- **Suggested action**: Identify every extra output before signing; keep the allowance
  minimal until descriptor verification lands in M4.
- **Tests**: `crates/psbt-guard-core/src/rules/m2_tests.rs`.

## PG304 — Maximum absolute fee violation

- **Severity**: Violation.
- **What it checks**: Enforces `max_absolute_fee_sat`; also blocks when fee accounting
  cannot verify the policy.
- **Why it matters**: A malicious or buggy transaction can siphon value as an excessive
  fee, while missing UTXO data can conceal the fee.
- **Evidence**: Calculated fee and maximum, or the reason the ceiling could not be
  evaluated.
- **Suggested action**: Do not sign until the fee is within policy and independently
  calculable.
- **Tests**: `crates/psbt-guard-core/src/rules/m2_tests.rs`.
