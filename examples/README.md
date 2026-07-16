# Examples

- [`intent.toml`](intent.toml) — draft payment-intent manifest (schema lands in M2).

## Intended CLI usage (target surface; analysis lands in M1/M2)

```bash
# Structural review only — no intent needed
psbt-guard inspect payment.psbt
psbt-guard inspect "cHNidP8B..."          # base64 accepted directly
cat payment.psbt | psbt-guard inspect -   # or via stdin

# Verify against declared intent
psbt-guard verify payment.psbt --intent intent.toml
psbt-guard verify payment.psbt --intent intent.toml --format json

# Look up a finding code from a report
psbt-guard explain PG301
```

Exit codes: `0` no policy violations, `1` violations or critical findings,
`2` malformed input or operational error.
