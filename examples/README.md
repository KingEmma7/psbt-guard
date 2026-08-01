# Examples

- [`intent.toml`](intent.toml) — validated payment-intent manifest used by `verify`.

## CLI usage

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

`explain` accepts finding codes case-insensitively and returns exit code `2` for an
unknown code.

Exit codes: `0` no policy violations, `1` violations or critical findings,
`2` malformed input or operational error.
