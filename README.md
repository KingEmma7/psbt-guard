# psbt-guard

**Offline, read-only PSBT intent verifier.** psbt-guard checks whether a Partially
Signed Bitcoin Transaction (PSBT, [BIP 174]) matches a payment intent you declare —
recipients, amounts, fee limits — and highlights conditions that deserve review
*before* you sign.

> **Status: milestone M1.** `inspect` loads PSBTs and reports structural findings
> PG101-PG105; intent verification is planned for M2. See [`PLAN.md`](PLAN.md).

## Why not just `decodepsbt`?

Bitcoin Core already decodes PSBTs structurally. psbt-guard answers a different
question: *"does this transaction do what I think it does?"* You declare intent in a
small manifest; the tool compares the PSBT against it and reports structured,
plain-language findings — unexpected recipients, amount mismatches, undeclared
outputs, excessive fees, non-standard sighashes, missing UTXO data.

## Safety boundaries

psbt-guard **never**:

- requests, loads, generates or stores private keys;
- signs a transaction;
- broadcasts a transaction;
- makes network requests.

It operates entirely on PSBT data, public wallet information and your declared intent.
Its verdict is **advisory review guidance — not a guarantee of safety**. A clean report
means none of its rules fired, nothing more.

## Usage

```bash
psbt-guard inspect <PSBT>                      # structural findings, no intent needed
psbt-guard verify <PSBT> --intent intent.toml  # verify against declared intent
psbt-guard explain PG301                       # explain a finding code
```

`<PSBT>` may be a file path, a base64 string, or `-` for stdin. For `inspect`, add
`--format json` for machine-readable output. `verify` and `explain` are still
milestone stubs. Intent manifests are TOML (primary) or JSON — see
[`examples/intent.toml`](examples/intent.toml).

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Analysis completed with no policy violations |
| `1` | Policy violations or critical findings |
| `2` | Malformed input or operational error |

## Building

```bash
cargo build --workspace
cargo run -p psbt-guard-cli -- --help
```

Requires Rust 1.74+. The workspace contains `psbt-guard-core` (reusable analysis
library, no I/O) and `psbt-guard-cli` (the `psbt-guard` binary).

> **macOS/Homebrew note**: if `cargo`/`rustc` are "not found", Rust was likely installed
> via `brew install rustup` (keg-only). Run
> `export PATH="/opt/homebrew/opt/rustup/bin:$PATH"` (and consider adding it to your
> shell profile) before building.

## Documentation

- [`PLAN.md`](PLAN.md) — problem statement, architecture, milestones
- [`docs/rule-catalogue.md`](docs/rule-catalogue.md) — stable finding codes
- [`docs/threat-model.md`](docs/threat-model.md) — what it does and doesn't defend against
- [`docs/learning-journal.md`](docs/learning-journal.md) — Rust/Bitcoin concepts log

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work shall be dual-licensed as above, without additional terms.

[BIP 174]: https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
