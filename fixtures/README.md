# Fixtures

Test PSBTs used by unit and integration tests. Nothing here — ever — may contain
private keys, real funds, or data derived from a real wallet.

## Provenance policy

Every fixture must come from one of these sources, recorded next to the file:

1. **BIP 174 test vectors** — the public valid/invalid PSBT vectors from the BIP text.
2. **Constructed in-repo** — built by test code or a documented script from all-public
   data (testnet/regtest scripts, well-known example xpubs).
3. **Other public specifications** — e.g. BIP 370/371 vectors, with a citation.

## Layout (populated from M1 onward)

```
fixtures/
  valid/        # well-formed PSBTs that should analyze cleanly
  invalid/      # undecodable or malformed inputs (must exit 2, never panic)
  suspicious/   # well-formed PSBTs that should trigger specific rules
```

Each fixture gets a sibling `<name>.md` (or a manifest entry) stating: source,
network, what it demonstrates, and which rule codes it exercises.
