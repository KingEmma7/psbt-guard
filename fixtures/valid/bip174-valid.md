# `bip174-valid.base64`

- **Source**: Public BIP 174 test vector, copied from the BIP 174 test vector
  section.
- **Network**: The vector is structural PSBT data; rules in M1 do not infer or
  require a network.
- **Demonstrates**: A parseable PSBT v0 sample used by parser tests.
- **Rule codes**: Parser coverage; individual PG101-PG105 triggering cases are
  constructed in unit tests from public dummy transactions.
