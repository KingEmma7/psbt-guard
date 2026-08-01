# Threat model

## What psbt-guard defends against (in scope)

A signer is presented with a PSBT produced by software or a counterparty they do not
fully trust (malicious coordinator, compromised wallet host, man-in-the-middle on an
airgap transfer). Concrete threats the rules target:

- Recipient substitution (pay attacker instead of declared recipient).
- Amount manipulation (declared recipient, wrong amount).
- Output injection (extra undeclared outputs draining funds).
- Fee siphoning (absurd fee, deliberately or by bug).
- Sighash downgrade (non-default sighash allowing post-signature modification).
- Information withholding (missing UTXO data preventing informed review).
- Funding-data substitution (conflicting UTXO fields that conceal the real fee).

M2 maps those threats to stable findings:

- PG301 requires every declared recipient address to appear.
- PG302 compares aggregate payments with declared amounts and tolerances.
- PG303 limits outputs not assigned to recipients.
- PG201 computes the absolute fee from funding UTXOs; PG304 enforces the ceiling and
  blocks when the ceiling cannot be evaluated.
- PG104 treats non-default sighash modes as critical.

## What psbt-guard does NOT defend against (out of scope)

- A compromised signing device or compromised intent manifest: if the attacker can
  edit the user's declared intent, verification against it is meaningless.
- Wrong intent: psbt-guard checks the PSBT against what the user *declared*, not what
  they *meant*.
- M2 change ownership: `max_change_outputs` is only a count allowance. An output within
  that allowance is not proven to belong to the user's wallet; descriptor verification
  is deferred to M4.
- Anything after signing: it cannot prevent broadcast of a bad transaction it never saw.
- Key theft, malware, physical attacks.

## Assumptions

- psbt-guard runs on a machine the user trusts at least as much as the signer.
- PSBT input is fully adversarial; parsing must be panic-free on arbitrary bytes.
- The tool itself is read-only: no keys, no signing, no broadcast, no network.
- Its verdict is advisory — a clean report is **not** a guarantee of safety.
- The intent manifest is obtained through a channel independent from the untrusted PSBT
  producer and reviewed before use.

## Failure posture

- Unknown manifest fields and wrong-network addresses are operational errors rather
  than silently ignored configuration.
- A declared fee ceiling that cannot be calculated is a policy violation, not a clean
  result.
- If undeclared outputs exceed the count allowance, every undeclared output is reported;
  the tool does not guess which one is change.
- Amount accumulation uses checked arithmetic and malformed value balance is never
  treated as a normal fee.
- Fee accounting validates every supplied previous transaction, reconciles it with
  `witness_utxo` when both are present, and rejects witness-only data for legacy
  outputs.
