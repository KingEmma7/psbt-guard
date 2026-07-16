# Threat model

> Placeholder — expanded during M1/M2 as rules land.

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

## What psbt-guard does NOT defend against (out of scope)

- A compromised signing device or compromised intent manifest: if the attacker can
  edit the user's declared intent, verification against it is meaningless.
- Wrong intent: psbt-guard checks the PSBT against what the user *declared*, not what
  they *meant*.
- Anything after signing: it cannot prevent broadcast of a bad transaction it never saw.
- Key theft, malware, physical attacks.

## Assumptions

- psbt-guard runs on a machine the user trusts at least as much as the signer.
- PSBT input is fully adversarial; parsing must be panic-free on arbitrary bytes.
- The tool itself is read-only: no keys, no signing, no broadcast, no network.
- Its verdict is advisory — a clean report is **not** a guarantee of safety.
