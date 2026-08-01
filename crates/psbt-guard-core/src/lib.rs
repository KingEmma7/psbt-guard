//! # psbt-guard-core
//!
//! Reusable analysis library for verifying that a Partially Signed Bitcoin
//! Transaction (PSBT, BIP 174) matches a user-declared payment intent.
//!
//! This crate is **offline and read-only** by design. It never handles private
//! keys, never signs, never broadcasts, and performs no network requests. Its
//! verdicts are advisory review guidance for a human signer — never a
//! guarantee of safety.
//!
//! The crate is independent of any terminal formatting: it consumes PSBT bytes
//! and intent data and produces typed values ([`report::AnalysisReport`],
//! [`model::Finding`]) that callers render however they wish.
//!
//! Status: MVP complete through milestone M3. The crate can run structural
//! inspection, verify a PSBT against validated recipient, amount, change-count
//! and fee policies, and explain every stable finding code.

pub mod catalogue;
pub mod intent;
pub mod model;
pub mod parse;
pub mod report;
pub mod rules;

#[cfg(test)]
pub(crate) mod test_support {
    use bitcoin::absolute;
    use bitcoin::transaction;
    use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    pub(crate) const VALID_PSBT_BASE64: &str = "cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA";

    pub(crate) fn minimal_psbt() -> Psbt {
        let unsigned_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        Psbt::from_unsigned_tx(unsigned_tx).expect("minimal unsigned transaction is valid")
    }

    pub(crate) fn minimal_psbt_with_witness_utxo() -> Psbt {
        let mut psbt = minimal_psbt();
        let mut script_bytes = vec![0x00, 0x14];
        script_bytes.extend([0_u8; 20]);
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: ScriptBuf::from_bytes(script_bytes),
        });
        psbt
    }
}
