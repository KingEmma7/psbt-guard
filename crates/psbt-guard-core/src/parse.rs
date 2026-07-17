//! PSBT parsing helpers.
//!
//! Core accepts bytes or base64 text and returns typed values. It never reads
//! files or stdin; the CLI owns those I/O decisions.

use std::str::FromStr;

use bitcoin::{psbt, Psbt};
use thiserror::Error;

/// Errors that mean the input could not be decoded as a PSBT at all.
#[derive(Debug, Error)]
pub enum ParseError {
    /// Binary bytes were not a valid PSBT serialization.
    #[error("could not decode PSBT bytes: {0}")]
    Bytes(#[source] psbt::Error),
    /// Text was not valid base64 or decoded to invalid PSBT bytes.
    #[error("could not decode PSBT base64: {0}")]
    Base64(#[source] psbt::PsbtParseError),
}

/// Parse binary PSBT bytes.
pub fn parse_psbt_bytes(bytes: &[u8]) -> Result<Psbt, ParseError> {
    Psbt::deserialize(bytes).map_err(ParseError::Bytes)
}

/// Parse a base64-encoded PSBT string.
pub fn parse_psbt_base64(text: &str) -> Result<Psbt, ParseError> {
    Psbt::from_str(text.trim()).map_err(ParseError::Base64)
}

#[cfg(test)]
mod tests {
    use super::{parse_psbt_base64, parse_psbt_bytes};
    use crate::test_support::VALID_PSBT_BASE64;

    #[test]
    fn parses_public_bip174_base64_vector() {
        let psbt = parse_psbt_base64(VALID_PSBT_BASE64).expect("valid BIP 174 vector parses");

        assert_eq!(psbt.inputs.len(), psbt.unsigned_tx.input.len());
        assert_eq!(psbt.outputs.len(), psbt.unsigned_tx.output.len());
    }

    #[test]
    fn invalid_base64_is_an_error_not_a_panic() {
        assert!(parse_psbt_base64("not a psbt").is_err());
    }

    #[test]
    fn invalid_bytes_are_an_error_not_a_panic() {
        assert!(parse_psbt_bytes(b"not a binary psbt").is_err());
    }
}
