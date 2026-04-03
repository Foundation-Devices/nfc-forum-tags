// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared TLV (Tag-Length-Value) length encoding for NFC Forum tags.
//!
//! Both Type 2 and Type 4 tags use the same TLV length format:
//! - **1-byte**: values 0x00–0xFE encode the length directly
//! - **3-byte**: 0xFF followed by a 2-byte big-endian length (0x00FF–0xFFFE)
//!
//! The tag field values and TLV semantics differ between tag types,
//! but the length encoding is identical.

use crate::vec::{BufferFullError, DataVec, VecExt};

/// Error during TLV parsing or encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvError {
    /// TLV structure is malformed (truncated length, out of bounds).
    InvalidTlv,
    /// Buffer is full.
    BufferFull,
}

impl From<BufferFullError> for TlvError {
    fn from(_: BufferFullError) -> Self {
        TlvError::BufferFull
    }
}

/// Parse the TLV length field starting at `data[offset]`.
///
/// Returns `(length_value, bytes_consumed)` where `bytes_consumed`
/// is 1 for the short format or 3 for the long format.
pub fn parse_tlv_length(data: &[u8], offset: usize) -> Result<(u16, usize), TlvError> {
    if offset >= data.len() {
        return Err(TlvError::InvalidTlv);
    }

    let first = data[offset];
    if first < 0xFF {
        // One-byte format: 0x00–0xFE.
        Ok((first as u16, 1))
    } else {
        // Three-byte format: 0xFF followed by 2-byte big-endian length.
        if offset + 3 > data.len() {
            return Err(TlvError::InvalidTlv);
        }
        let len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        Ok((len, 3))
    }
}

/// Encode a TLV length field into `out`.
///
/// Uses the 1-byte format for lengths < 255, or the 3-byte format
/// (0xFF prefix + 2-byte big-endian) for lengths >= 255.
pub fn encode_tlv_length(len: u16, out: &mut DataVec) -> Result<(), TlvError> {
    if len < 0xFF {
        out.try_push(len as u8)?;
    } else {
        out.try_push(0xFF)?;
        out.try_extend(&len.to_be_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_byte_length() {
        let data = [0x03];
        let (len, consumed) = parse_tlv_length(&data, 0).unwrap();
        assert_eq!(len, 3);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_zero_length() {
        let data = [0x00];
        let (len, consumed) = parse_tlv_length(&data, 0).unwrap();
        assert_eq!(len, 0);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_max_one_byte_length() {
        let data = [0xFE];
        let (len, consumed) = parse_tlv_length(&data, 0).unwrap();
        assert_eq!(len, 254);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_three_byte_length() {
        let data = [0xFF, 0x01, 0x00];
        let (len, consumed) = parse_tlv_length(&data, 0).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_three_byte_length_min() {
        let data = [0xFF, 0x00, 0xFF];
        let (len, consumed) = parse_tlv_length(&data, 0).unwrap();
        assert_eq!(len, 255);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_with_offset() {
        let data = [0xAA, 0xBB, 0x42];
        let (len, consumed) = parse_tlv_length(&data, 2).unwrap();
        assert_eq!(len, 0x42);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn parse_truncated_three_byte() {
        let data = [0xFF, 0x01];
        assert_eq!(parse_tlv_length(&data, 0), Err(TlvError::InvalidTlv));
    }

    #[test]
    fn parse_empty() {
        let data: [u8; 0] = [];
        assert_eq!(parse_tlv_length(&data, 0), Err(TlvError::InvalidTlv));
    }

    #[test]
    fn encode_short_length() {
        let mut out = DataVec::new();
        encode_tlv_length(42, &mut out).unwrap();
        assert_eq!(&*out, &[42]);
    }

    #[test]
    fn encode_long_length() {
        let mut out = DataVec::new();
        encode_tlv_length(256, &mut out).unwrap();
        assert_eq!(&*out, &[0xFF, 0x01, 0x00]);
    }

    #[test]
    fn encode_boundary_254() {
        let mut out = DataVec::new();
        encode_tlv_length(254, &mut out).unwrap();
        assert_eq!(&*out, &[0xFE]);
    }

    #[test]
    fn encode_boundary_255() {
        let mut out = DataVec::new();
        encode_tlv_length(255, &mut out).unwrap();
        assert_eq!(&*out, &[0xFF, 0x00, 0xFF]);
    }
}
