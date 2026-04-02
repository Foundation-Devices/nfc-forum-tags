// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! NFC Forum Type 2 Tag operations (T2TOP 1.1).
//!
//! This module implements the command set, memory model, and NDEF access
//! procedures for Type 2 Tags as defined in the NFC Forum Type 2 Tag
//! Operation Specification version 1.1.
//!
//! # Protocol overview
//!
//! After ISO 14443-3A activation (REQA → anticollision → SELECT), the
//! SAK byte indicates a Type 2 Tag (non-ISO14443-4 compliant). At that
//! point, the three commands defined here take over:
//!
//! - [`Command::Read`] — read 4 blocks (16 bytes)
//! - [`Command::Write`] — write 1 block (4 bytes)
//! - [`Command::SectorSelectPart1`] / [`Command::SectorSelectPart2`] — switch sector for tags > 1 KB

pub mod cc;
pub mod memory;
pub mod reader;
pub mod tlv;

pub use cc::{AccessCondition, CapabilityContainer, TagState};
pub use memory::{LockArea, MemoryLayout, ReservedArea};
pub use reader::{ReaderError, T2TReader};
pub use tlv::{LockControlValue, MemoryControlValue, Tlv};

use crate::vec::{BufferFullError, FrameVec, VecExt};

// ── Error ──────────────────────────────────────────────────────────

/// Errors from Type 2 Tag protocol operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type2Error {
    /// Response length does not match expected format.
    InvalidLength,
    /// Capability Container magic byte is not 0xE1.
    InvalidMagic(u8),
    /// CC version not supported by this implementation.
    UnsupportedVersion { major: u8, minor: u8 },
    /// Tag responded with a NACK (4-bit error code).
    Nack(u8),
    /// TLV block is malformed.
    InvalidTlv,
    /// Tag is in READ-ONLY state.
    ReadOnly,
    /// Internal buffer is full.
    BufferFull,
    /// Block number or sector exceeds tag capacity.
    OutOfRange,
    /// Unknown command code when parsing.
    UnknownCommand(u8),
}

impl From<BufferFullError> for Type2Error {
    fn from(_: BufferFullError) -> Self {
        Type2Error::BufferFull
    }
}

// ── Transceiver trait ──────────────────────────────────────────────

/// Hardware abstraction for NFC Type 2 Tag communication.
///
/// Implementors handle the physical layer including CRC_A.
/// Commands are provided **without** CRC; the transceiver appends
/// CRC_A on transmit and validates/strips it on receive.
///
/// This trait is intentionally independent of `iso14443::PcdTransceiver`.
/// A thin adapter can bridge the two.
pub trait T2TTransceiver {
    type Error;

    /// Transmit a command and receive the response.
    ///
    /// - For READ: returns 16 payload bytes (CRC already stripped).
    /// - For WRITE / SECTOR SELECT Packet 1: returns a single byte
    ///   containing the 4-bit ACK (0x0A) or NACK value.
    fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, Self::Error>;

    /// Transmit a command expecting silence (passive ACK) or a NACK.
    ///
    /// Used for SECTOR SELECT Packet 2 where success means no response.
    /// Returns `Ok(None)` for passive ACK (success) or `Ok(Some(nack))`
    /// for a NACK response.
    fn transceive_no_response(&mut self, cmd: &[u8]) -> Result<Option<u8>, Self::Error>;
}

// ── Command codes ──────────────────────────────────────────────────

/// READ command code (Section 5.1).
pub const CMD_READ: u8 = 0x30;
/// WRITE command code (Section 5.2).
pub const CMD_WRITE: u8 = 0xA2;
/// SECTOR SELECT command code (Section 5.3).
pub const CMD_SECTOR_SELECT: u8 = 0xC2;

/// ACK response value (4 bits).
pub const ACK: u8 = 0x0A;

// ── Command ────────────────────────────────────────────────────────

/// Type 2 Tag command set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// READ: read 4 blocks (16 bytes) starting at `block_no`.
    ///
    /// Wire format: `[0x30, block_no]` + CRC_A.
    Read { block_no: u8 },

    /// WRITE: write 4 bytes to `block_no`.
    ///
    /// Wire format: `[0xA2, block_no, data[0..4]]` + CRC_A.
    Write { block_no: u8, data: [u8; 4] },

    /// SECTOR SELECT Packet 1.
    ///
    /// Wire format: `[0xC2, 0xFF]` + CRC_A.
    SectorSelectPart1,

    /// SECTOR SELECT Packet 2.
    ///
    /// Wire format: `[sector_no, 0x00, 0x00, 0x00]` + CRC_A.
    SectorSelectPart2 { sector_no: u8 },
}

impl Command {
    /// Serialize this command to wire bytes (without CRC).
    pub fn to_bytes(&self) -> FrameVec {
        let mut v = FrameVec::new();
        match self {
            Command::Read { block_no } => {
                // Infallible: 2 bytes always fits in FrameVec(20).
                let _ = v.try_extend(&[CMD_READ, *block_no]);
            }
            Command::Write { block_no, data } => {
                // 6 bytes total.
                let _ = v.try_extend(&[CMD_WRITE, *block_no]);
                let _ = v.try_extend(data);
            }
            Command::SectorSelectPart1 => {
                let _ = v.try_extend(&[CMD_SECTOR_SELECT, 0xFF]);
            }
            Command::SectorSelectPart2 { sector_no } => {
                let _ = v.try_extend(&[*sector_no, 0x00, 0x00, 0x00]);
            }
        }
        v
    }

    /// Parse a response for this command.
    ///
    /// The caller must provide the raw response bytes (CRC already
    /// stripped by the transceiver). For ACK/NACK responses the
    /// transceiver should return a single byte with the 4-bit value.
    pub fn parse_answer(&self, raw: &[u8]) -> Result<Answer, Type2Error> {
        match self {
            Command::Read { .. } => {
                if raw.len() < 16 {
                    return Err(Type2Error::InvalidLength);
                }
                let mut data = [0u8; 16];
                data.copy_from_slice(&raw[..16]);
                Ok(Answer::Data(data))
            }
            Command::Write { .. } | Command::SectorSelectPart1 => {
                if raw.is_empty() {
                    return Err(Type2Error::InvalidLength);
                }
                let val = raw[0] & 0x0F;
                if val == ACK {
                    Ok(Answer::Ack)
                } else {
                    Ok(Answer::Nack(val))
                }
            }
            Command::SectorSelectPart2 { .. } => {
                // Passive ACK = no response. If we got bytes, it's a NACK.
                if raw.is_empty() {
                    Ok(Answer::PassiveAck)
                } else {
                    let val = raw[0] & 0x0F;
                    Ok(Answer::Nack(val))
                }
            }
        }
    }
}

impl TryFrom<&[u8]> for Command {
    type Error = Type2Error;

    /// Parse a command from wire bytes (without CRC).
    fn try_from(raw: &[u8]) -> Result<Self, Type2Error> {
        if raw.is_empty() {
            return Err(Type2Error::InvalidLength);
        }
        match raw[0] {
            CMD_READ => {
                if raw.len() < 2 {
                    return Err(Type2Error::InvalidLength);
                }
                Ok(Command::Read { block_no: raw[1] })
            }
            CMD_WRITE => {
                if raw.len() < 6 {
                    return Err(Type2Error::InvalidLength);
                }
                let mut data = [0u8; 4];
                data.copy_from_slice(&raw[2..6]);
                Ok(Command::Write {
                    block_no: raw[1],
                    data,
                })
            }
            CMD_SECTOR_SELECT => {
                if raw.len() < 2 {
                    return Err(Type2Error::InvalidLength);
                }
                if raw[1] == 0xFF {
                    Ok(Command::SectorSelectPart1)
                } else {
                    Err(Type2Error::InvalidLength)
                }
            }
            other => Err(Type2Error::UnknownCommand(other)),
        }
    }
}

// ── Answer ─────────────────────────────────────────────────────────

/// Parsed response from a Type 2 Tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// 16 bytes of data from a READ command (4 blocks).
    Data([u8; 16]),
    /// ACK response (0x0A) to WRITE or SECTOR SELECT Packet 1.
    Ack,
    /// NACK response with the 4-bit error code.
    Nack(u8),
    /// Passive ACK (silence) — SECTOR SELECT Packet 2 success.
    PassiveAck,
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_command_serialization() {
        let cmd = Command::Read { block_no: 0x03 };
        let bytes = cmd.to_bytes();
        assert_eq!(&*bytes, &[0x30, 0x03]);
    }

    #[test]
    fn write_command_serialization() {
        let cmd = Command::Write {
            block_no: 0x04,
            data: [0x03, 0x00, 0xFE, 0x00],
        };
        let bytes = cmd.to_bytes();
        assert_eq!(&*bytes, &[0xA2, 0x04, 0x03, 0x00, 0xFE, 0x00]);
    }

    #[test]
    fn sector_select_p1_serialization() {
        let cmd = Command::SectorSelectPart1;
        let bytes = cmd.to_bytes();
        assert_eq!(&*bytes, &[0xC2, 0xFF]);
    }

    #[test]
    fn sector_select_p2_serialization() {
        let cmd = Command::SectorSelectPart2 { sector_no: 0x01 };
        let bytes = cmd.to_bytes();
        assert_eq!(&*bytes, &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn parse_read_response() {
        let cmd = Command::Read { block_no: 0x03 };
        let raw = [
            0xE1, 0x10, 0x06, 0x00, // CC block
            0x03, 0x00, 0xFE, 0x00, // data block
            0x00, 0x00, 0x00, 0x00, // data block
            0x00, 0x00, 0x00, 0x00, // data block
        ];
        let answer = cmd.parse_answer(&raw).unwrap();
        assert_eq!(answer, Answer::Data(raw));
    }

    #[test]
    fn parse_ack_response() {
        let cmd = Command::Write {
            block_no: 0x04,
            data: [0; 4],
        };
        let answer = cmd.parse_answer(&[0x0A]).unwrap();
        assert_eq!(answer, Answer::Ack);
    }

    #[test]
    fn parse_nack_response() {
        let cmd = Command::Write {
            block_no: 0x04,
            data: [0; 4],
        };
        let answer = cmd.parse_answer(&[0x00]).unwrap();
        assert_eq!(answer, Answer::Nack(0x00));
    }

    #[test]
    fn parse_passive_ack() {
        let cmd = Command::SectorSelectPart2 { sector_no: 1 };
        let answer = cmd.parse_answer(&[]).unwrap();
        assert_eq!(answer, Answer::PassiveAck);
    }

    #[test]
    fn roundtrip_read_command() {
        let cmd = Command::Read { block_no: 0x10 };
        let bytes = cmd.to_bytes();
        let parsed = Command::try_from(bytes.as_slice()).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn roundtrip_write_command() {
        let cmd = Command::Write {
            block_no: 0x05,
            data: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = cmd.to_bytes();
        let parsed = Command::try_from(bytes.as_slice()).unwrap();
        assert_eq!(parsed, cmd);
    }

    #[test]
    fn roundtrip_sector_select_p1() {
        let cmd = Command::SectorSelectPart1;
        let bytes = cmd.to_bytes();
        let parsed = Command::try_from(bytes.as_slice()).unwrap();
        assert_eq!(parsed, cmd);
    }
}
