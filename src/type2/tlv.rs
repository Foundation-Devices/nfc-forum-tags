// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! TLV block parsing and building for Type 2 Tags.
//!
//! The data area of a Type 2 Tag contains a sequence of TLV blocks
//! (Section 2.3 of T2TOP 1.1):
//!
//! | Tag | Name             | L field | V field              |
//! |-----|------------------|---------|----------------------|
//! | 00h | NULL             | —       | —                    |
//! | 01h | Lock Control     | 03h     | position/size/ctrl   |
//! | 02h | Memory Control   | 03h     | position/size/ctrl   |
//! | 03h | NDEF Message     | var     | NDEF message bytes   |
//! | FDh | Proprietary      | var     | proprietary data     |
//! | FEh | Terminator       | —       | —                    |

use super::Type2Error;
use super::memory::ADDRESS_SPACE_END;
use crate::tlv::{self as shared_tlv, MAX_TLV_LENGTH, TlvError};
use crate::vec::{DataVec, VecExt};

/// TLV tag field values.
pub const TLV_NULL: u8 = 0x00;
pub const TLV_LOCK_CONTROL: u8 = 0x01;
pub const TLV_MEMORY_CONTROL: u8 = 0x02;
pub const TLV_NDEF_MESSAGE: u8 = 0x03;
pub const TLV_PROPRIETARY: u8 = 0xFD;
pub const TLV_TERMINATOR: u8 = 0xFE;

/// A parsed TLV block from the Type 2 Tag data area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tlv {
    /// NULL TLV (0x00): padding, no length or value.
    Null,
    /// Lock Control TLV (0x01): describes dynamic lock bit positions.
    LockControl(LockControlValue),
    /// Memory Control TLV (0x02): describes reserved memory areas.
    MemoryControl(MemoryControlValue),
    /// NDEF Message TLV (0x03): contains the NDEF message payload.
    NdefMessage(DataVec),
    /// Proprietary TLV (0xFD): opaque vendor data.
    Proprietary(DataVec),
    /// Terminator TLV (0xFE): marks end of TLV area.
    Terminator,
}

/// Lock Control TLV value (3 bytes, Section 2.3.2).
///
/// Describes the position and size of a dynamic lock area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockControlValue {
    /// Page address (upper nibble of position byte).
    pub page_addr: u8,
    /// Byte offset within the page (lower nibble of position byte).
    pub byte_offset: u8,
    /// Number of dynamic lock bits (0x00 = 256).
    pub size_in_bits: u16,
    /// Bytes per page exponent: actual bytes = 2^bytes_per_page.
    pub bytes_per_page: u8,
    /// Bytes locked per lock bit exponent: actual bytes = 2^bytes_locked_per_bit.
    pub bytes_locked_per_bit: u8,
}

impl LockControlValue {
    /// Byte address of the lock area start in the tag's linear address space.
    ///
    /// Computed in `u32`: `bytes_per_page` may encode a page size up to
    /// `2^15`, so a standards-valid control TLV can describe an address far
    /// above `u16::MAX` (e.g. `PageAddr = 7`, `BytesPerPage = 15` is byte
    /// 229,376). Narrower arithmetic panicked in overflow-checked builds and
    /// silently wrapped otherwise.
    pub fn byte_address(&self) -> u32 {
        let page_size = 1u32 << self.bytes_per_page;
        self.page_addr as u32 * page_size + self.byte_offset as u32
    }

    /// Number of lock bytes (ceiling of size_in_bits / 8).
    pub fn lock_byte_count(&self) -> u16 {
        self.size_in_bits.div_ceil(8)
    }

    /// Number of data bytes each lock bit protects.
    pub fn bytes_per_lock_bit(&self) -> u16 {
        1u16 << self.bytes_locked_per_bit
    }

    /// Parse from 3 raw bytes.
    pub fn from_bytes(bytes: [u8; 3]) -> Result<Self, Type2Error> {
        let page_addr = bytes[0] >> 4;
        let byte_offset = bytes[0] & 0x0F;
        let size_in_bits = if bytes[1] == 0 { 256 } else { bytes[1] as u16 };
        let bytes_per_page = bytes[2] & 0x0F;
        let bytes_locked_per_bit = bytes[2] >> 4;

        if bytes_per_page == 0 || bytes_locked_per_bit == 0 {
            return Err(Type2Error::InvalidTlv);
        }

        let value = LockControlValue {
            page_addr,
            byte_offset,
            size_in_bits,
            bytes_per_page,
            bytes_locked_per_bit,
        };

        // The exponent nibbles are only range-checked for zero above, so a
        // standards-shaped descriptor can still point outside the tag's
        // addressable memory (page 15 at a 2^15 page size is byte 491,520,
        // beyond the last sector). Reject the whole descriptor here rather
        // than carrying an address that describes no real byte.
        check_area_in_address_space(value.byte_address(), value.lock_byte_count())?;
        Ok(value)
    }

    /// Serialize to 3 bytes.
    pub fn to_bytes(&self) -> [u8; 3] {
        let size_raw = if self.size_in_bits == 256 {
            0
        } else {
            self.size_in_bits as u8
        };
        [
            (self.page_addr << 4) | (self.byte_offset & 0x0F),
            size_raw,
            (self.bytes_locked_per_bit << 4) | (self.bytes_per_page & 0x0F),
        ]
    }
}

/// Memory Control TLV value (3 bytes, Section 2.3.3).
///
/// Describes the position and size of a reserved memory area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryControlValue {
    /// Page address (upper nibble of position byte).
    pub page_addr: u8,
    /// Byte offset within the page (lower nibble of position byte).
    pub byte_offset: u8,
    /// Size of the reserved area in bytes (0x00 = 256).
    pub size_in_bytes: u16,
    /// Bytes per page exponent: actual bytes = 2^bytes_per_page.
    pub bytes_per_page: u8,
}

impl MemoryControlValue {
    /// Byte address of the reserved area start.
    ///
    /// Computed in `u32` for the same reason as
    /// [`LockControlValue::byte_address`]: a standards-valid page exponent can
    /// describe an address above `u16::MAX`.
    pub fn byte_address(&self) -> u32 {
        let page_size = 1u32 << self.bytes_per_page;
        self.page_addr as u32 * page_size + self.byte_offset as u32
    }

    /// Parse from 3 raw bytes.
    pub fn from_bytes(bytes: [u8; 3]) -> Result<Self, Type2Error> {
        let page_addr = bytes[0] >> 4;
        let byte_offset = bytes[0] & 0x0F;
        let size_in_bytes = if bytes[1] == 0 { 256 } else { bytes[1] as u16 };
        let bytes_per_page = bytes[2] & 0x0F;

        if bytes_per_page == 0 {
            return Err(Type2Error::InvalidTlv);
        }

        let value = MemoryControlValue {
            page_addr,
            byte_offset,
            size_in_bytes,
            bytes_per_page,
        };

        // Same address-space validation as the Lock Control descriptor.
        check_area_in_address_space(value.byte_address(), value.size_in_bytes)?;
        Ok(value)
    }

    /// Serialize to 3 bytes.
    pub fn to_bytes(&self) -> [u8; 3] {
        let size_raw = if self.size_in_bytes == 256 {
            0
        } else {
            self.size_in_bytes as u8
        };
        [
            (self.page_addr << 4) | (self.byte_offset & 0x0F),
            size_raw,
            self.bytes_per_page & 0x0F,
        ]
    }
}

/// Verify that a control descriptor's whole range lies inside the tag's
/// addressable memory (sectors `0x00`–`0xFE`).
///
/// Note this bounds the range against the *address space*, not against the
/// Capability Container data area: lock and reserved regions legitimately sit
/// outside the data area — the default dynamic lock area is defined to begin
/// immediately after it — so bounding them by the CC would reject valid tags.
fn check_area_in_address_space(start: u32, size: u16) -> Result<(), Type2Error> {
    let end = start
        .checked_add(size as u32)
        .ok_or(Type2Error::InvalidTlv)?;
    if start >= ADDRESS_SPACE_END || end > ADDRESS_SPACE_END {
        return Err(Type2Error::InvalidTlv);
    }
    Ok(())
}

/// Parse the TLV length field starting at `data[offset]`.
///
/// Returns `(length_value, bytes_consumed)`.
fn parse_tlv_length(data: &[u8], offset: usize) -> Result<(u16, usize), Type2Error> {
    shared_tlv::parse_tlv_length(data, offset).map_err(|_| Type2Error::InvalidTlv)
}

/// Encode a TLV length field into `out`.
fn encode_tlv_length(len: u16, out: &mut DataVec) -> Result<(), Type2Error> {
    shared_tlv::encode_tlv_length(len, out).map_err(|e| match e {
        TlvError::BufferFull => Type2Error::BufferFull,
        TlvError::InvalidTlv => Type2Error::InvalidTlv,
    })
}

/// Parse a sequence of TLV blocks from the data area.
///
/// `data` should be the raw bytes of the data area starting from block 4,
/// with lock and reserved bytes already skipped or included (the parser
/// processes them as-is from the byte stream).
///
/// Parsing stops at a Terminator TLV or end of data.
#[cfg(not(feature = "alloc"))]
pub fn parse_tlvs(data: &[u8]) -> Result<heapless::Vec<Tlv, 4>, Type2Error> {
    let mut result = heapless::Vec::new();
    parse_tlvs_into(data, &mut result)?;
    Ok(result)
}

#[cfg(feature = "alloc")]
pub fn parse_tlvs(data: &[u8]) -> Result<alloc::vec::Vec<Tlv>, Type2Error> {
    let mut result = alloc::vec::Vec::new();
    parse_tlvs_into(data, &mut result)?;
    Ok(result)
}

/// Internal TLV parser that appends into any container implementing push semantics.
fn parse_tlvs_into<C: TlvCollector>(data: &[u8], out: &mut C) -> Result<(), Type2Error> {
    let mut offset = 0;

    while offset < data.len() {
        let tag = data[offset];
        offset += 1;

        match tag {
            TLV_NULL => {
                out.push_tlv(Tlv::Null)?;
            }
            TLV_TERMINATOR => {
                out.push_tlv(Tlv::Terminator)?;
                return Ok(());
            }
            TLV_LOCK_CONTROL => {
                let (len, consumed) = parse_tlv_length(data, offset)?;
                offset += consumed;
                if len != 3 || offset + 3 > data.len() {
                    return Err(Type2Error::InvalidTlv);
                }
                let value = LockControlValue::from_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                ])?;
                offset += 3;
                out.push_tlv(Tlv::LockControl(value))?;
            }
            TLV_MEMORY_CONTROL => {
                let (len, consumed) = parse_tlv_length(data, offset)?;
                offset += consumed;
                if len != 3 || offset + 3 > data.len() {
                    return Err(Type2Error::InvalidTlv);
                }
                let value = MemoryControlValue::from_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                ])?;
                offset += 3;
                out.push_tlv(Tlv::MemoryControl(value))?;
            }
            TLV_NDEF_MESSAGE => {
                let (len, consumed) = parse_tlv_length(data, offset)?;
                offset += consumed;
                let len = len as usize;
                if offset + len > data.len() {
                    return Err(Type2Error::InvalidTlv);
                }
                let mut v = DataVec::new();
                v.try_extend(&data[offset..offset + len])?;
                offset += len;
                out.push_tlv(Tlv::NdefMessage(v))?;
            }
            TLV_PROPRIETARY => {
                let (len, consumed) = parse_tlv_length(data, offset)?;
                offset += consumed;
                let len = len as usize;
                if offset + len > data.len() {
                    return Err(Type2Error::InvalidTlv);
                }
                let mut v = DataVec::new();
                v.try_extend(&data[offset..offset + len])?;
                offset += len;
                out.push_tlv(Tlv::Proprietary(v))?;
            }
            _ => {
                // Unknown/reserved TLV: read length and skip.
                let (len, consumed) = parse_tlv_length(data, offset)?;
                offset += consumed;
                offset += len as usize;
                if offset > data.len() {
                    return Err(Type2Error::InvalidTlv);
                }
            }
        }
    }

    Ok(())
}

/// Abstraction for pushing TLVs into different container types.
trait TlvCollector {
    fn push_tlv(&mut self, tlv: Tlv) -> Result<(), Type2Error>;
}

#[cfg(not(feature = "alloc"))]
impl TlvCollector for heapless::Vec<Tlv, 4> {
    fn push_tlv(&mut self, tlv: Tlv) -> Result<(), Type2Error> {
        self.push(tlv).map_err(|_| Type2Error::BufferFull)
    }
}

#[cfg(feature = "alloc")]
impl TlvCollector for alloc::vec::Vec<Tlv> {
    fn push_tlv(&mut self, tlv: Tlv) -> Result<(), Type2Error> {
        self.push(tlv);
        Ok(())
    }
}

impl Tlv {
    /// Serialize this TLV block to bytes.
    pub fn to_bytes(&self) -> Result<DataVec, Type2Error> {
        let mut out = DataVec::new();
        match self {
            Tlv::Null => {
                out.try_push(TLV_NULL)?;
            }
            Tlv::Terminator => {
                out.try_push(TLV_TERMINATOR)?;
            }
            Tlv::LockControl(v) => {
                out.try_push(TLV_LOCK_CONTROL)?;
                out.try_push(0x03)?;
                out.try_extend(&v.to_bytes())?;
            }
            Tlv::MemoryControl(v) => {
                out.try_push(TLV_MEMORY_CONTROL)?;
                out.try_push(0x03)?;
                out.try_extend(&v.to_bytes())?;
            }
            Tlv::NdefMessage(data) => {
                // Validate the untruncated length *before* emitting anything,
                // so an oversized value can never produce a TLV whose declared
                // length disagrees with the bytes that follow it.
                let len = checked_value_length(data.len())?;
                out.try_push(TLV_NDEF_MESSAGE)?;
                encode_tlv_length(len, &mut out)?;
                out.try_extend(data)?;
            }
            Tlv::Proprietary(data) => {
                let len = checked_value_length(data.len())?;
                out.try_push(TLV_PROPRIETARY)?;
                encode_tlv_length(len, &mut out)?;
                out.try_extend(data)?;
            }
        }
        Ok(out)
    }

    /// If this is an NDEF Message TLV, return the raw NDEF bytes.
    pub fn ndef_data(&self) -> Option<&[u8]> {
        match self {
            Tlv::NdefMessage(data) => Some(data),
            _ => None,
        }
    }

    /// The length of the V field (0 for NULL/Terminator).
    ///
    /// Returns [`Type2Error::OutOfRange`] when the value is longer than a TLV
    /// length field can represent. Reporting a truncated length here previously
    /// let a 65,536-byte value claim length zero.
    pub fn value_length(&self) -> Result<u16, Type2Error> {
        match self {
            Tlv::Null | Tlv::Terminator => Ok(0),
            Tlv::LockControl(_) | Tlv::MemoryControl(_) => Ok(3),
            Tlv::NdefMessage(data) | Tlv::Proprietary(data) => checked_value_length(data.len()),
        }
    }
}

/// Convert a value length to the TLV length field width, rejecting anything
/// the encoding cannot represent (including the reserved `0xFFFF`).
fn checked_value_length(len: usize) -> Result<u16, Type2Error> {
    match u16::try_from(len) {
        Ok(l) if l <= MAX_TLV_LENGTH => Ok(l),
        _ => Err(Type2Error::OutOfRange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_static_tag_tlvs() {
        // From spec Appendix B.1: NDEF Message TLV (empty) + Terminator
        let data = [0x03, 0x00, 0xFE];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0], Tlv::NdefMessage(DataVec::new()));
        assert_eq!(tlvs[1], Tlv::Terminator);
    }

    #[test]
    fn parse_static_tag_with_ndef() {
        // NDEF Message TLV with empty NDEF message D00000h + Terminator
        let data = [0x03, 0x03, 0xD0, 0x00, 0x00, 0xFE];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        let expected_ndef = {
            let mut v = DataVec::new();
            let _ = v.try_extend(&[0xD0, 0x00, 0x00]);
            v
        };
        assert_eq!(tlvs[0], Tlv::NdefMessage(expected_ndef));
        assert_eq!(tlvs[1], Tlv::Terminator);
    }

    #[test]
    fn parse_dynamic_tag_tlvs() {
        // From spec Appendix B.2 / C.7:
        // Lock Control TLV + Memory Control TLV + NDEF Message TLV (empty)
        #[rustfmt::skip]
        let data = [
            0x01, 0x03, 0xE0, 0x06, 0x33, // Lock Control TLV
            0x02, 0x03, 0xE1, 0x0F, 0x03, // Memory Control TLV
            0x03, 0x00,                     // NDEF Message TLV (empty)
            0xFE,                           // Terminator
        ];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 4);

        // Lock Control TLV
        if let Tlv::LockControl(lc) = &tlvs[0] {
            assert_eq!(lc.page_addr, 0x0E);
            assert_eq!(lc.byte_offset, 0x00);
            assert_eq!(lc.size_in_bits, 6);
            assert_eq!(lc.bytes_per_page, 3);
            assert_eq!(lc.bytes_locked_per_bit, 3);
            // ByteAddr = 14 * 2^3 + 0 = 112
            assert_eq!(lc.byte_address(), 112);
        } else {
            panic!("Expected LockControl TLV");
        }

        // Memory Control TLV
        if let Tlv::MemoryControl(mc) = &tlvs[1] {
            assert_eq!(mc.page_addr, 0x0E);
            assert_eq!(mc.byte_offset, 0x01);
            assert_eq!(mc.size_in_bytes, 15);
            assert_eq!(mc.bytes_per_page, 3);
            // ByteAddr = 14 * 2^3 + 1 = 113
            assert_eq!(mc.byte_address(), 113);
        } else {
            panic!("Expected MemoryControl TLV");
        }

        assert_eq!(tlvs[2], Tlv::NdefMessage(DataVec::new()));
        assert_eq!(tlvs[3], Tlv::Terminator);
    }

    #[test]
    fn null_tlv_padding() {
        let data = [0x00, 0x00, 0x03, 0x00, 0xFE];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 4);
        assert_eq!(tlvs[0], Tlv::Null);
        assert_eq!(tlvs[1], Tlv::Null);
        assert_eq!(tlvs[2], Tlv::NdefMessage(DataVec::new()));
        assert_eq!(tlvs[3], Tlv::Terminator);
    }

    #[test]
    fn skip_unknown_tlv() {
        // Unknown tag 0x04 with 2 bytes of data, then terminator
        let data = [0x04, 0x02, 0xAA, 0xBB, 0xFE];
        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0], Tlv::Terminator);
    }

    #[test]
    fn three_byte_length_format() {
        // NDEF Message TLV with 3-byte length (0xFF, 0x01, 0x00 = 256 bytes)
        let mut data = [0u8; 4 + 256 + 1];
        data[0] = 0x03;
        data[1] = 0xFF;
        data[2] = 0x01;
        data[3] = 0x00;
        data[4..260].fill(0xAA);
        data[260] = 0xFE;

        let tlvs = parse_tlvs(&data).unwrap();
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].value_length(), Ok(256));
        assert_eq!(tlvs[1], Tlv::Terminator);
    }

    #[test]
    fn roundtrip_lock_control_value() {
        let lc = LockControlValue {
            page_addr: 0x0E,
            byte_offset: 0x00,
            size_in_bits: 6,
            bytes_per_page: 3,
            bytes_locked_per_bit: 3,
        };
        let bytes = lc.to_bytes();
        assert_eq!(bytes, [0xE0, 0x06, 0x33]);
        let parsed = LockControlValue::from_bytes(bytes).unwrap();
        assert_eq!(parsed, lc);
    }

    #[test]
    fn roundtrip_memory_control_value() {
        let mc = MemoryControlValue {
            page_addr: 0x0E,
            byte_offset: 0x01,
            size_in_bytes: 15,
            bytes_per_page: 3,
        };
        let bytes = mc.to_bytes();
        assert_eq!(bytes, [0xE1, 0x0F, 0x03]);
        let parsed = MemoryControlValue::from_bytes(bytes).unwrap();
        assert_eq!(parsed, mc);
    }

    #[test]
    fn roundtrip_ndef_tlv() {
        let mut ndef_data = DataVec::new();
        let _ = ndef_data.try_extend(&[0xD0, 0x00, 0x00]);
        let tlv = Tlv::NdefMessage(ndef_data);
        let bytes = tlv.to_bytes().unwrap();
        assert_eq!(&*bytes, &[0x03, 0x03, 0xD0, 0x00, 0x00]);

        let parsed = parse_tlvs(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], tlv);
    }

    // ── Control-TLV address-space validation (SFT-7603) ────────────

    /// The audit's demonstrated Lock Control TLV describes byte 491,520
    /// (page 15 at a 2^15 page size), well past the last addressable sector.
    /// It must be rejected as InvalidTlv, identically in every build profile.
    #[test]
    fn demonstrated_lock_control_tlv_is_rejected() {
        assert_eq!(
            LockControlValue::from_bytes([0xF0, 0x08, 0x1F]),
            Err(Type2Error::InvalidTlv)
        );
        // And through the full TLV stream, as a tag would present it.
        let data = [0x01, 0x03, 0xF0, 0x08, 0x1F, 0xFE];
        assert_eq!(parse_tlvs(&data), Err(Type2Error::InvalidTlv));
    }

    /// Descriptors whose range fits the address space are still accepted, so
    /// the validation does not reject legitimate tags.
    #[test]
    fn in_range_control_tlvs_still_accepted() {
        // 7 * 2^15 = 229,376 — large but inside the addressable space.
        let lc = LockControlValue::from_bytes([0x70, 0x08, 0x3F]).unwrap();
        assert_eq!(lc.byte_address(), 229_376);
        // A typical small descriptor.
        let lc = LockControlValue::from_bytes([0xE0, 0x06, 0x33]).unwrap();
        assert_eq!(lc.byte_address(), 112);
        let mc = MemoryControlValue::from_bytes([0xE1, 0x0F, 0x03]).unwrap();
        assert_eq!(mc.byte_address(), 113);
    }

    /// Every combination of both exponent nibbles, across page addresses and
    /// byte offsets, must parse or fail cleanly — never panic, and never yield
    /// a descriptor reaching outside the address space.
    #[test]
    fn all_exponent_combinations_are_safe() {
        for page_addr in 0u8..16 {
            for byte_offset in 0u8..16 {
                let b0 = (page_addr << 4) | byte_offset;
                for size in [0x00u8, 0x01, 0x08, 0x80, 0xFF] {
                    for bytes_per_page in 0u8..16 {
                        for locked_per_bit in 0u8..16 {
                            let b2 = (locked_per_bit << 4) | bytes_per_page;
                            if let Ok(lc) = LockControlValue::from_bytes([b0, size, b2]) {
                                let end = lc.byte_address() + lc.lock_byte_count() as u32;
                                assert!(end <= ADDRESS_SPACE_END, "lock area escapes space");
                            }
                            if let Ok(mc) = MemoryControlValue::from_bytes([b0, size, b2]) {
                                let end = mc.byte_address() + mc.size_in_bytes as u32;
                                assert!(end <= ADDRESS_SPACE_END, "reserved area escapes space");
                            }
                        }
                    }
                }
            }
        }
    }

    // ── Oversized value serialization (SFT-7597) ───────────────────

    /// Build a `DataVec` of `n` bytes, or `None` if the buffer cannot hold it
    /// (fixed-capacity default builds cap at 1024).
    fn value_of(n: usize) -> Option<DataVec> {
        let mut v = DataVec::new();
        for _ in 0..n {
            v.try_push(0xAB).ok()?;
        }
        Some(v)
    }

    /// A value longer than the TLV length field can represent must be rejected
    /// with a stable error and emit no partial output — never a zero length
    /// followed by the full payload.
    #[test]
    fn serializer_rejects_oversized_values() {
        // 0xFFFE is the largest representable length; 0xFFFF is reserved and
        // 0x10000 overflows the field entirely.
        for len in [0xFFFFusize, 0x10000, 0x20000] {
            let Some(data) = value_of(len) else {
                continue; // buffer too small in this build to construct the case
            };
            for tlv in [
                Tlv::NdefMessage(data.clone()),
                Tlv::Proprietary(data.clone()),
            ] {
                assert_eq!(
                    tlv.value_length(),
                    Err(Type2Error::OutOfRange),
                    "len {len} must not report a truncated length"
                );
                assert!(
                    matches!(tlv.to_bytes(), Err(Type2Error::OutOfRange)),
                    "len {len} must not serialize"
                );
            }
        }
    }

    /// The exact maximum representable value still serializes correctly, with
    /// the 3-byte length format and the full payload.
    #[test]
    fn serializer_accepts_max_representable_value() {
        let Some(data) = value_of(MAX_TLV_LENGTH as usize) else {
            return; // not constructible in fixed-capacity builds
        };
        let tlv = Tlv::NdefMessage(data);
        assert_eq!(tlv.value_length(), Ok(MAX_TLV_LENGTH));
        let bytes = tlv.to_bytes().unwrap();
        assert_eq!(&bytes[..4], &[TLV_NDEF_MESSAGE, 0xFF, 0xFF, 0xFE]);
        assert_eq!(bytes.len(), 4 + MAX_TLV_LENGTH as usize);
    }
}
