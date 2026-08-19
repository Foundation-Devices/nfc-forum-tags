// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! High-level Type 2 Tag reader/writer.
//!
//! [`T2TReader`] orchestrates command sequences for NDEF detection,
//! reading, and writing on a Type 2 Tag after ISO 14443-3A activation.

use super::cc::CapabilityContainer;
use super::memory::{BLOCK_SIZE, CC_BLOCK, DATA_START_BLOCK, MAX_SECTOR, MemoryLayout};
use super::tlv::{self, Tlv};
use super::{Answer, Command, T2TTransceiver, Type2Error};
use crate::tag::AccessCondition;
use crate::vec::{DataVec, VecExt};

/// Errors from the T2T reader, wrapping transport and protocol errors.
#[derive(Debug)]
pub enum ReaderError<E> {
    /// The transceiver returned an error.
    Transceiver(E),
    /// Type 2 Tag protocol violation.
    Protocol(Type2Error),
}

impl<E> From<Type2Error> for ReaderError<E> {
    fn from(e: Type2Error) -> Self {
        ReaderError::Protocol(e)
    }
}

/// Default number of retries on transient transceiver errors.
const DEFAULT_MAX_RETRIES: u8 = 1;

/// Tracked sector-selection state.
///
/// Block numbers are sector-relative, so the reader must never assume which
/// sector is active after an ambiguous failure. A Type 2 protocol infringement
/// resets the tag to sector 0, and a transceiver error cannot distinguish
/// "not transmitted" from "applied, but the response was lost" — either way the
/// cached sector may no longer match the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectorState {
    /// The tag is known to have this sector selected.
    Known(u8),
    /// The active sector is unknown; it must be re-established before any
    /// sector-relative command.
    Unknown,
}

/// High-level NFC Forum Type 2 Tag reader/writer.
///
/// Wraps a [`T2TTransceiver`] and tracks the currently selected sector.
/// Maintains a 16-byte read cache to avoid redundant RF transactions.
/// Retries transient transceiver errors up to `max_retries` times.
pub struct T2TReader<'t, T: T2TTransceiver<N>, const N: usize> {
    transceiver: &'t mut T,
    sector: SectorState,
    /// Cached 16-byte READ result: (block_no, data).
    cache_block: Option<u8>,
    cache_data: [u8; 16],
    /// Maximum number of retries on transient transceiver errors.
    max_retries: u8,
}

impl<'t, T: T2TTransceiver<N>, const N: usize> T2TReader<'t, T, N> {
    /// Create a new reader. The default sector is 0.
    pub fn new(transceiver: &'t mut T) -> Self {
        T2TReader {
            transceiver,
            sector: SectorState::Known(0),
            cache_block: None,
            cache_data: [0u8; 16],
            max_retries: DEFAULT_MAX_RETRIES,
        }
    }

    /// Set the maximum number of retries on transient transceiver errors.
    ///
    /// Default is 1 (one retry after the initial attempt). Set to 0 to
    /// disable retries. Only transceiver-level errors are retried; NACK
    /// responses from the tag are not retried.
    pub fn set_max_retries(&mut self, n: u8) {
        self.max_retries = n;
    }

    /// Get the currently selected sector number.
    /// Returns `None` when the active sector is unknown after an ambiguous
    /// error; the next sector-relative operation re-establishes it.
    pub fn current_sector(&self) -> Option<u8> {
        match self.sector {
            SectorState::Known(s) => Some(s),
            SectorState::Unknown => None,
        }
    }

    /// Current sector-selection state, including whether it is unknown.
    pub fn sector_state(&self) -> SectorState {
        self.sector
    }

    /// Get a mutable reference to the underlying transceiver.
    ///
    /// Useful for sending custom commands (e.g., NTAG-specific extensions)
    /// that are not part of the T2T spec.
    pub fn transceiver(&mut self) -> &mut T {
        self.transceiver
    }

    /// Invalidate the read cache.
    ///
    /// Call this after sending custom write commands directly through
    /// the transceiver to ensure subsequent reads reflect the new state.
    pub fn invalidate_cache(&mut self) {
        self.cache_block = None;
    }

    /// Transceive with retry on transceiver errors.
    ///
    /// Retries up to `max_retries` times on transceiver-level errors.
    /// Useful for sending custom commands with the same retry behavior
    /// as the built-in READ/WRITE.
    /// A transceiver error makes the active sector ambiguous, so every retry
    /// first re-establishes the sector that was intended when the command was
    /// issued. Without that, a failure which reset the tag to sector 0 would
    /// silently redirect the retry to the same block number in the wrong
    /// sector. If the sector was already unknown, no retry is attempted.
    pub fn transceive_with_retry(
        &mut self,
        cmd: &[u8],
    ) -> Result<crate::vec::FrameVec<N>, ReaderError<T::Error>> {
        let intended = self.sector;
        let mut last_err = None;
        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                match intended {
                    // Re-select before retrying so the retry provably lands in
                    // the intended sector.
                    SectorState::Known(s) => self.force_sector_select(s)?,
                    // Sector unknown before the command: retrying could hit any
                    // sector, so stop and report the original error.
                    SectorState::Unknown => break,
                }
            }
            match self.transceiver.transceive(cmd) {
                Ok(raw) => return Ok(raw),
                Err(e) => {
                    // Ambiguous failure: the tag may have reset to sector 0.
                    self.sector = SectorState::Unknown;
                    self.invalidate_cache();
                    last_err = Some(e);
                }
            }
        }
        Err(ReaderError::Transceiver(last_err.unwrap()))
    }

    /// Read 4 blocks (16 bytes) starting at `block_no` in the current sector.
    ///
    /// Results are cached; subsequent reads of the same block will
    /// be served from the cache without an RF transaction. Transceiver
    /// errors are retried up to `max_retries` times.
    pub fn read(&mut self, block_no: u8) -> Result<[u8; 16], ReaderError<T::Error>> {
        if let Some(cached_block) = self.cache_block {
            if block_no == cached_block {
                return Ok(self.cache_data);
            }
        }

        let cmd = Command::Read { block_no };
        let raw = self.transceive_with_retry(&cmd.to_bytes())?;
        match cmd.parse_answer(&raw)? {
            Answer::Data(data) => {
                self.cache_block = Some(block_no);
                self.cache_data = data;
                Ok(data)
            }
            Answer::Nack(code) => Err(Type2Error::Nack(code).into()),
            _ => Err(Type2Error::InvalidLength.into()),
        }
    }

    /// Write 4 bytes to `block_no` in the current sector.
    ///
    /// Invalidates the read cache since the tag memory has changed.
    /// Transceiver errors are retried up to `max_retries` times.
    pub fn write(&mut self, block_no: u8, data: [u8; 4]) -> Result<(), ReaderError<T::Error>> {
        let cmd = Command::Write { block_no, data };
        let raw = self.transceive_with_retry(&cmd.to_bytes())?;
        self.invalidate_cache();
        match cmd.parse_answer(&raw)? {
            Answer::Ack => Ok(()),
            Answer::Nack(code) => Err(Type2Error::Nack(code).into()),
            _ => Err(Type2Error::InvalidLength.into()),
        }
    }

    /// Select a sector (for tags > 1 KB).
    ///
    /// Sends SECTOR SELECT Packet 1, expects ACK, then sends Packet 2
    /// and expects passive ACK (silence). Invalidates the read cache.
    /// Packet 1 retries on transceiver errors; Packet 2 does not retry
    /// since passive ACK (silence) makes retry semantics ambiguous.
    pub fn sector_select(&mut self, sector: u8) -> Result<(), ReaderError<T::Error>> {
        // Sector 0xFF is reserved by the protocol and must never be selected.
        if sector > MAX_SECTOR {
            return Err(Type2Error::OutOfRange.into());
        }
        if self.sector == SectorState::Known(sector) {
            return Ok(());
        }
        self.force_sector_select(sector)
    }

    /// Perform the SECTOR SELECT sequence unconditionally, without the
    /// known-state fast path.
    ///
    /// Any failure — transceiver error or NACK, in either packet — leaves the
    /// sector state [`SectorState::Unknown`] and the read cache invalidated,
    /// since the tag may or may not have applied the selection. Packet 1 is
    /// sent directly rather than through [`Self::transceive_with_retry`] to
    /// avoid recursing back into sector recovery.
    fn force_sector_select(&mut self, sector: u8) -> Result<(), ReaderError<T::Error>> {
        if sector > MAX_SECTOR {
            return Err(Type2Error::OutOfRange.into());
        }
        self.invalidate_cache();
        self.sector = SectorState::Unknown;

        // Packet 1: [0xC2, 0xFF]
        let cmd1 = Command::SectorSelectPart1;
        let raw = self
            .transceiver
            .transceive(&cmd1.to_bytes())
            .map_err(ReaderError::Transceiver)?;
        match cmd1.parse_answer(&raw)? {
            Answer::Ack => {}
            Answer::Nack(code) => return Err(Type2Error::Nack(code).into()),
            _ => return Err(Type2Error::InvalidLength.into()),
        }

        // Packet 2: [sector_no, 0x00, 0x00, 0x00] — passive ACK (silence) on
        // success. An error here is ambiguous: the tag may have applied the
        // selection anyway, so the state stays Unknown.
        let cmd2 = Command::SectorSelectPart2 { sector_no: sector };
        let nack = self
            .transceiver
            .transceive_no_response(&cmd2.to_bytes())
            .map_err(ReaderError::Transceiver)?;
        if let Some(nack_code) = nack {
            return Err(Type2Error::Nack(nack_code).into());
        }

        self.sector = SectorState::Known(sector);
        Ok(())
    }

    /// Read and parse the Capability Container (block 3).
    pub fn read_cc(&mut self) -> Result<CapabilityContainer, ReaderError<T::Error>> {
        // Ensure we're in sector 0 for CC.
        self.sector_select(0)?;
        let data = self.read(CC_BLOCK)?;
        let cc = CapabilityContainer::try_from([data[0], data[1], data[2], data[3]])?;
        Ok(cc)
    }

    /// Read the raw data area bytes, skipping lock and reserved areas.
    ///
    /// Returns the contiguous data area bytes with lock/reserved regions
    /// removed. Stops early when a Terminator TLV (`0xFE`) is encountered
    /// at a TLV tag position, avoiding unnecessary reads past the end of
    /// meaningful data.
    pub fn read_data_area(
        &mut self,
        layout: &MemoryLayout,
    ) -> Result<DataVec, ReaderError<T::Error>> {
        let mut result = DataVec::new();
        let total_bytes = layout.data_area_size;
        let mut bytes_read = 0u16;

        // Lightweight TLV scanner to detect the Terminator TLV (0xFE)
        // during reading, so we can stop early and avoid unnecessary reads.
        let mut tlv_scan = TlvScanner::new();

        // Start reading from block 4.
        let start_byte_addr = DATA_START_BLOCK as u32 * BLOCK_SIZE as u32;
        let mut byte_addr = start_byte_addr;

        // Read block by block (4 bytes at a time) to handle skip areas.
        // The persistent cache in T2TReader avoids redundant RF reads
        // when blocks fall within the same 16-byte READ response.

        'outer: while bytes_read < total_bytes {
            let (sector, block, _) =
                MemoryLayout::address_to_sector_block(byte_addr).ok_or(Type2Error::OutOfRange)?;

            // Switch sector if needed.
            if self.sector != SectorState::Known(sector) {
                self.sector_select(sector)?;
            }

            // Extract the 4 bytes for this block from a 16-byte READ.
            // The persistent cache handles deduplication across calls.
            let block_data = {
                let cached = self.cache_block.and_then(|cb| {
                    let ahead = block.wrapping_sub(cb);
                    if ahead < 4 {
                        Some(ahead as usize)
                    } else {
                        None
                    }
                });
                if let Some(blocks_ahead) = cached {
                    let offset = blocks_ahead * BLOCK_SIZE;
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&self.cache_data[offset..offset + BLOCK_SIZE]);
                    b
                } else {
                    let data = self.read(block)?;
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&data[..BLOCK_SIZE]);
                    b
                }
            };

            // Process each byte in this block.
            for (i, &byte) in block_data.iter().enumerate().take(BLOCK_SIZE) {
                let addr = byte_addr + i as u32;
                if layout.is_skip_area(addr) {
                    continue;
                }
                if bytes_read >= total_bytes {
                    break 'outer;
                }

                result.try_push(byte).map_err(Type2Error::from)?;
                bytes_read += 1;

                if tlv_scan.feed(byte) {
                    break 'outer;
                }
            }

            byte_addr += BLOCK_SIZE as u32;
        }

        Ok(result)
    }

    /// Read the data area, parse TLVs, and return the NDEF data area bytes.
    ///
    /// For dynamic tags with Lock/Memory Control TLVs, performs a
    /// two-pass read: first pass discovers the control TLVs, second
    /// pass re-reads with the proper layout that skips lock/reserved
    /// areas. For static tags, a single pass suffices.
    ///
    /// The persistent read cache makes the second pass cheap when
    /// blocks overlap with the first pass.
    fn read_data_area_with_layout(
        &mut self,
        cc: &CapabilityContainer,
    ) -> Result<DataVec, ReaderError<T::Error>> {
        let basic_layout = MemoryLayout::from_cc_and_tlvs(cc, &[]);
        let data_area = self.read_data_area(&basic_layout)?;
        let tlvs = tlv::parse_tlvs(&data_area).map_err(ReaderError::Protocol)?;

        // For dynamic tags: if Lock/Memory Control TLVs were found,
        // re-read with the proper layout that skips those areas.
        if cc.is_dynamic()
            && tlvs
                .iter()
                .any(|t| matches!(t, Tlv::LockControl(_) | Tlv::MemoryControl(_)))
        {
            let full_layout = MemoryLayout::from_cc_and_tlvs(cc, &tlvs);
            self.read_data_area(&full_layout)
        } else {
            Ok(data_area)
        }
    }

    /// Detect and read the NDEF message from the tag.
    ///
    /// Performs the NDEF detection procedure (Section 6.4.1):
    /// 1. Read CC
    /// 2. Validate CC
    /// 3. Read data area and parse TLVs
    /// 4. Find first NDEF Message TLV
    ///
    /// Returns the raw NDEF message bytes (suitable for passing to
    /// `ndef::Message::try_from()`), or an empty slice if no NDEF
    /// message is present (INITIALIZED state).
    pub fn read_ndef(&mut self) -> Result<DataVec, ReaderError<T::Error>> {
        let cc = self.read_cc()?;
        if !cc.is_valid() {
            return Err(Type2Error::InvalidMagic(0).into());
        }

        let data_area = self.read_data_area_with_layout(&cc)?;
        let tlvs = tlv::parse_tlvs(&data_area).map_err(ReaderError::Protocol)?;

        // Find the first NDEF Message TLV.
        for tlv in &tlvs {
            if let Tlv::NdefMessage(data) = tlv {
                return Ok(data.clone());
            }
        }

        // No NDEF Message TLV found — tag may be in an invalid state.
        Ok(DataVec::new())
    }

    /// Write an NDEF message to the tag.
    ///
    /// Implements the NDEF write procedure (Section 6.4.3):
    /// 1. Read CC and verify INITIALIZED or READ/WRITE state
    /// 2. Read data area to find NDEF Message TLV position
    /// 3. Write L=0 to NDEF Message TLV
    /// 4. Write NDEF message data
    /// 5. Write Terminator TLV
    /// 6. Update L field with actual length
    ///
    /// `ndef_data` should be raw NDEF bytes (e.g., from `ndef::Message::to_vec()`).
    pub fn write_ndef(&mut self, ndef_data: &[u8]) -> Result<(), ReaderError<T::Error>> {
        let cc = self.read_cc()?;
        if !cc.is_valid() {
            return Err(Type2Error::InvalidMagic(0).into());
        }
        if cc.write_access != AccessCondition::Granted {
            return Err(Type2Error::ReadOnly.into());
        }

        // Read the data area to find the NDEF Message TLV position.
        let data_area = self.read_data_area_with_layout(&cc)?;
        let tlvs = tlv::parse_tlvs(&data_area).map_err(ReaderError::Protocol)?;

        // Reject lengths that cannot be encoded in the NDEF Message TLV
        // length field before any arithmetic. The 3-byte length format is
        // `0xFF` followed by a big-endian u16, and `0xFFFF` is reserved, so
        // the largest encodable value is `0xFFFE`. Computing in `usize`
        // avoids the silent `as u16` truncation that let a 65_536-byte
        // input validate as length zero.
        let ndef_len_usize = ndef_data.len();
        if ndef_len_usize > 0xFFFE {
            return Err(Type2Error::OutOfRange.into());
        }
        let ndef_len = ndef_len_usize as u16;
        let l_field_size: usize = if ndef_len < 0xFF { 1 } else { 3 };

        // Find the byte offset of the first NDEF Message TLV within the data area.
        let mut ndef_tlv_offset: Option<usize> = None;
        {
            let mut offset = 0usize;
            for tlv in &tlvs {
                match tlv {
                    Tlv::NdefMessage(_) => {
                        ndef_tlv_offset = Some(offset);
                        break;
                    }
                    Tlv::Null => {
                        offset += 1;
                    }
                    Tlv::Terminator => {
                        break;
                    }
                    Tlv::LockControl(_) | Tlv::MemoryControl(_) => {
                        offset += 5; // T(1) + L(1) + V(3)
                    }
                    Tlv::Proprietary(data) => {
                        let v_len = data.len();
                        let l_size = if v_len < 0xFF { 1 } else { 3 };
                        offset += 1 + l_size + v_len;
                    }
                }
            }
        }

        let ndef_offset = ndef_tlv_offset.ok_or(Type2Error::InvalidTlv)?;

        // Prove the encoded TLV fits the usable capacity remaining after the
        // mandatory NDEF TLV. The data area counts only usable (non-skip)
        // bytes, so `data_area_size - ndef_offset` is the exact room left for
        // T + L + V + Terminator. Checked `usize` arithmetic with the offset
        // included rejects the oversized/near-capacity overruns before any
        // WRITE is issued.
        let required_end = ndef_offset
            .checked_add(1) // T
            .and_then(|x| x.checked_add(l_field_size)) // L
            .and_then(|x| x.checked_add(ndef_len_usize)) // V
            .and_then(|x| x.checked_add(1)) // Terminator
            .ok_or(Type2Error::OutOfRange)?;
        let data_area_size = cc.data_area_size();
        if required_end > data_area_size as usize {
            return Err(Type2Error::OutOfRange.into());
        }

        // Build the memory layout so the write can locate the NDEF TLV at its
        // true physical address and step over lock/reserved regions. The data
        // area's usable bytes are not contiguous: control regions before the
        // NDEF TLV shift its physical address above `data_start + ndef_offset`,
        // and any region within the value must be preserved, not overwritten.
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &tlvs);

        // Physical address of the NDEF TLV: the logical offset mapped through
        // the skip regions. Never `data_start + ndef_offset` directly, which
        // is only correct when nothing is skipped before the NDEF TLV.
        let ndef_byte_addr = layout
            .usable_offset_to_address(ndef_offset as u16)
            .ok_or(Type2Error::OutOfRange)?;

        // Exclusive physical limit: one byte past the last usable byte of the
        // data area. Every legitimate write lands strictly below it, so it is
        // a defense-in-depth backstop against a runaway cursor.
        let write_limit_addr = layout
            .usable_offset_to_address(data_area_size - 1)
            .and_then(|a| a.checked_add(1))
            .ok_or(Type2Error::OutOfRange)?;

        // Build the full byte sequence to write:
        // [T=0x03, L=0x00, ...ndef_data..., T=0xFE]
        // L is initially 0 for crash safety (Section 6.4.3), then updated
        // to the real length at the end.
        let mut payload = DataVec::new();
        payload
            .try_push(tlv::TLV_NDEF_MESSAGE)
            .map_err(Type2Error::from)?; // T
        if ndef_len < 0xFF {
            payload.try_push(0x00).map_err(Type2Error::from)?;
        } else {
            payload.try_push(0xFF).map_err(Type2Error::from)?;
            payload.try_push(0x00).map_err(Type2Error::from)?;
            payload.try_push(0x00).map_err(Type2Error::from)?;
        }
        payload.try_extend(ndef_data).map_err(Type2Error::from)?; // V
        payload
            .try_push(tlv::TLV_TERMINATOR)
            .map_err(Type2Error::from)?;

        // Write the payload over usable bytes only, jumping lock/reserved
        // regions so they are never modified.
        self.write_usable_bytes(&layout, ndef_byte_addr, &payload, write_limit_addr)?;

        // Crash-safe length update: set the real L field last, again through
        // the skip-aware path. The L field is at logical offset ndef_offset+1.
        let l_addr = layout
            .usable_offset_to_address(ndef_offset as u16 + 1)
            .ok_or(Type2Error::OutOfRange)?;
        if ndef_len < 0xFF {
            self.write_usable_bytes(&layout, l_addr, &[ndef_len as u8], write_limit_addr)?;
        } else {
            // 3-byte length: [0xFF, MSB, LSB] at bytes 1..4 from T.
            let l_bytes = [0xFF, (ndef_len >> 8) as u8, ndef_len as u8];
            self.write_usable_bytes(&layout, l_addr, &l_bytes, write_limit_addr)?;
        }

        Ok(())
    }

    /// Write `data` across the usable (non-skip) bytes of the data area,
    /// starting at physical `start_addr` and jumping over lock and reserved
    /// regions described by `layout` so they are preserved.
    ///
    /// Skip bytes that fall inside a written page are kept via
    /// read-modify-write; a fully usable, fully covered page is written
    /// directly. `limit_addr` is an exclusive physical bound — reaching it
    /// before `data` is consumed returns [`Type2Error::OutOfRange`], so a
    /// malformed layout cannot drive writes out of the data area.
    fn write_usable_bytes(
        &mut self,
        layout: &MemoryLayout,
        start_addr: u32,
        data: &[u8],
        limit_addr: u32,
    ) -> Result<(), ReaderError<T::Error>> {
        let mut di = 0usize;
        let mut addr = start_addr;

        while di < data.len() {
            if addr >= limit_addr {
                return Err(Type2Error::OutOfRange.into());
            }
            let (sector, block, offset) =
                MemoryLayout::address_to_sector_block(addr).ok_or(Type2Error::OutOfRange)?;
            if self.sector != SectorState::Known(sector) {
                self.sector_select(sector)?;
            }
            let page_base = addr - offset as u32;

            // Fast path: a fully usable page that remaining data fully covers
            // needs no read-modify-write.
            let page_all_usable =
                (0..BLOCK_SIZE).all(|i| !layout.is_skip_area(page_base + i as u32));
            if offset == 0 && data.len() - di >= BLOCK_SIZE && page_all_usable {
                if page_base + BLOCK_SIZE as u32 > limit_addr {
                    return Err(Type2Error::OutOfRange.into());
                }
                let page = [data[di], data[di + 1], data[di + 2], data[di + 3]];
                self.write(block, page)?;
                di += BLOCK_SIZE;
                addr = page_base + BLOCK_SIZE as u32;
                continue;
            }

            // Slow path: read-modify-write, placing data only on usable bytes
            // and preserving any lock/reserved byte in the page.
            let cur = self.read(block)?;
            let mut page = [cur[0], cur[1], cur[2], cur[3]];
            let mut touched = false;
            for (i, slot) in page.iter_mut().enumerate().skip(offset as usize) {
                if di >= data.len() {
                    break;
                }
                let a = page_base + i as u32;
                if a >= limit_addr {
                    return Err(Type2Error::OutOfRange.into());
                }
                if layout.is_skip_area(a) {
                    continue; // preserve lock/reserved byte
                }
                *slot = data[di];
                di += 1;
                touched = true;
            }
            if touched {
                self.write(block, page)?;
            }
            addr = page_base + BLOCK_SIZE as u32;
        }
        Ok(())
    }
}

/// Lightweight TLV boundary scanner for detecting the Terminator TLV
/// during data area reads. Tracks position within the TLV stream so
/// that `0xFE` bytes inside TLV values are not mistaken for a Terminator.
///
/// Feed bytes one at a time via [`feed`]; returns `true` when the
/// Terminator TLV tag is encountered at a valid TLV boundary.
enum TlvScanState {
    /// Next byte is a TLV tag.
    Tag,
    /// Next byte is the first length byte.
    Length,
    /// Read first byte of 3-byte extended length; waiting for MSB.
    LengthExtMsb,
    /// Read MSB of extended length; waiting for LSB.
    LengthExtLsb(u8),
    /// Skipping `remaining` value bytes.
    Value(u16),
}

struct TlvScanner {
    state: TlvScanState,
}

impl TlvScanner {
    fn new() -> Self {
        Self {
            state: TlvScanState::Tag,
        }
    }

    /// Feed the next data byte. Returns `true` if this byte is a
    /// Terminator TLV tag (0xFE), meaning the caller should stop reading.
    fn feed(&mut self, byte: u8) -> bool {
        match self.state {
            TlvScanState::Tag => match byte {
                tlv::TLV_TERMINATOR => return true,
                tlv::TLV_NULL => {} // No L/V, stay in Tag state.
                _ => self.state = TlvScanState::Length,
            },
            TlvScanState::Length => {
                if byte == 0xFF {
                    // 3-byte length: 0xFF + MSB + LSB.
                    self.state = TlvScanState::LengthExtMsb;
                } else if byte == 0 {
                    self.state = TlvScanState::Tag;
                } else {
                    self.state = TlvScanState::Value(byte as u16);
                }
            }
            TlvScanState::LengthExtMsb => {
                self.state = TlvScanState::LengthExtLsb(byte);
            }
            TlvScanState::LengthExtLsb(msb) => {
                let len = (msb as u16) << 8 | byte as u16;
                if len == 0 {
                    self.state = TlvScanState::Tag;
                } else {
                    self.state = TlvScanState::Value(len);
                }
            }
            TlvScanState::Value(remaining) => {
                if remaining <= 1 {
                    self.state = TlvScanState::Tag;
                } else {
                    self.state = TlvScanState::Value(remaining - 1);
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type2::ACK;
    use crate::vec::FrameVec;

    /// Mock transceiver for testing.
    struct MockTransceiver {
        /// Flat memory (1 sector = 1024 bytes).
        memory: [u8; 1024],
    }

    impl MockTransceiver {
        fn new() -> Self {
            MockTransceiver {
                memory: [0u8; 1024],
            }
        }

        /// Set up a static tag with a valid CC and empty NDEF TLV.
        fn setup_static_initialized(&mut self) {
            // Block 0-2: internal/UID/lock (zeros are fine for testing).
            // Block 3: CC
            self.memory[12] = 0xE1; // CC0: magic
            self.memory[13] = 0x10; // CC1: version 1.0
            self.memory[14] = 0x06; // CC2: 48 bytes data area
            self.memory[15] = 0x00; // CC3: r/w access
            // Block 4: NDEF Message TLV (empty) + Terminator
            self.memory[16] = 0x03; // T = NDEF Message
            self.memory[17] = 0x00; // L = 0
            self.memory[18] = 0xFE; // Terminator
        }

        /// Set up a static tag with a non-empty NDEF message.
        fn setup_static_with_ndef(&mut self) {
            self.setup_static_initialized();
            // Write empty NDEF message D00000h
            self.memory[16] = 0x03; // T
            self.memory[17] = 0x03; // L = 3
            self.memory[18] = 0xD0; // V[0]
            self.memory[19] = 0x00; // V[1]
            self.memory[20] = 0x00; // V[2]
            self.memory[21] = 0xFE; // Terminator
        }
    }

    impl T2TTransceiver for MockTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
            let command = Command::try_from(cmd).map_err(|_| ())?;
            match command {
                Command::Read { block_no } => {
                    let start = block_no as usize * BLOCK_SIZE;
                    let mut response = FrameVec::new();
                    let end = (start + 16).min(self.memory.len());
                    let _ = response.try_extend(&self.memory[start..end]);
                    // Pad if near end of memory.
                    while response.len() < 16 {
                        let _ = response.try_push(0);
                    }
                    Ok(response)
                }
                Command::Write { block_no, data } => {
                    let start = block_no as usize * BLOCK_SIZE;
                    if start + 4 <= self.memory.len() {
                        self.memory[start..start + 4].copy_from_slice(&data);
                    }
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart1 => {
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart2 { .. } => {
                    // Shouldn't be called via transceive.
                    Err(())
                }
            }
        }

        fn transceive_no_response(&mut self, _cmd: &[u8]) -> Result<Option<u8>, ()> {
            // Passive ACK (success).
            Ok(None)
        }
    }

    /// Mock transceiver that counts RF transactions.
    struct CountingTransceiver {
        inner: MockTransceiver,
        transceive_count: usize,
    }

    impl CountingTransceiver {
        fn new() -> Self {
            CountingTransceiver {
                inner: MockTransceiver::new(),
                transceive_count: 0,
            }
        }
    }

    impl T2TTransceiver for CountingTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
            self.transceive_count += 1;
            self.inner.transceive(cmd)
        }

        fn transceive_no_response(&mut self, cmd: &[u8]) -> Result<Option<u8>, ()> {
            self.inner.transceive_no_response(cmd)
        }
    }

    #[test]
    fn read_cc_from_mock() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_initialized();
        let mut reader = T2TReader::new(&mut mock);
        let cc = reader.read_cc().unwrap();
        assert_eq!(cc.version_major, 1);
        assert_eq!(cc.version_minor, 0);
        assert_eq!(cc.data_area_size(), 48);
        assert_eq!(cc.read_access, AccessCondition::Granted);
        assert_eq!(cc.write_access, AccessCondition::Granted);
    }

    #[test]
    fn read_ndef_empty() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_initialized();
        let mut reader = T2TReader::new(&mut mock);
        let ndef = reader.read_ndef().unwrap();
        assert!(ndef.is_empty());
    }

    #[test]
    fn read_ndef_with_data() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);
        let ndef = reader.read_ndef().unwrap();
        assert_eq!(&*ndef, &[0xD0, 0x00, 0x00]);
    }

    #[test]
    fn write_then_read_ndef() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_initialized();
        let mut reader = T2TReader::new(&mut mock);

        // Write an empty NDEF message.
        let ndef_data = [0xD0, 0x00, 0x00];
        reader.write_ndef(&ndef_data).unwrap();

        // Read it back.
        let result = reader.read_ndef().unwrap();
        assert_eq!(&*result, &ndef_data);
    }

    #[test]
    fn read_block() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);

        // Read block 3 (CC).
        let data = reader.read(3).unwrap();
        assert_eq!(data[0], 0xE1);
        assert_eq!(data[1], 0x10);
        assert_eq!(data[2], 0x06);
        assert_eq!(data[3], 0x00);
    }

    #[test]
    fn write_block() {
        let mut mock = MockTransceiver::new();
        mock.setup_static_initialized();
        let mut reader = T2TReader::new(&mut mock);

        reader.write(4, [0xAA, 0xBB, 0xCC, 0xDD]).unwrap();

        // Read it back.
        let data = reader.read(4).unwrap();
        assert_eq!(&data[..4], &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn read_cache_hit() {
        let mut mock = CountingTransceiver::new();
        mock.inner.setup_static_with_ndef();
        {
            let mut reader = T2TReader::new(&mut mock);
            let _ = reader.read(3).unwrap();
            let _ = reader.read(3).unwrap();
        }
        // Only 1 transceive: second read served from cache.
        assert_eq!(mock.transceive_count, 1);
    }

    #[test]
    fn read_cache_miss_different_block() {
        let mut mock = CountingTransceiver::new();
        mock.inner.setup_static_with_ndef();
        {
            let mut reader = T2TReader::new(&mut mock);
            let _ = reader.read(3).unwrap();
            let _ = reader.read(8).unwrap();
        }
        // 2 transceives: different blocks, cache miss on second.
        assert_eq!(mock.transceive_count, 2);
    }

    #[test]
    fn write_invalidates_cache() {
        let mut mock = CountingTransceiver::new();
        mock.inner.setup_static_with_ndef();
        {
            let mut reader = T2TReader::new(&mut mock);
            let _ = reader.read(4).unwrap();
            reader.write(4, [0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
            let _ = reader.read(4).unwrap();
        }
        // 3 transceives: read + write + read (cache invalidated by write).
        assert_eq!(mock.transceive_count, 3);
    }

    /// Mock transceiver that fails N times then succeeds.
    struct FailingTransceiver {
        inner: MockTransceiver,
        failures_remaining: usize,
        /// Number of `transceive` calls made (used to count retry attempts).
        attempts: usize,
    }

    impl FailingTransceiver {
        fn new(fail_count: usize) -> Self {
            FailingTransceiver {
                inner: MockTransceiver::new(),
                failures_remaining: fail_count,
                attempts: 0,
            }
        }
    }

    impl T2TTransceiver for FailingTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
            self.attempts += 1;
            if self.failures_remaining > 0 {
                self.failures_remaining -= 1;
                return Err(());
            }
            self.inner.transceive(cmd)
        }

        fn transceive_no_response(&mut self, cmd: &[u8]) -> Result<Option<u8>, ()> {
            self.inner.transceive_no_response(cmd)
        }
    }

    #[test]
    fn retry_on_transient_error() {
        let mut mock = FailingTransceiver::new(1);
        mock.inner.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);
        reader.set_max_retries(1);

        let data = reader.read(3).unwrap();
        assert_eq!(data[0], 0xE1);
    }

    #[test]
    fn retry_exhausted() {
        let mut mock = FailingTransceiver::new(3);
        mock.inner.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);
        reader.set_max_retries(1); // 2 attempts total, 3 failures.

        assert!(reader.read(3).is_err());
    }

    #[test]
    fn retry_disabled() {
        let mut mock = FailingTransceiver::new(1);
        mock.inner.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);
        reader.set_max_retries(0);

        assert!(reader.read(3).is_err());
    }

    // ── Sector state across retries (SFT-7595) ─────────────────────

    /// Multi-sector mock that models the NFC Forum rule making sector 0 the
    /// default after a protocol infringement: the configured failure returns an
    /// error *and* resets the tag's active sector to 0. Records the physical
    /// (sector, block) of every WRITE so a misdirected retry is detectable.
    struct SectorResetTransceiver {
        /// Sector the tag itself considers active.
        tag_sector: u8,
        /// Countdown to the next induced failure; 0 disables.
        fail_in: usize,
        /// Physical (sector, block, data) of each WRITE applied.
        writes: heapless::Vec<(u8, u8, [u8; 4]), 8>,
        /// Number of SECTOR SELECT sequences completed.
        selects: usize,
        /// When set, packet 2 returns a transceiver error.
        fail_packet2: bool,
    }

    impl SectorResetTransceiver {
        fn new() -> Self {
            SectorResetTransceiver {
                tag_sector: 0,
                fail_in: 0,
                writes: heapless::Vec::new(),
                selects: 0,
                fail_packet2: false,
            }
        }
    }

    impl T2TTransceiver for SectorResetTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
            let command = Command::try_from(cmd).map_err(|_| ())?;
            // Induce a failure that also resets the tag to sector 0, exactly as
            // a protocol infringement would.
            if self.fail_in > 0 {
                self.fail_in -= 1;
                if self.fail_in == 0 {
                    self.tag_sector = 0;
                    return Err(());
                }
            }
            match command {
                Command::Read { .. } => {
                    let mut response = FrameVec::new();
                    let _ = response.try_extend(&[0u8; 16]);
                    Ok(response)
                }
                Command::Write { block_no, data } => {
                    let _ = self.writes.push((self.tag_sector, block_no, data));
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart1 => {
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart2 { .. } => Err(()),
            }
        }

        fn transceive_no_response(&mut self, cmd: &[u8]) -> Result<Option<u8>, ()> {
            if self.fail_packet2 {
                return Err(());
            }
            // Packet 2 carries the sector number.
            self.tag_sector = cmd[0];
            self.selects += 1;
            Ok(None)
        }
    }

    /// A transceiver error that resets the tag to sector 0 must not let the
    /// retry land on sector 0's copy of the same block: the reader re-selects
    /// sector 1 first.
    #[test]
    fn retry_after_sector_reset_reselects_intended_sector() {
        let mut mock = SectorResetTransceiver::new();
        {
            let mut reader = T2TReader::new(&mut mock);
            reader.set_max_retries(1);
            reader.sector_select(1).unwrap();
            // Fail the next transceive (the WRITE), resetting the tag to 0.
            reader.transceiver().fail_in = 1;
            reader.write(3, [0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
            assert_eq!(reader.current_sector(), Some(1));
        }
        // Exactly one write landed, and it landed in sector 1 — never sector 0,
        // where block 3 is the Capability Container.
        assert_eq!(mock.writes.len(), 1);
        assert_eq!(mock.writes[0].0, 1, "write must land in sector 1");
        assert_eq!(mock.writes[0].1, 3);
        // Two selects: the initial one plus the recovery before the retry.
        assert_eq!(mock.selects, 2);
    }

    /// A packet-2 failure leaves the sector unknown, and the next operation
    /// re-establishes it rather than assuming the old value.
    #[test]
    fn packet2_error_leaves_sector_unknown() {
        let mut mock = SectorResetTransceiver::new();
        let mut reader = T2TReader::new(&mut mock);
        reader.sector_select(1).unwrap();
        assert_eq!(reader.sector_state(), SectorState::Known(1));

        reader.transceiver().fail_packet2 = true;
        assert!(reader.sector_select(2).is_err());
        assert_eq!(reader.sector_state(), SectorState::Unknown);
        assert_eq!(reader.current_sector(), None);

        // Recovery: a later successful selection restores a known sector.
        reader.transceiver().fail_packet2 = false;
        reader.sector_select(2).unwrap();
        assert_eq!(reader.sector_state(), SectorState::Known(2));
    }

    /// A NACK from packet 2 is equally ambiguous and must leave state unknown.
    #[test]
    fn packet2_nack_leaves_sector_unknown() {
        struct NackP2(SectorResetTransceiver);
        impl T2TTransceiver for NackP2 {
            type Error = ();
            fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
                self.0.transceive(cmd)
            }
            fn transceive_no_response(&mut self, _cmd: &[u8]) -> Result<Option<u8>, ()> {
                Ok(Some(0x00)) // NACK
            }
        }
        let mut mock = NackP2(SectorResetTransceiver::new());
        let mut reader = T2TReader::new(&mut mock);
        assert!(reader.sector_select(1).is_err());
        assert_eq!(reader.sector_state(), SectorState::Unknown);
    }

    /// An error leaves the sector unknown and invalidates the read cache, so a
    /// later read cannot be served with data from a possibly-different sector.
    #[test]
    fn ambiguous_error_invalidates_cache_and_sector() {
        let mut mock = FailingTransceiver::new(0);
        mock.inner.setup_static_with_ndef();
        let mut reader = T2TReader::new(&mut mock);
        reader.set_max_retries(0);

        let _ = reader.read(3).unwrap(); // populates the cache
        reader.transceiver().failures_remaining = 1;
        assert!(reader.read(8).is_err());

        assert_eq!(reader.sector_state(), SectorState::Unknown);
        assert!(reader.cache_block.is_none(), "cache must be invalidated");
    }

    /// With the sector already unknown, a failing command is not retried into
    /// an arbitrary sector.
    #[test]
    fn no_retry_while_sector_unknown() {
        let mut mock = FailingTransceiver::new(0);
        mock.inner.setup_static_with_ndef();
        {
            let mut reader = T2TReader::new(&mut mock);
            reader.set_max_retries(3);
            // Drive the reader into the unknown state: every attempt fails, so
            // even the sector-recovery step cannot restore a known sector.
            reader.transceiver().failures_remaining = 100;
            assert!(reader.read(3).is_err());
            assert_eq!(reader.sector_state(), SectorState::Unknown);

            // A second failure must not spawn retries while unknown.
            reader.transceiver().attempts = 0;
            assert!(reader.read(3).is_err());
            assert_eq!(
                reader.transceiver().attempts,
                1,
                "no retry may be attempted while the sector is unknown"
            );
        }
    }

    /// Sector 0xFF is reserved and must be rejected without any RF traffic.
    #[test]
    fn reserved_sector_rejected() {
        let mut mock = SectorResetTransceiver::new();
        let mut reader = T2TReader::new(&mut mock);
        assert!(matches!(
            reader.sector_select(0xFF),
            Err(ReaderError::Protocol(Type2Error::OutOfRange))
        ));
        assert_eq!(reader.transceiver().selects, 0);
    }

    // ── write_ndef bounds enforcement (SFT-7601) ───────────────────

    /// Transceiver that applies writes to flat memory and counts every
    /// WRITE command, so tests can assert that no page write escaped the
    /// data area (or that no write happened at all).
    struct RecordingTransceiver {
        memory: [u8; 1024],
        writes: usize,
    }

    impl RecordingTransceiver {
        fn new() -> Self {
            RecordingTransceiver {
                memory: [0u8; 1024],
                writes: 0,
            }
        }

        /// Write a valid CC (`size_field` * 8 bytes of data area) plus an
        /// empty NDEF Message TLV and Terminator at the data-area start.
        fn setup(&mut self, size_field: u8) {
            self.memory[12] = 0xE1; // magic
            self.memory[13] = 0x10; // version 1.0
            self.memory[14] = size_field; // data area = size_field * 8
            self.memory[15] = 0x00; // r/w access
            self.memory[16] = 0x03; // NDEF Message TLV
            self.memory[17] = 0x00; // L = 0
            self.memory[18] = 0xFE; // Terminator
        }
    }

    impl T2TTransceiver for RecordingTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
            let command = Command::try_from(cmd).map_err(|_| ())?;
            match command {
                Command::Read { block_no } => {
                    let start = block_no as usize * BLOCK_SIZE;
                    let mut response = FrameVec::new();
                    let end = (start + 16).min(self.memory.len());
                    let _ = response.try_extend(&self.memory[start..end]);
                    while response.len() < 16 {
                        let _ = response.try_push(0);
                    }
                    Ok(response)
                }
                Command::Write { block_no, data } => {
                    self.writes += 1;
                    let start = block_no as usize * BLOCK_SIZE;
                    if start + 4 <= self.memory.len() {
                        self.memory[start..start + 4].copy_from_slice(&data);
                    }
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart1 => {
                    let mut response = FrameVec::new();
                    let _ = response.try_push(ACK);
                    Ok(response)
                }
                Command::SectorSelectPart2 { .. } => Err(()),
            }
        }

        fn transceive_no_response(&mut self, _cmd: &[u8]) -> Result<Option<u8>, ()> {
            Ok(None)
        }
    }

    /// A 65,536-byte input truncates to length 0 under `as u16`. It must
    /// now be rejected with a range error before any write — including the
    /// `alloc`/`std` builds whose unbounded `DataVec` previously let the
    /// full slice through and into the security pages.
    #[test]
    fn write_ndef_rejects_oversized_input_with_no_writes() {
        let mut mock = RecordingTransceiver::new();
        mock.setup(0x06); // 48-byte data area
        {
            let mut reader = T2TReader::new(&mut mock);
            let oversized = [0xAAu8; 65_536];
            let res = reader.write_ndef(&oversized);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(mock.writes, 0, "oversized input must not write any page");
    }

    /// Any length that cannot be encoded in the TLV length field (> 0xFFFE)
    /// is rejected before writing.
    #[test]
    fn write_ndef_rejects_unencodable_length_with_no_writes() {
        let mut mock = RecordingTransceiver::new();
        mock.setup(0x06);
        {
            let mut reader = T2TReader::new(&mut mock);
            let too_long = [0u8; 0xFFFF]; // 0xFFFF is the reserved marker value
            let res = reader.write_ndef(&too_long);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(mock.writes, 0);
    }

    /// A payload that fits `data_area_size` from offset 0 but overruns once
    /// a preceding NULL TLV shifts the write start must be rejected with no
    /// writes — the near-capacity overrun variant.
    #[test]
    fn write_ndef_rejects_nonzero_offset_overrun_with_no_writes() {
        let mut mock = RecordingTransceiver::new();
        // 48-byte data area, NULL TLV then empty NDEF TLV → NDEF at offset 1.
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x06, 0x00]);
        mock.memory[16] = 0x00; // NULL TLV consumes one offset byte
        mock.memory[17] = 0x03; // NDEF Message TLV
        mock.memory[18] = 0x00; // L = 0
        mock.memory[19] = 0xFE; // Terminator
        {
            let mut reader = T2TReader::new(&mut mock);
            // 45 bytes: 1+1+45+1 = 48 fits at offset 0, but +1 offset = 49 > 48.
            let payload = [0xABu8; 45];
            let res = reader.write_ndef(&payload);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(mock.writes, 0, "offset overrun must not write any page");
    }

    /// A Memory Control TLV (reserved region) ahead of the NDEF TLV pushes
    /// the write offset to 5. A payload that would fit from offset 0 but
    /// overruns once that offset is included must be rejected with no writes.
    #[test]
    fn write_ndef_rejects_memory_control_offset_overrun_with_no_writes() {
        let mut mock = RecordingTransceiver::new();
        // 48-byte data area. Memory Control TLV (T,L,V=3) then empty NDEF TLV
        // → NDEF at offset 5.
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x06, 0x00]);
        mock.memory[16] = 0x02; // Memory Control TLV
        mock.memory[17] = 0x03; // L = 3
        mock.memory[18] = 0xF0; // V: page_addr=15, byte_offset=0
        mock.memory[19] = 0x05; // V: size
        mock.memory[20] = 0x03; // V: bytes-per-page
        mock.memory[21] = 0x03; // NDEF Message TLV
        mock.memory[22] = 0x00; // L = 0
        mock.memory[23] = 0xFE; // Terminator
        {
            let mut reader = T2TReader::new(&mut mock);
            // 41 bytes: 1+1+41+1 = 44 fits at offset 0, but +5 offset = 49 > 48.
            let payload = [0xCDu8; 41];
            let res = reader.write_ndef(&payload);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(
            mock.writes, 0,
            "reserved-region offset overrun must not write"
        );
    }

    /// The maximum payload that exactly fills the data area succeeds and
    /// writes nothing beyond it (which on NTAG is the dynamic-lock page).
    #[test]
    fn write_ndef_max_payload_stays_within_data_area() {
        let mut mock = RecordingTransceiver::new();
        mock.setup(0x06); // 48-byte data area at bytes 16..64
        {
            let mut reader = T2TReader::new(&mut mock);
            // 45 bytes: T + L + 45 + Terminator = 48 = data area.
            reader.write_ndef(&[0x55u8; 45]).unwrap();
        }
        assert_eq!(mock.memory[16], 0x03); // T
        assert_eq!(mock.memory[17], 45); // L (final)
        assert_eq!(mock.memory[63], 0xFE); // Terminator at last data-area byte
        assert!(
            mock.memory[64..].iter().all(|&b| b == 0),
            "nothing written beyond the data area"
        );
    }

    /// A 255-byte payload uses the 3-byte extended length encoding and, when
    /// it fits, is written correctly.
    #[test]
    fn write_ndef_extended_length_encoding() {
        let mut mock = RecordingTransceiver::new();
        mock.setup(0x40); // 512-byte data area
        {
            let mut reader = T2TReader::new(&mut mock);
            reader.write_ndef(&[0x22u8; 255]).unwrap();
        }
        assert_eq!(mock.memory[16], 0x03); // T
        assert_eq!(mock.memory[17], 0xFF); // 3-byte length marker
        assert_eq!(mock.memory[18], 0x00); // length MSB
        assert_eq!(mock.memory[19], 0xFF); // length LSB (255)
        assert_eq!(mock.memory[20], 0x22); // V starts
        assert_eq!(mock.memory[275], 0xFE); // Terminator after 255 bytes
    }

    // ── Skip-region-aware writes (SFT-7594) ────────────────────────

    /// Set up the audit-proof layout: a 96-byte data area (default dynamic
    /// lock byte at physical 112) with a Proprietary TLV occupying 88 logical
    /// bytes, so the NDEF TLV begins at physical address 104. A sentinel is
    /// placed in the lock byte.
    fn setup_proprietary_before_ndef(mock: &mut RecordingTransceiver) {
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x0C, 0x00]); // 96 bytes
        mock.memory[16] = 0xFD; // Proprietary TLV
        mock.memory[17] = 86; // L = 86 → T+L+V = 88 logical bytes
        mock.memory[104] = 0x03; // NDEF Message TLV at logical offset 88
        mock.memory[105] = 0x00; // L = 0
        mock.memory[106] = 0xFE; // Terminator
        mock.memory[112] = 0xA5; // dynamic lock byte sentinel
    }

    /// The audit proof: a 10-byte message encodes to 13 bytes but only 8
    /// usable bytes remain after the mandatory NDEF TLV. It previously wrote
    /// 104..=116 contiguously and changed the lock byte at 112 from 0xA5 to
    /// 0x07 while returning success. It must now return `OutOfRange` with no
    /// WRITE issued and the lock byte intact.
    #[test]
    fn write_ndef_audit_proof_rejected_lock_byte_intact() {
        let mut mock = RecordingTransceiver::new();
        setup_proprietary_before_ndef(&mut mock);

        {
            let mut reader = T2TReader::new(&mut mock);
            let res = reader.write_ndef(&[0x11u8; 10]);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(mock.writes, 0, "no WRITE may be issued");
        assert_eq!(mock.memory[112], 0xA5, "lock byte must be untouched");
    }

    /// One byte beyond the remaining usable capacity performs zero writes.
    #[test]
    fn write_ndef_one_byte_excess_after_proprietary_tlv_no_writes() {
        let mut mock = RecordingTransceiver::new();
        setup_proprietary_before_ndef(&mut mock);

        {
            let mut reader = T2TReader::new(&mut mock);
            // 8 usable bytes remain: T + L + V + Terminator → V max = 5.
            let res = reader.write_ndef(&[0x22u8; 6]);
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(mock.writes, 0, "one-byte excess must not write");
        assert_eq!(mock.memory[112], 0xA5);
    }

    /// The exact-boundary message for the same layout succeeds, landing the
    /// Terminator on the last usable byte without touching the lock byte.
    #[test]
    fn write_ndef_exact_boundary_after_proprietary_tlv_succeeds() {
        let mut mock = RecordingTransceiver::new();
        setup_proprietary_before_ndef(&mut mock);

        {
            let mut reader = T2TReader::new(&mut mock);
            reader.write_ndef(&[0x33u8; 5]).unwrap();
        }
        assert_eq!(mock.memory[104], 0x03); // T at the located physical address
        assert_eq!(mock.memory[105], 5); // L updated last
        assert!(mock.memory[106..111].iter().all(|&b| b == 0x33)); // V
        assert_eq!(mock.memory[111], 0xFE); // Terminator on last usable byte
        assert_eq!(mock.memory[112], 0xA5, "lock byte preserved at boundary");
    }

    /// A lock region (from a Lock Control TLV) that falls inside the NDEF
    /// value is preserved, and the value continues past it.
    #[test]
    fn write_ndef_preserves_lock_region_inside_value() {
        let mut mock = RecordingTransceiver::new();
        // 96-byte data area with a Lock Control TLV placing 1 lock byte at
        // physical address 28 (page_addr 7 * page size 4 + offset 0).
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x0C, 0x00]);
        mock.memory[16] = 0x01; // Lock Control TLV
        mock.memory[17] = 0x03; // L = 3
        mock.memory[18] = 0x70; // page_addr=7, byte_offset=0
        mock.memory[19] = 0x08; // size_in_bits = 8 → 1 lock byte
        mock.memory[20] = 0x32; // bytes_locked_per_bit=3, bytes_per_page=2
        mock.memory[21] = 0x03; // NDEF Message TLV at logical offset 5
        mock.memory[22] = 0x00; // L = 0
        mock.memory[23] = 0xFE; // Terminator
        mock.memory[28] = 0xA5; // lock byte sentinel

        {
            let mut reader = T2TReader::new(&mut mock);
            reader.write_ndef(&[0x44u8; 8]).unwrap();
        }

        assert_eq!(
            mock.memory[28], 0xA5,
            "lock region inside the value must be preserved"
        );
        assert_eq!(mock.memory[21], 0x03);
        assert_eq!(mock.memory[22], 8);
        // Value: 23..28, skip 28, resume 29..32.
        assert!(mock.memory[23..28].iter().all(|&b| b == 0x44));
        assert!(mock.memory[29..32].iter().all(|&b| b == 0x44));
    }

    /// A reserved (Memory Control) region inside the NDEF value is preserved,
    /// and the value bytes continue on the far side of it.
    #[test]
    fn write_ndef_preserves_reserved_region_inside_value() {
        let mut mock = RecordingTransceiver::new();
        // 96-byte data area; Memory Control TLV reserving 24..28.
        mock.memory[12..16].copy_from_slice(&[0xE1, 0x10, 0x0C, 0x00]);
        mock.memory[16] = 0x02; // Memory Control TLV
        mock.memory[17] = 0x03; // L = 3
        mock.memory[18] = 0x60; // page_addr=6, byte_offset=0
        mock.memory[19] = 0x04; // size = 4 bytes
        mock.memory[20] = 0x02; // bytes_per_page exponent → page size 4 → addr 24
        mock.memory[21] = 0x03; // NDEF Message TLV at logical offset 5
        mock.memory[22] = 0x00; // L = 0
        mock.memory[23] = 0xFE; // Terminator
        // Sentinels in the reserved region.
        mock.memory[24..28].copy_from_slice(&[0xA5, 0xA6, 0xA7, 0xA8]);

        {
            let mut reader = T2TReader::new(&mut mock);
            reader.write_ndef(&[0x44u8; 8]).unwrap();
        }

        assert_eq!(
            &mock.memory[24..28],
            &[0xA5, 0xA6, 0xA7, 0xA8],
            "reserved region inside the value must be preserved"
        );
        // TLV header at 21..23, value resumes after the reserved region.
        assert_eq!(mock.memory[21], 0x03);
        assert_eq!(mock.memory[22], 8);
        assert_eq!(mock.memory[23], 0x44);
        assert!(mock.memory[28..35].iter().all(|&b| b == 0x44));
    }

    /// Length-format boundary: a 253-byte payload (1-byte length) exactly
    /// fills a 256-byte data area and succeeds, while a 255-byte payload
    /// (3-byte length, needs 260) is rejected with no writes.
    #[test]
    fn write_ndef_length_boundary() {
        // Just fits with 1-byte length.
        let mut fit = RecordingTransceiver::new();
        fit.setup(0x20); // 256-byte data area
        {
            let mut reader = T2TReader::new(&mut fit);
            reader.write_ndef(&[0x33u8; 253]).unwrap();
        }
        assert_eq!(fit.memory[17], 253); // 1-byte length field

        // Just over with 3-byte length.
        let mut over = RecordingTransceiver::new();
        over.setup(0x20);
        {
            let mut reader = T2TReader::new(&mut over);
            let res = reader.write_ndef(&[0x33u8; 255]); // needs 260 > 256
            assert!(matches!(
                res,
                Err(ReaderError::Protocol(Type2Error::OutOfRange))
            ));
        }
        assert_eq!(over.writes, 0);
    }
}
