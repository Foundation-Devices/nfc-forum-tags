// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! High-level Type 2 Tag reader/writer.
//!
//! [`T2TReader`] orchestrates command sequences for NDEF detection,
//! reading, and writing on a Type 2 Tag after ISO 14443-3A activation.

use super::cc::CapabilityContainer;
use super::memory::{BLOCK_SIZE, CC_BLOCK, DATA_START_BLOCK, MemoryLayout};
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

/// High-level NFC Forum Type 2 Tag reader/writer.
///
/// Wraps a [`T2TTransceiver`] and tracks the currently selected sector.
/// Maintains a 16-byte read cache to avoid redundant RF transactions.
/// Retries transient transceiver errors up to `max_retries` times.
pub struct T2TReader<'t, T: T2TTransceiver> {
    transceiver: &'t mut T,
    current_sector: u8,
    /// Cached 16-byte READ result: (block_no, data).
    cache_block: Option<u8>,
    cache_data: [u8; 16],
    /// Maximum number of retries on transient transceiver errors.
    max_retries: u8,
}

impl<'t, T: T2TTransceiver> T2TReader<'t, T> {
    /// Create a new reader. The default sector is 0.
    pub fn new(transceiver: &'t mut T) -> Self {
        T2TReader {
            transceiver,
            current_sector: 0,
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

    /// Invalidate the read cache.
    fn invalidate_cache(&mut self) {
        self.cache_block = None;
    }

    /// Transceive with retry on transceiver errors.
    fn transceive_with_retry(
        &mut self,
        cmd: &[u8],
    ) -> Result<crate::vec::FrameVec, ReaderError<T::Error>> {
        let mut last_err = None;
        for _ in 0..=self.max_retries {
            match self.transceiver.transceive(cmd) {
                Ok(raw) => return Ok(raw),
                Err(e) => last_err = Some(e),
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
        if sector == self.current_sector {
            return Ok(());
        }
        self.invalidate_cache();

        // Packet 1: [0xC2, 0xFF] — retries on transceiver error.
        let cmd1 = Command::SectorSelectPart1;
        let raw = self.transceive_with_retry(&cmd1.to_bytes())?;
        match cmd1.parse_answer(&raw)? {
            Answer::Ack => {}
            Answer::Nack(code) => return Err(Type2Error::Nack(code).into()),
            _ => return Err(Type2Error::InvalidLength.into()),
        }

        // Packet 2: [sector_no, 0x00, 0x00, 0x00]
        let cmd2 = Command::SectorSelectPart2 { sector_no: sector };
        let nack = self
            .transceiver
            .transceive_no_response(&cmd2.to_bytes())
            .map_err(ReaderError::Transceiver)?;
        if let Some(nack_code) = nack {
            return Err(Type2Error::Nack(nack_code).into());
        }

        self.current_sector = sector;
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
        let start_byte_addr = DATA_START_BLOCK as u16 * BLOCK_SIZE as u16;
        let mut byte_addr = start_byte_addr;

        // Read block by block (4 bytes at a time) to handle skip areas.
        // The persistent cache in T2TReader avoids redundant RF reads
        // when blocks fall within the same 16-byte READ response.

        'outer: while bytes_read < total_bytes {
            let (sector, block, _) = MemoryLayout::address_to_sector_block(byte_addr);

            // Switch sector if needed.
            if sector != self.current_sector {
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
                let addr = byte_addr + i as u16;
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

            byte_addr += BLOCK_SIZE as u16;
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

        // Calculate available space.
        let ndef_len = ndef_data.len() as u16;
        let l_field_size: u16 = if ndef_len < 0xFF { 1 } else { 3 };
        let total_ndef_tlv_size = 1 + l_field_size + ndef_len; // T + L + V
        let terminator_size = 1u16; // Terminator TLV

        if total_ndef_tlv_size + terminator_size > cc.data_area_size() {
            return Err(Type2Error::OutOfRange.into());
        }

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

        let data_start_addr = DATA_START_BLOCK as u16 * BLOCK_SIZE as u16;
        let ndef_byte_addr = data_start_addr + ndef_offset as u16;

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

        // Write the payload page by page using read-modify-write for
        // pages that are partially covered.
        self.write_bytes_at(ndef_byte_addr, &payload)?;

        // Update L field with actual length (atomic-ish: single page write).
        if ndef_len < 0xFF {
            self.write_byte_at(ndef_byte_addr + 1, ndef_len as u8)?;
        } else {
            // 3-byte length: [0xFF, MSB, LSB] at bytes 1..4 from T.
            let l_bytes = [0xFF, (ndef_len >> 8) as u8, ndef_len as u8];
            self.write_bytes_at(ndef_byte_addr + 1, &l_bytes)?;
        }

        Ok(())
    }

    /// Write a contiguous byte sequence starting at `start_addr`, using
    /// page-level writes. Partial pages at the start and end are handled
    /// via read-modify-write; full pages are written directly.
    fn write_bytes_at(
        &mut self,
        start_addr: u16,
        data: &[u8],
    ) -> Result<(), ReaderError<T::Error>> {
        let mut addr = start_addr;
        let mut remaining = data;

        while !remaining.is_empty() {
            let (sector, block, offset) = MemoryLayout::address_to_sector_block(addr);
            if sector != self.current_sector {
                self.sector_select(sector)?;
            }

            let o = offset as usize;
            let can_write = BLOCK_SIZE - o; // bytes we can place in this page
            let n = remaining.len().min(can_write);

            if o == 0 && n == BLOCK_SIZE {
                // Full page — write directly, no read needed.
                let page = [remaining[0], remaining[1], remaining[2], remaining[3]];
                self.write(block, page)?;
            } else {
                // Partial page — read-modify-write.
                let cur = self.read(block)?;
                let mut page = [cur[0], cur[1], cur[2], cur[3]];
                page[o..o + n].copy_from_slice(&remaining[..n]);
                self.write(block, page)?;
            }

            remaining = &remaining[n..];
            addr += n as u16;
        }
        Ok(())
    }

    /// Write a single byte at a given byte address, doing a read-modify-write
    /// on the containing block.
    fn write_byte_at(&mut self, byte_addr: u16, value: u8) -> Result<(), ReaderError<T::Error>> {
        let (sector, block, offset) = MemoryLayout::address_to_sector_block(byte_addr);

        if sector != self.current_sector {
            self.sector_select(sector)?;
        }

        // Read the current block contents.
        let read_data = self.read(block)?;
        let mut block_data = [read_data[0], read_data[1], read_data[2], read_data[3]];

        // Modify the target byte.
        block_data[offset as usize] = value;

        // Write back.
        self.write(block, block_data)?;
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
    }

    impl FailingTransceiver {
        fn new(fail_count: usize) -> Self {
            FailingTransceiver {
                inner: MockTransceiver::new(),
                failures_remaining: fail_count,
            }
        }
    }

    impl T2TTransceiver for FailingTransceiver {
        type Error = ();

        fn transceive(&mut self, cmd: &[u8]) -> Result<FrameVec, ()> {
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
}
