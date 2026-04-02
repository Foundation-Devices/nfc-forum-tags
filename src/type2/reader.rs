// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! High-level Type 2 Tag reader/writer.
//!
//! [`T2TReader`] orchestrates command sequences for NDEF detection,
//! reading, and writing on a Type 2 Tag after ISO 14443-3A activation.

use super::cc::{AccessCondition, CapabilityContainer};
use super::memory::{BLOCK_SIZE, CC_BLOCK, DATA_START_BLOCK, MemoryLayout};
use super::tlv::{self, Tlv};
use super::{Answer, Command, T2TTransceiver, Type2Error};
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

/// High-level NFC Forum Type 2 Tag reader/writer.
///
/// Wraps a [`T2TTransceiver`] and tracks the currently selected sector.
pub struct T2TReader<'t, T: T2TTransceiver> {
    transceiver: &'t mut T,
    current_sector: u8,
}

impl<'t, T: T2TTransceiver> T2TReader<'t, T> {
    /// Create a new reader. The default sector is 0.
    pub fn new(transceiver: &'t mut T) -> Self {
        T2TReader {
            transceiver,
            current_sector: 0,
        }
    }

    /// Read 4 blocks (16 bytes) starting at `block_no` in the current sector.
    pub fn read(&mut self, block_no: u8) -> Result<[u8; 16], ReaderError<T::Error>> {
        let cmd = Command::Read { block_no };
        let raw = self
            .transceiver
            .transceive(&cmd.to_bytes())
            .map_err(ReaderError::Transceiver)?;
        match cmd.parse_answer(&raw)? {
            Answer::Data(data) => Ok(data),
            Answer::Nack(code) => Err(Type2Error::Nack(code).into()),
            _ => Err(Type2Error::InvalidLength.into()),
        }
    }

    /// Write 4 bytes to `block_no` in the current sector.
    pub fn write(&mut self, block_no: u8, data: [u8; 4]) -> Result<(), ReaderError<T::Error>> {
        let cmd = Command::Write { block_no, data };
        let raw = self
            .transceiver
            .transceive(&cmd.to_bytes())
            .map_err(ReaderError::Transceiver)?;
        match cmd.parse_answer(&raw)? {
            Answer::Ack => Ok(()),
            Answer::Nack(code) => Err(Type2Error::Nack(code).into()),
            _ => Err(Type2Error::InvalidLength.into()),
        }
    }

    /// Select a sector (for tags > 1 KB).
    ///
    /// Sends SECTOR SELECT Packet 1, expects ACK, then sends Packet 2
    /// and expects passive ACK (silence).
    pub fn sector_select(&mut self, sector: u8) -> Result<(), ReaderError<T::Error>> {
        if sector == self.current_sector {
            return Ok(());
        }

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
    /// Returns the contiguous data area bytes with lock/reserved regions removed.
    pub fn read_data_area(
        &mut self,
        layout: &MemoryLayout,
    ) -> Result<DataVec, ReaderError<T::Error>> {
        let mut result = DataVec::new();
        let total_bytes = layout.data_area_size;
        let mut bytes_read = 0u16;

        // Start reading from block 4.
        let start_byte_addr = DATA_START_BLOCK as u16 * BLOCK_SIZE as u16;
        // We need to read enough blocks to cover data_area_size plus any
        // interspersed lock/reserved areas.
        let mut byte_addr = start_byte_addr;

        // Read block by block (4 bytes at a time) to handle skip areas.
        // We use READ which returns 16 bytes (4 blocks), but we process
        // one block at a time to properly skip lock/reserved areas.
        let mut read_cache: Option<(u8, [u8; 16])> = None;

        while bytes_read < total_bytes {
            let (sector, block, _) = MemoryLayout::address_to_sector_block(byte_addr);

            // Switch sector if needed.
            if sector != self.current_sector {
                self.sector_select(sector)?;
            }

            // Check if we have this block cached from a previous READ.
            let block_data = if let Some((cached_block, ref cached_data)) = read_cache {
                let blocks_ahead = block.wrapping_sub(cached_block);
                if blocks_ahead < 4 {
                    // This block is in the cache.
                    let offset = blocks_ahead as usize * BLOCK_SIZE;
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&cached_data[offset..offset + BLOCK_SIZE]);
                    b
                } else {
                    // Need a new READ.
                    let data = self.read(block)?;
                    read_cache = Some((block, data));
                    let mut b = [0u8; 4];
                    b.copy_from_slice(&data[..BLOCK_SIZE]);
                    b
                }
            } else {
                let data = self.read(block)?;
                read_cache = Some((block, data));
                let mut b = [0u8; 4];
                b.copy_from_slice(&data[..BLOCK_SIZE]);
                b
            };

            // Process each byte in this block.
            for i in 0..BLOCK_SIZE {
                let addr = byte_addr + i as u16;
                if layout.is_skip_area(addr) {
                    continue;
                }
                if bytes_read < total_bytes {
                    result
                        .try_push(block_data[i])
                        .map_err(|e| Type2Error::from(e))?;
                    bytes_read += 1;
                }
            }

            byte_addr += BLOCK_SIZE as u16;
        }

        Ok(result)
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

        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &[]);
        let data_area = self.read_data_area(&layout)?;

        let tlvs = tlv::parse_tlvs(&data_area).map_err(ReaderError::Protocol)?;

        // Re-derive layout with TLV info for completeness.
        let _layout = MemoryLayout::from_cc_and_tlvs(&cc, &tlvs);

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
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &[]);

        // Calculate available space: data_area_size minus Lock/Memory Control TLVs.
        let ndef_len = ndef_data.len() as u16;
        let l_field_size: u16 = if ndef_len < 0xFF { 1 } else { 3 };
        let total_ndef_tlv_size = 1 + l_field_size + ndef_len; // T + L + V
        let terminator_size = 1u16; // Terminator TLV

        if total_ndef_tlv_size + terminator_size > cc.data_area_size() {
            return Err(Type2Error::OutOfRange.into());
        }

        // We need to find where the first NDEF Message TLV starts in the
        // block structure. For simplicity, read block 4 to find TLV start.
        // In a static tag, NDEF TLV starts at block 4 byte 0.
        // In a dynamic tag, it follows Lock/Memory Control TLVs.

        let data_area = self.read_data_area(&layout)?;
        let tlvs = tlv::parse_tlvs(&data_area).map_err(ReaderError::Protocol)?;

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

        // Build the new TLV sequence starting at ndef_offset:
        // Step 1: Write T=03, L=00 (set length to 0 first for crash safety).
        let data_start_addr = DATA_START_BLOCK as u16 * BLOCK_SIZE as u16;
        let ndef_byte_addr = data_start_addr + ndef_offset as u16;

        // We need to write block-by-block. First write the NDEF TLV header
        // with L=0, then the data, then update L.

        // Build the full byte sequence: [03, L=00, ...ndef_data..., FE]
        // Then we'll go back and fix L.

        // Phase 1: Write T=03, L=00 at the NDEF TLV position.
        self.write_byte_at(ndef_byte_addr, 0x03, &layout)?;
        self.write_byte_at(ndef_byte_addr + 1, 0x00, &layout)?;

        // Phase 2: Write NDEF data starting after T+L (1-byte L for now).
        let v_start = if ndef_len < 0xFF {
            ndef_byte_addr + 2 // T(1) + L(1)
        } else {
            ndef_byte_addr + 4 // T(1) + L(3)
        };

        for (i, &byte) in ndef_data.iter().enumerate() {
            self.write_byte_at(v_start + i as u16, byte, &layout)?;
        }

        // Phase 3: Write Terminator TLV after the NDEF data.
        let terminator_addr = v_start + ndef_len;
        // Only write terminator if there's room.
        if terminator_addr < data_start_addr + cc.data_area_size() {
            self.write_byte_at(terminator_addr, 0xFE, &layout)?;
        }

        // Phase 4: Update L field with actual length.
        if ndef_len < 0xFF {
            self.write_byte_at(ndef_byte_addr + 1, ndef_len as u8, &layout)?;
        } else {
            self.write_byte_at(ndef_byte_addr + 1, 0xFF, &layout)?;
            self.write_byte_at(ndef_byte_addr + 2, (ndef_len >> 8) as u8, &layout)?;
            self.write_byte_at(ndef_byte_addr + 3, ndef_len as u8, &layout)?;
        }

        Ok(())
    }

    /// Write a single byte at a given byte address, doing a read-modify-write
    /// on the containing block.
    fn write_byte_at(
        &mut self,
        byte_addr: u16,
        value: u8,
        _layout: &MemoryLayout,
    ) -> Result<(), ReaderError<T::Error>> {
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
}
