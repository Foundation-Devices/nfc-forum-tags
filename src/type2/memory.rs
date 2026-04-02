// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Memory structure and layout for Type 2 Tags.
//!
//! Type 2 Tags use a block-based memory model:
//! - Block = 4 bytes
//! - Sector = 256 blocks = 1024 bytes
//! - Static memory: 16 blocks (64 bytes)
//! - Dynamic memory: >16 blocks, up to 255 sectors

use super::cc::CapabilityContainer;
use super::tlv::{LockControlValue, MemoryControlValue, Tlv};

/// Block size in bytes.
pub const BLOCK_SIZE: usize = 4;

/// Number of blocks per sector.
pub const BLOCKS_PER_SECTOR: usize = 256;

/// Sector size in bytes (256 blocks * 4 bytes).
pub const SECTOR_SIZE: usize = BLOCK_SIZE * BLOCKS_PER_SECTOR;

/// Block number of the Capability Container.
pub const CC_BLOCK: u8 = 3;

/// First block of the data area.
pub const DATA_START_BLOCK: u8 = 4;

/// Data area size for static memory structure (blocks 4–15 = 48 bytes).
pub const STATIC_DATA_AREA_SIZE: usize = 48;

/// Static memory total size (16 blocks = 64 bytes).
pub const STATIC_MEMORY_SIZE: usize = 64;

/// Byte address of static lock bytes (block 2, bytes 2–3).
pub const STATIC_LOCK_BYTE_ADDR: u16 = 10;

/// A lock area descriptor.
///
/// Describes a contiguous region of lock bytes that protect data bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockArea {
    /// Byte address of the first lock byte.
    pub byte_address: u16,
    /// Number of lock bits in this area.
    pub size_in_bits: u16,
    /// Number of data bytes each lock bit protects.
    pub bytes_per_lock_bit: u16,
}

impl LockArea {
    /// Number of lock bytes (ceiling of bits / 8).
    pub fn lock_byte_count(&self) -> u16 {
        (self.size_in_bits + 7) / 8
    }

    /// Byte address past the last lock byte.
    pub fn end_address(&self) -> u16 {
        self.byte_address + self.lock_byte_count()
    }

    /// Create from a parsed Lock Control TLV value.
    pub fn from_lock_control(lc: &LockControlValue) -> Self {
        LockArea {
            byte_address: lc.byte_address(),
            size_in_bits: lc.size_in_bits,
            bytes_per_lock_bit: lc.bytes_per_lock_bit(),
        }
    }

    /// Check if a byte address falls within this lock area.
    pub fn contains(&self, addr: u16) -> bool {
        addr >= self.byte_address && addr < self.end_address()
    }
}

/// A reserved memory area descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservedArea {
    /// Byte address of the first reserved byte.
    pub byte_address: u16,
    /// Number of reserved bytes.
    pub size: u16,
}

impl ReservedArea {
    /// Byte address past the last reserved byte.
    pub fn end_address(&self) -> u16 {
        self.byte_address + self.size
    }

    /// Create from a parsed Memory Control TLV value.
    pub fn from_memory_control(mc: &MemoryControlValue) -> Self {
        ReservedArea {
            byte_address: mc.byte_address(),
            size: mc.size_in_bytes,
        }
    }

    /// Check if a byte address falls within this reserved area.
    pub fn contains(&self, addr: u16) -> bool {
        addr >= self.byte_address && addr < self.end_address()
    }
}

/// Describes the complete memory layout of a Type 2 Tag.
///
/// Built from the Capability Container and TLV blocks found in the data area.
#[derive(Debug, Clone)]
pub struct MemoryLayout {
    /// Total data area size in bytes (from CC2 * 8).
    pub data_area_size: u16,
    /// Lock areas (static + dynamic from Lock Control TLVs).
    #[cfg(not(feature = "alloc"))]
    pub lock_areas: heapless::Vec<LockArea, 8>,
    #[cfg(feature = "alloc")]
    pub lock_areas: alloc::vec::Vec<LockArea>,
    /// Reserved areas (from Memory Control TLVs).
    #[cfg(not(feature = "alloc"))]
    pub reserved_areas: heapless::Vec<ReservedArea, 8>,
    #[cfg(feature = "alloc")]
    pub reserved_areas: alloc::vec::Vec<ReservedArea>,
}

impl MemoryLayout {
    /// Build a memory layout from the CC and parsed TLV blocks.
    pub fn from_cc_and_tlvs(cc: &CapabilityContainer, tlvs: &[Tlv]) -> Self {
        let data_area_size = cc.data_area_size();

        #[cfg(not(feature = "alloc"))]
        let mut lock_areas = heapless::Vec::<LockArea, 8>::new();
        #[cfg(feature = "alloc")]
        let mut lock_areas = alloc::vec::Vec::<LockArea>::new();

        #[cfg(not(feature = "alloc"))]
        let mut reserved_areas = heapless::Vec::<ReservedArea, 8>::new();
        #[cfg(feature = "alloc")]
        let mut reserved_areas = alloc::vec::Vec::<ReservedArea>::new();

        for tlv in tlvs {
            match tlv {
                Tlv::LockControl(lc) => {
                    let area = LockArea::from_lock_control(lc);
                    let _ = push_area(&mut lock_areas, area);
                }
                Tlv::MemoryControl(mc) => {
                    let area = ReservedArea::from_memory_control(mc);
                    let _ = push_area(&mut reserved_areas, area);
                }
                _ => {}
            }
        }

        // If dynamic memory and no Lock Control TLVs, apply default lock area.
        if cc.is_dynamic() && lock_areas.is_empty() {
            let default_lock = default_dynamic_lock_area(data_area_size);
            let _ = push_area(&mut lock_areas, default_lock);
        }

        MemoryLayout {
            data_area_size,
            lock_areas,
            reserved_areas,
        }
    }

    /// Check if a byte address is in a lock or reserved area (should be skipped during data reads).
    pub fn is_skip_area(&self, byte_addr: u16) -> bool {
        self.lock_areas.iter().any(|a| a.contains(byte_addr))
            || self.reserved_areas.iter().any(|a| a.contains(byte_addr))
    }

    /// Total number of sectors needed for this tag.
    pub fn sector_count(&self) -> u8 {
        let total_bytes = self.data_area_size as u32
            + (DATA_START_BLOCK as u32 * BLOCK_SIZE as u32)
            + self
                .lock_areas
                .iter()
                .map(|a| a.lock_byte_count() as u32)
                .sum::<u32>()
            + self
                .reserved_areas
                .iter()
                .map(|a| a.size as u32)
                .sum::<u32>();
        let sectors = (total_bytes + SECTOR_SIZE as u32 - 1) / SECTOR_SIZE as u32;
        sectors.min(255) as u8
    }

    /// Convert a linear byte address to (sector, block, offset).
    pub fn address_to_sector_block(byte_addr: u16) -> (u8, u8, u8) {
        let sector = (byte_addr / SECTOR_SIZE as u16) as u8;
        let within_sector = byte_addr % SECTOR_SIZE as u16;
        let block = (within_sector / BLOCK_SIZE as u16) as u8;
        let offset = (within_sector % BLOCK_SIZE as u16) as u8;
        (sector, block, offset)
    }

    /// Convert (sector, block, offset) to a linear byte address.
    pub fn sector_block_to_address(sector: u8, block: u8, offset: u8) -> u16 {
        sector as u16 * SECTOR_SIZE as u16 + block as u16 * BLOCK_SIZE as u16 + offset as u16
    }
}

/// Default dynamic lock area when no Lock Control TLV is present (Section 2.2.2).
fn default_dynamic_lock_area(data_area_size: u16) -> LockArea {
    let extra_bytes = data_area_size.saturating_sub(STATIC_DATA_AREA_SIZE as u16);
    let lock_bits = (extra_bytes + 7) / 8;
    // Default position: first byte after the data area.
    let byte_address = DATA_START_BLOCK as u16 * BLOCK_SIZE as u16 + data_area_size;

    LockArea {
        byte_address,
        size_in_bits: lock_bits,
        bytes_per_lock_bit: 8,
    }
}

/// Push into a heapless or alloc vec, ignoring overflow for heapless.
#[cfg(not(feature = "alloc"))]
fn push_area<T, const N: usize>(vec: &mut heapless::Vec<T, N>, val: T) -> Result<(), ()> {
    vec.push(val).map_err(|_| ())
}

#[cfg(feature = "alloc")]
fn push_area<T>(vec: &mut alloc::vec::Vec<T>, val: T) -> Result<(), ()> {
    vec.push(val);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type2::cc::CapabilityContainer;

    #[test]
    fn static_layout() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x00]).unwrap();
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &[]);
        assert_eq!(layout.data_area_size, 48);
        assert!(layout.lock_areas.is_empty());
        assert!(layout.reserved_areas.is_empty());
    }

    #[test]
    fn dynamic_layout_with_default_locks() {
        // 96 bytes data area, no TLVs → default lock area
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x0C, 0x00]).unwrap();
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &[]);
        assert_eq!(layout.data_area_size, 96);
        assert_eq!(layout.lock_areas.len(), 1);

        let lock = &layout.lock_areas[0];
        // Default: after data area = block 4 offset + 96 = 16 + 96 = 112
        assert_eq!(lock.byte_address, 112);
        // (96 - 48) / 8 = 6 lock bits
        assert_eq!(lock.size_in_bits, 6);
    }

    #[test]
    fn dynamic_layout_with_lock_control_tlv() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x0C, 0x00]).unwrap();
        let lc = LockControlValue {
            page_addr: 0x0E,
            byte_offset: 0x00,
            size_in_bits: 6,
            bytes_per_page: 3,
            bytes_locked_per_bit: 3,
        };
        let tlvs = [Tlv::LockControl(lc)];
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &tlvs);

        // Lock Control TLV overrides default
        assert_eq!(layout.lock_areas.len(), 1);
        assert_eq!(layout.lock_areas[0].byte_address, 112);
        assert_eq!(layout.lock_areas[0].bytes_per_lock_bit, 8); // 2^3 = 8
    }

    #[test]
    fn address_conversion_roundtrip() {
        let addr = 113u16;
        let (sector, block, offset) = MemoryLayout::address_to_sector_block(addr);
        assert_eq!(sector, 0);
        assert_eq!(block, 28);
        assert_eq!(offset, 1);
        assert_eq!(
            MemoryLayout::sector_block_to_address(sector, block, offset),
            addr
        );
    }

    #[test]
    fn skip_area_detection() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x0C, 0x00]).unwrap();
        let lc = LockControlValue {
            page_addr: 0x0E,
            byte_offset: 0x00,
            size_in_bits: 6,
            bytes_per_page: 3,
            bytes_locked_per_bit: 3,
        };
        let mc = MemoryControlValue {
            page_addr: 0x0E,
            byte_offset: 0x01,
            size_in_bytes: 15,
            bytes_per_page: 3,
        };
        let tlvs = [Tlv::LockControl(lc), Tlv::MemoryControl(mc)];
        let layout = MemoryLayout::from_cc_and_tlvs(&cc, &tlvs);

        // Lock area at 112, 1 byte
        assert!(layout.is_skip_area(112));
        // Reserved area starts at 113, length 15 → 113..128
        assert!(layout.is_skip_area(113));
        assert!(layout.is_skip_area(127));
        assert!(!layout.is_skip_area(128));
        // Data area byte should not be skip
        assert!(!layout.is_skip_area(16));
    }
}
