// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Capability Container (CC) — block 3 of a Type 2 Tag.
//!
//! The CC holds 4 bytes of management data:
//! - CC0: magic number (0xE1)
//! - CC1: mapping version (major | minor nibbles)
//! - CC2: data area size / 8
//! - CC3: access conditions (read | write nibbles)

use super::Type2Error;

/// Magic number indicating NFC Forum defined data.
pub const CC_MAGIC: u8 = 0xE1;

/// Major version this implementation supports.
pub const SUPPORTED_MAJOR_VERSION: u8 = 1;

/// NFC Forum Type 2 Tag Capability Container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContainer {
    /// CC1 major version (upper nibble).
    pub version_major: u8,
    /// CC1 minor version (lower nibble).
    pub version_minor: u8,
    /// CC2: raw size field. Actual data area size = `size_field * 8` bytes.
    pub size_field: u8,
    /// Read access condition (upper nibble of CC3).
    pub read_access: AccessCondition,
    /// Write access condition (lower nibble of CC3).
    pub write_access: AccessCondition,
}

/// Access condition for read or write (4-bit nibble from CC3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCondition {
    /// 0x0: access granted without any security.
    Granted,
    /// 0xF: no access granted (read-only for write, or denied for read).
    Denied,
    /// 0x8–0xE: proprietary access condition.
    Proprietary(u8),
    /// 0x1–0x7: reserved for future use.
    Rfu(u8),
}

impl AccessCondition {
    /// Parse a 4-bit nibble into an access condition.
    pub fn from_nibble(nibble: u8) -> Self {
        match nibble {
            0x00 => AccessCondition::Granted,
            0x0F => AccessCondition::Denied,
            0x08..=0x0E => AccessCondition::Proprietary(nibble),
            _ => AccessCondition::Rfu(nibble),
        }
    }

    /// Encode as a 4-bit nibble.
    pub fn to_nibble(self) -> u8 {
        match self {
            AccessCondition::Granted => 0x00,
            AccessCondition::Denied => 0x0F,
            AccessCondition::Proprietary(v) => v,
            AccessCondition::Rfu(v) => v,
        }
    }
}

/// Tag lifecycle state derived from CC and NDEF TLV content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagState {
    /// CC valid, NDEF Message TLV present with L=0.
    Initialized,
    /// CC valid (CC3=0x00), NDEF Message TLV with L≠0.
    ReadWrite,
    /// CC valid (CC3=0x0F), NDEF Message TLV with L≠0, all locks set.
    ReadOnly,
}

impl CapabilityContainer {
    /// Data area size in bytes (`size_field * 8`).
    pub fn data_area_size(&self) -> u16 {
        self.size_field as u16 * 8
    }

    /// Whether this is a dynamic memory tag (data area > 48 bytes).
    pub fn is_dynamic(&self) -> bool {
        self.size_field > 0x06
    }

    /// Check if the CC is valid for NDEF operations.
    ///
    /// Returns `true` if the version is compatible and read access
    /// is granted (upper nibble of CC3 = 0x0).
    pub fn is_valid(&self) -> bool {
        self.version_major == SUPPORTED_MAJOR_VERSION
            && self.read_access == AccessCondition::Granted
    }

    /// Determine the tag state given the NDEF Message TLV length.
    ///
    /// Returns `None` if the CC is not valid for NDEF operations.
    pub fn tag_state(&self, ndef_tlv_length: u16) -> Option<TagState> {
        if !self.is_valid() {
            return None;
        }
        if ndef_tlv_length == 0 && self.write_access == AccessCondition::Granted {
            Some(TagState::Initialized)
        } else if ndef_tlv_length > 0 && self.write_access == AccessCondition::Granted {
            Some(TagState::ReadWrite)
        } else if ndef_tlv_length > 0 && self.write_access == AccessCondition::Denied {
            Some(TagState::ReadOnly)
        } else {
            None
        }
    }

    /// Serialize to 4 CC bytes.
    pub fn to_bytes(&self) -> [u8; 4] {
        [
            CC_MAGIC,
            (self.version_major << 4) | (self.version_minor & 0x0F),
            self.size_field,
            (self.read_access.to_nibble() << 4) | self.write_access.to_nibble(),
        ]
    }
}

impl TryFrom<[u8; 4]> for CapabilityContainer {
    type Error = Type2Error;

    fn try_from(bytes: [u8; 4]) -> Result<Self, Type2Error> {
        if bytes[0] != CC_MAGIC {
            return Err(Type2Error::InvalidMagic(bytes[0]));
        }

        let version_major = bytes[1] >> 4;
        let version_minor = bytes[1] & 0x0F;

        // Reject if major version is higher than what we support.
        if version_major > SUPPORTED_MAJOR_VERSION {
            return Err(Type2Error::UnsupportedVersion {
                major: version_major,
                minor: version_minor,
            });
        }

        Ok(CapabilityContainer {
            version_major,
            version_minor,
            size_field: bytes[2],
            read_access: AccessCondition::from_nibble(bytes[3] >> 4),
            write_access: AccessCondition::from_nibble(bytes[3] & 0x0F),
        })
    }
}

impl TryFrom<&[u8]> for CapabilityContainer {
    type Error = Type2Error;

    fn try_from(slice: &[u8]) -> Result<Self, Type2Error> {
        if slice.len() < 4 {
            return Err(Type2Error::InvalidLength);
        }
        let bytes: [u8; 4] = [slice[0], slice[1], slice[2], slice[3]];
        CapabilityContainer::try_from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_static_cc() {
        // Example from spec: static tag, 48 bytes, r/w access
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x00]).unwrap();
        assert_eq!(cc.version_major, 1);
        assert_eq!(cc.version_minor, 0);
        assert_eq!(cc.size_field, 0x06);
        assert_eq!(cc.data_area_size(), 48);
        assert!(!cc.is_dynamic());
        assert_eq!(cc.read_access, AccessCondition::Granted);
        assert_eq!(cc.write_access, AccessCondition::Granted);
    }

    #[test]
    fn parse_dynamic_cc() {
        // Example from spec: dynamic tag, 96 bytes, r/w access
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x0C, 0x00]).unwrap();
        assert_eq!(cc.data_area_size(), 96);
        assert!(cc.is_dynamic());
    }

    #[test]
    fn parse_readonly_cc() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x0F]).unwrap();
        assert_eq!(cc.read_access, AccessCondition::Granted);
        assert_eq!(cc.write_access, AccessCondition::Denied);
    }

    #[test]
    fn reject_bad_magic() {
        let err = CapabilityContainer::try_from([0x00, 0x10, 0x06, 0x00]).unwrap_err();
        assert_eq!(err, Type2Error::InvalidMagic(0x00));
    }

    #[test]
    fn reject_higher_major_version() {
        let err = CapabilityContainer::try_from([0xE1, 0x20, 0x06, 0x00]).unwrap_err();
        assert_eq!(err, Type2Error::UnsupportedVersion { major: 2, minor: 0 });
    }

    #[test]
    fn roundtrip_cc() {
        let cc = CapabilityContainer {
            version_major: 1,
            version_minor: 0,
            size_field: 0x10,
            read_access: AccessCondition::Granted,
            write_access: AccessCondition::Granted,
        };
        let bytes = cc.to_bytes();
        assert_eq!(bytes, [0xE1, 0x10, 0x10, 0x00]);
        let parsed = CapabilityContainer::try_from(bytes).unwrap();
        assert_eq!(parsed, cc);
    }

    #[test]
    fn tag_state_initialized() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x00]).unwrap();
        assert_eq!(cc.tag_state(0), Some(TagState::Initialized));
    }

    #[test]
    fn tag_state_readwrite() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x00]).unwrap();
        assert_eq!(cc.tag_state(3), Some(TagState::ReadWrite));
    }

    #[test]
    fn tag_state_readonly() {
        let cc = CapabilityContainer::try_from([0xE1, 0x10, 0x06, 0x0F]).unwrap();
        assert_eq!(cc.tag_state(3), Some(TagState::ReadOnly));
    }
}
