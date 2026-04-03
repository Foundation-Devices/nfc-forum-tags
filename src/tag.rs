// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared tag types for all NFC Forum tag types.
//!
//! These types are common across Type 2, Type 4, and other tag
//! specifications defined by the NFC Forum.

/// Tag lifecycle state.
///
/// All NFC Forum tag types define the same three states with
/// equivalent semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagState {
    /// CC valid, NDEF present but empty (length = 0).
    Initialized,
    /// CC valid, NDEF present with data, write access granted.
    ReadWrite,
    /// CC valid, NDEF present with data, write access denied.
    ReadOnly,
}

/// Access condition for read or write operations.
///
/// Used by both Type 2 (4-bit nibble encoding) and Type 4
/// (full byte encoding) tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessCondition {
    /// Access granted without any security.
    Granted,
    /// No access granted.
    Denied,
    /// Proprietary access condition.
    Proprietary(u8),
    /// Reserved for future use.
    Rfu(u8),
}

impl AccessCondition {
    /// Parse a 4-bit nibble (Type 2 Tag CC3 encoding).
    ///
    /// - 0x0: Granted
    /// - 0xF: Denied
    /// - 0x8–0xE: Proprietary
    /// - 0x1–0x7: RFU
    pub fn from_nibble(nibble: u8) -> Self {
        match nibble {
            0x00 => AccessCondition::Granted,
            0x0F => AccessCondition::Denied,
            0x08..=0x0E => AccessCondition::Proprietary(nibble),
            _ => AccessCondition::Rfu(nibble),
        }
    }

    /// Encode as a 4-bit nibble (Type 2 Tag CC3 encoding).
    pub fn to_nibble(self) -> u8 {
        match self {
            AccessCondition::Granted => 0x00,
            AccessCondition::Denied => 0x0F,
            AccessCondition::Proprietary(v) => v,
            AccessCondition::Rfu(v) => v,
        }
    }
}
