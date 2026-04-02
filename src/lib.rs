// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # nfc-forum-tags
//!
//! Rust implementation of NFC Forum Tag Type operations.
//!
//! Currently supports **Type 2 Tag** (T2TOP 1.1) with plans for Type 4.
//!
//! ## Architecture
//!
//! The library provides data structures and a transport layer for
//! interacting with NFC Forum tags after ISO 14443-3A activation:
//!
//! - [`type2::T2TTransceiver`] — implement for your NFC-A hardware
//! - [`type2::Command`] / [`type2::Answer`] — command serialization and response parsing
//! - [`type2::reader::T2TReader`] — high-level orchestrator for NDEF detection, read, write
//!
//! ## Features
//!
//! - `alloc` — use `Vec` instead of `heapless::Vec` for buffers
//! - `std` — implies `alloc`
//!
//! `#![no_std]` by default (uses `heapless` with fixed-size buffers).

#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod type2;
pub mod vec;
