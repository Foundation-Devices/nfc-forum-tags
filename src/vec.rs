// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared buffer types for NFC Forum tag operations.
//!
//! Provides [`FrameVec`] for command/response frames and [`DataVec`] for
//! larger payloads (NDEF messages, full sector reads). Under `no_std`,
//! these are fixed-capacity [`heapless::Vec`]s; with the `alloc` feature
//! they become standard [`Vec`]s.

/// Buffer for command/response frames (max 20 bytes covers the 16-byte READ response).
#[cfg(feature = "alloc")]
pub type FrameVec = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
pub type FrameVec = heapless::Vec<u8, 20>;

/// Buffer for larger data: NDEF messages, full sector reads (up to 1024 bytes).
#[cfg(feature = "alloc")]
pub type DataVec = alloc::vec::Vec<u8>;
#[cfg(not(feature = "alloc"))]
pub type DataVec = heapless::Vec<u8, 1024>;

/// Fallible push/extend for both `heapless::Vec` and `alloc::vec::Vec`.
pub trait VecExt<T> {
    fn try_push(&mut self, val: T) -> Result<(), BufferFullError>;
    fn try_extend(&mut self, slice: &[T]) -> Result<(), BufferFullError>
    where
        T: Clone;
}

/// Error returned when a fixed-capacity buffer is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferFullError;

#[cfg(feature = "alloc")]
impl<T: Clone> VecExt<T> for alloc::vec::Vec<T> {
    fn try_push(&mut self, val: T) -> Result<(), BufferFullError> {
        self.push(val);
        Ok(())
    }
    fn try_extend(&mut self, slice: &[T]) -> Result<(), BufferFullError> {
        self.extend_from_slice(slice);
        Ok(())
    }
}

#[cfg(not(feature = "alloc"))]
impl<T: Clone, const N: usize> VecExt<T> for heapless::Vec<T, N> {
    fn try_push(&mut self, val: T) -> Result<(), BufferFullError> {
        self.push(val).map_err(|_| BufferFullError)
    }
    fn try_extend(&mut self, slice: &[T]) -> Result<(), BufferFullError> {
        self.extend_from_slice(slice).map_err(|_| BufferFullError)
    }
}
