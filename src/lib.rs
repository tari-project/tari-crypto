// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Tari-Crypto
#![no_std]

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;


#[macro_use]
mod macros;
pub mod commitment;
pub mod deterministic_randomizer;
pub mod dhke;
pub mod hash;
pub mod hashing;
pub mod keys;
pub mod range_proof;
pub mod rewindable_range_proof;
pub mod signatures;

// Implementations
#[allow(clippy::op_ref)]
pub mod ristretto;

#[cfg(feature = "wasm")]
pub mod wasm;

pub mod errors;
pub mod extended_range_proof;
#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export tari_utils
pub use tari_utilities;
