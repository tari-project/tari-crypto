// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Tari-Crypto

#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(any(feature = "bulletproofs_plus", test))]
#[macro_use]
extern crate std;

#[macro_use]
mod macros;
pub mod commitment;
pub mod deterministic_randomizer;
pub mod dhke;
pub mod hashing;
pub mod keys;
#[cfg(feature = "bulletproofs_plus")]
pub mod range_proof;
pub mod signatures;

// Implementations
#[allow(clippy::op_ref)]
pub mod ristretto;

pub mod compressed_commitment;
pub mod compressed_key;
pub mod errors;
#[cfg(feature = "bulletproofs_plus")]
pub mod extended_range_proof;

// Re-export tari_utils
pub use tari_utilities;
