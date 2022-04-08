// Copyright 2018 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This crate is part of the [Tari Cryptocurrency](https://tari.com) project.
//!
//! Major features of this library include:
//!
//! - Pedersen commitments
//! - Schnorr Signatures
//! - Generic Public and Secret Keys
//!
//! The `tari_crypto` crate makes heavy use of the excellent [Dalek](https://github.com/dalek-cryptography/curve25519-dalek)
//!  libraries. The default implementation for Tari ECC is the [Ristretto255 curve](https://ristretto.group).

#[macro_use]
extern crate lazy_static;

#[macro_use]
mod macros;
pub mod commitment;
pub mod hash;
pub mod keys;
#[cfg(feature = "musig")]
pub mod musig;
pub mod range_proof;
pub mod signatures;

// Implementations
#[allow(clippy::op_ref)]
pub mod ristretto;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export tari_utils
pub use tari_utilities;
