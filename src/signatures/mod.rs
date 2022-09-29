// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

mod commitment_and_public_key_signature;
mod commitment_signature;
mod schnorr;

pub use commitment_and_public_key_signature::*;
pub use commitment_signature::*;
pub use schnorr::*;
