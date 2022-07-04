// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This module contains implementations using the Ristretto curve.

pub mod bulletproofs_plus;
pub mod constants;
mod dalek_range_proof;
#[cfg(feature = "musig")]
pub mod musig;
pub mod pedersen;
mod ristretto_com_sig;
pub mod ristretto_keys;
mod ristretto_sig;
pub mod serialize;
pub mod utils;

// Re-export
pub use dalek_range_proof::DalekRangeProofService;

pub use self::{
    ristretto_com_sig::RistrettoComSig,
    ristretto_keys::{RistrettoPublicKey, RistrettoSecretKey},
    ristretto_sig::RistrettoSchnorr,
};

// test modules
#[cfg(test)]
mod test_common;
