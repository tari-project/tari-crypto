// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This module contains implementations using the Ristretto curve.

pub mod bulletproofs_plus;
pub mod constants;
#[cfg(feature = "bulletproofs")]
mod dalek_range_proof;
pub mod pedersen;
mod ristretto_com_and_pub_sig;
mod ristretto_com_sig;
pub mod ristretto_keys;
mod ristretto_sig;
#[cfg(feature = "serde")]
pub mod serialize;
pub mod utils;

// Re-export
#[cfg(feature = "bulletproofs")]
pub use dalek_range_proof::DalekRangeProofService;

pub use self::{
    ristretto_com_and_pub_sig::RistrettoComAndPubSig,
    ristretto_com_sig::RistrettoComSig,
    ristretto_keys::{RistrettoPublicKey, RistrettoSecretKey},
    ristretto_sig::{RistrettoSchnorr, RistrettoSchnorrWithDomain},
};

// test modules
#[cfg(test)]
mod test_common;
