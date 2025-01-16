// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This module contains implementations using the Ristretto curve.

#[cfg(feature = "bulletproofs_plus")]
pub mod bulletproofs_plus;
pub mod constants;
pub mod pedersen;
mod ristretto_com_and_pub_sig;
mod ristretto_com_sig;
pub mod ristretto_keys;
mod ristretto_sig;
#[cfg(feature = "serde")]
pub mod serialize;

pub use self::{
    ristretto_com_and_pub_sig::{CompressedRistrettoComAndPubSig,RistrettoComAndPubSig},
    ristretto_com_sig::RistrettoComSig,
    ristretto_keys::{RistrettoPublicKey, RistrettoSecretKey},
    ristretto_sig::{CompressedRistrettoSchnorr,RistrettoSchnorr, RistrettoSchnorrWithDomain},
};

// test modules
#[cfg(test)]
mod test_common;
