// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Handy utility functions for use in tests and demo scripts

use digest::Digest;
use tari_utilities::ByteArray;

use crate::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
    signatures::SchnorrSignatureError,
};

/// A set of keys and it's associated signature
pub struct SignatureSet {
    /// The secret nonce
    pub nonce: RistrettoSecretKey,
    /// The public nonce
    pub public_nonce: RistrettoPublicKey,
    /// The message signed. Note that the [SignatureSet::public_nonce] is prepended to this message before signing
    pub message: Vec<u8>,
    /// The signature
    pub signature: RistrettoSchnorr,
}

/// Generate a random keypair and a signature for the provided message
///
/// # Panics
///
/// The function panics if it cannot generate a suitable signature
#[deprecated(
    since = "0.16.0",
    note = "Use SchnorrSignature::sign_message instead. This method will be removed in v1.0.0"
)]
pub fn sign<D: Digest>(
    private_key: &RistrettoSecretKey,
    message: &[u8],
) -> Result<SignatureSet, SchnorrSignatureError> {
    let mut rng = rand::thread_rng();
    let (nonce, public_nonce) = RistrettoPublicKey::random_keypair(&mut rng);
    let message = D::new()
        .chain(public_nonce.as_bytes())
        .chain(message)
        .finalize()
        .to_vec();
    let e = RistrettoSecretKey::from_bytes(&message).map_err(|_| SchnorrSignatureError::InvalidChallenge)?;
    let s = RistrettoSchnorr::sign_raw(&private_key, nonce.clone(), e.as_bytes())?;
    Ok(SignatureSet {
        nonce,
        public_nonce,
        message,
        signature: s,
    })
}
