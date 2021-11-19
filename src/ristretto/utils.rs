// Copyright 2020. The Tari Project
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Handy utility functions for use in tests and demo scripts

use crate::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
    signatures::SchnorrSignatureError,
};
use digest::Digest;
use tari_utilities::ByteArray;

/// A set of keys and it's associated signature
pub struct SignatureSet {
    pub nonce: RistrettoSecretKey,
    pub public_nonce: RistrettoPublicKey,
    pub message: Vec<u8>,
    pub signature: RistrettoSchnorr,
}

/// Generate a random keypair and a signature for the provided message
///
/// # Panics
///
/// The function panics if it cannot generate a suitable signature
pub fn sign<D: Digest>(
    private_key: &RistrettoSecretKey,
    message: &[u8],
) -> Result<SignatureSet, SchnorrSignatureError> {
    let mut rng = rand::thread_rng();
    let (nonce, public_nonce) = RistrettoPublicKey::random_keypair(&mut rng);
    let message = D::new()
        .chain(public_nonce.compress().as_bytes())
        .chain(message)
        .finalize()
        .to_vec();
    let e = RistrettoSecretKey::from_bytes(&message).map_err(|_| SchnorrSignatureError::InvalidChallenge)?;
    let s = RistrettoSchnorr::sign(private_key.clone(), nonce.clone(), e.as_bytes())?;
    Ok(SignatureSet {
        nonce,
        public_nonce,
        message,
        signature: s,
    })
}
