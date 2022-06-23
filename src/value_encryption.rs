// Copyright 2022 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use blake2::{Blake2b, Digest};
use chacha20poly1305::{
    aead::{Aead, Error, NewAead, Payload},
    ChaCha20Poly1305,
    Key,
    Nonce,
};
use curve25519_dalek::ristretto::RistrettoPoint;

use crate::{
    commitment::HomomorphicCommitment,
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

pub fn encrypt_value(
    encryption_key: &RistrettoSecretKey,
    commitment: &HomomorphicCommitment<RistrettoPublicKey>,
    value: u64,
) -> Result<Vec<u8>, Error> {
    let shared_secret = RistrettoPublicKey::from_secret_key(encryption_key).point();
    let commitment = commitment.as_public_key().point();
    let aead_key = kdf_aead(&shared_secret, &commitment);
    // Encrypt the value (with fixed length) using ChaCha20-Poly1305 with a fixed zero nonce
    let aead_payload = Payload {
        msg: &value.to_le_bytes(),
        aad: b"TARI_AAD_SCAN".as_ref(),
    };
    // Included in the public transaction
    ChaCha20Poly1305::new(&aead_key).encrypt(&Nonce::default(), aead_payload)
}

// Authenticate and decrypt an AEAD value
pub fn decrypt_value(
    encryption_key: &RistrettoSecretKey,
    commitment: &HomomorphicCommitment<RistrettoPublicKey>,
    aead_value: &[u8],
) -> Result<u64, Error> {
    let shared_secret = RistrettoPublicKey::from_secret_key(encryption_key).point();
    let commitment = commitment.as_public_key().point();
    let aead_key = kdf_aead(&shared_secret, &commitment);
    // Authenticate and decrypt the value
    let aead_payload = Payload {
        msg: &aead_value,
        aad: b"TARI_AAD_SCAN".as_ref(),
    };
    let mut value_bytes = [0u8; 8];
    let decrypted_bytes = ChaCha20Poly1305::new(&aead_key).decrypt(&Nonce::default(), aead_payload)?;
    value_bytes.clone_from_slice(&decrypted_bytes[..8]);
    Ok(u64::from_le_bytes(value_bytes))
}

// Generate a ChaCha20-Poly1305 key from an ECDH shared secret and commitment using Blake2b
fn kdf_aead(shared_secret: &RistrettoPoint, commitment: &RistrettoPoint) -> Key {
    const AEAD_KEY_LENGTH: usize = 32; // The length in bytes of a ChaCha20-Poly1305 AEAD key
    assert!(Blake2b::output_size() >= AEAD_KEY_LENGTH); // Make sure the hash function can produce enough key

    let mut hasher = Blake2b::with_params(&[], &mut b"SCAN_AEAD".as_ref(), &mut b"TARI_KDF".as_ref());
    hasher.update(shared_secret.compress().as_bytes());
    hasher.update(commitment.compress().as_bytes());
    let output = hasher.finalize();

    *Key::from_slice(&output[..AEAD_KEY_LENGTH])
}
