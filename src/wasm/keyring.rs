// Copyright 2020. The Tari Project
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

use wasm_bindgen::prelude::*;

use crate::{
    commitment::HomomorphicCommitmentFactory,
    keys::PublicKey,
    ristretto::{
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
    wasm::{
        commitments::CommitmentResult,
        key_utils::{sign_message_with_key, SignResult},
    },
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use tari_utilities::hex::Hex;

#[wasm_bindgen]
#[derive(Default)]
pub struct KeyRing {
    factory: PedersenCommitmentFactory,
    keys: HashMap<String, (RistrettoSecretKey, RistrettoPublicKey)>,
}

#[wasm_bindgen]
impl KeyRing {
    /// Create new keyring
    pub fn new() -> Self {
        KeyRing {
            keys: HashMap::new(),
            factory: PedersenCommitmentFactory::default(),
        }
    }

    /// Create a new random keypair and associate it with 'id'. The number of keys in the keyring is returned
    pub fn new_key(&mut self, id: String) -> usize {
        let pair = RistrettoPublicKey::random_keypair(&mut OsRng);
        self.keys.insert(id, pair);
        self.keys.len()
    }

    /// Return the number of keys in the keyring
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if there are no keys in the key ring, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Return the private key associated with 'id' as a hex string. If there is no key associated with the `id`,
    /// `None` is returned.
    pub fn private_key(&self, id: &str) -> Option<String> {
        self.keys.get(id).map(|p| p.0.to_hex())
    }

    /// Return the public key associated with 'id' as a hex string. If there is no key associated with the `id`,
    /// `None` is returned.
    pub fn public_key(&self, id: &str) -> Option<String> {
        self.keys.get(id).map(|p| p.1.to_hex())
    }

    /// Sign a message using a private key
    ///
    /// Use can use a key in the keyring to generate a digital signature. To create the signature, the caller must
    /// provide the `id` associated with the key, the message to sign, and a `nonce`.
    ///
    /// The return type is pretty unRust-like, but is structured to more closely model a JSON object.
    ///
    /// `keys::check_signature` is used to verify signatures.
    pub fn sign(&self, id: &str, msg: &str) -> JsValue {
        let mut result = SignResult::default();
        let k = self.keys.get(id);
        if k.is_none() {
            result.error = format!("Private key for '{}' does not exist", id);
            return JsValue::from_serde(&result).unwrap();
        }
        let k = k.unwrap();
        sign_message_with_key(&k.0, msg, None, &mut result);
        JsValue::from_serde(&result).unwrap()
    }

    /// Sign a message using a private key and a specific nonce
    ///
    /// Use can use a key in the keyring to generate a digital signature. To create the signature, the caller must
    /// provide the `id` associated with the key, the message to sign, and a `nonce_id`. *Do not* reuse nonces.
    /// This function is provided because in some signature schemes require the public nonce to be
    /// part of the message.
    ///
    /// The return type is pretty unRust-like, but is structured to more closely model a JSON object.
    ///
    /// `keys::check_signature` is used to verify signatures.
    pub fn sign_with_nonce(&self, id: &str, nonce_id: &str, msg: &str) -> JsValue {
        let mut result = SignResult::default();
        let k = self.keys.get(id);
        if k.is_none() {
            result.error = format!("Private key for '{}' does not exist", id);
            return JsValue::from_serde(&result).unwrap();
        }
        let k = k.unwrap();
        let nonce = self.keys.get(nonce_id);
        if nonce.is_none() {
            result.error = format!("Private nonce for `{}` does not exist", nonce_id);
            return JsValue::from_serde(&result).unwrap();
        }
        let nonce = nonce.unwrap();
        sign_message_with_key(&k.0, msg, Some(&nonce.0), &mut result);
        JsValue::from_serde(&result).unwrap()
    }

    /// Commits a value and private key for the given id using a Pedersen commitment.
    pub fn commit(&self, id: &str, value: u64) -> JsValue {
        let mut result = CommitmentResult::default();
        let k = match self.keys.get(id) {
            Some(k) => &k.0,
            None => {
                result.error = format!("Private key for '{}' does not exist", id);
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let commitment = self.factory.commit_value(k, value);
        result.commitment = Some(commitment.to_hex());
        JsValue::from_serde(&result).unwrap()
    }

    /// Checks whether the key for the given id and value opens the commitment
    pub fn opens(&self, id: &str, value: u64, commitment: &str) -> bool {
        let k = match self.keys.get(id) {
            Some(k) => &k.0,
            None => return false,
        };
        let commitment = match RistrettoPublicKey::from_hex(commitment) {
            Ok(p) => PedersenCommitment::from_public_key(&p),
            _ => return false,
        };
        self.factory.open_value(k, value, &commitment)
    }
}
