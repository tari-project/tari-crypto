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

use crate::{
    commitment::HomomorphicCommitmentFactory,
    ristretto::{
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};
use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

#[derive(Default, Serialize, Deserialize)]
pub struct CommitmentResult {
    pub commitment: Option<String>,
    pub error: String,
}

/// Commits a value and blinding factor (private key) using a Pedersen commitment.
#[wasm_bindgen]
pub fn commit(key: &str, value: u64) -> JsValue {
    let mut result = CommitmentResult::default();
    let k = RistrettoSecretKey::from_hex(key);
    if k.is_err() {
        result.error = "Invalid private key".to_string();
        return JsValue::from_serde(&result).unwrap();
    }
    let factory = PedersenCommitmentFactory::default();
    let commitment = factory.commit_value(&k.unwrap(), value);
    result.commitment = Some(commitment.to_hex());
    JsValue::from_serde(&result).unwrap()
}

/// Checks whether the given key and value opens the commitment
#[wasm_bindgen]
pub fn opens(key: &str, value: u64, commitment: &str) -> bool {
    let k = RistrettoSecretKey::from_hex(key);
    if k.is_err() {
        return false;
    }
    let c = RistrettoPublicKey::from_hex(commitment);
    if c.is_err() {
        return false;
    }
    let factory = PedersenCommitmentFactory::default();
    let c = PedersenCommitment::from_public_key(&c.unwrap());
    factory.open_value(&k.unwrap(), value, &c)
}
