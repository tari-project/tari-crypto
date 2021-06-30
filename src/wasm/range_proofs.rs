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
    range_proof::RangeProofService,
    ristretto::{
        dalek_range_proof::DalekRangeProofService,
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        RistrettoSecretKey,
    },
    tari_utilities::hex::from_hex,
};
use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

#[derive(Default, Serialize, Deserialize)]
pub struct RangeProofResult {
    proof: String,
    error: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct VerificationResult {
    valid: bool,
    error: String,
}

#[wasm_bindgen]
pub struct RangeProofFactory {
    rpf: DalekRangeProofService,
    //    cf: PedersenCommitmentFactory,
}

#[wasm_bindgen]
impl RangeProofFactory {
    pub fn new() -> Self {
        let cf = PedersenCommitmentFactory::default();
        let rpf = DalekRangeProofService::new(64, &cf).unwrap();
        RangeProofFactory { rpf }
    }

    /// Creates a new range proof for the given key-value pair.
    pub fn create_proof(&self, key: &str, value: u64) -> JsValue {
        let mut result = RangeProofResult::default();
        let key = match RistrettoSecretKey::from_hex(key) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid private key".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        match self.rpf.construct_proof(&key, value) {
            Ok(p) => result.proof = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        JsValue::from_serde(&result).unwrap()
    }

    /// Verifies the given range proof and commitment.
    pub fn verify(&self, commitment: &str, proof: &str) -> JsValue {
        let mut result = VerificationResult::default();
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid private key".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let proof = match from_hex(proof) {
            Ok(v) => v,
            Err(e) => {
                result.error = format!("Range proof is invalid. {}", e.to_string());
                return JsValue::from_serde(&result).unwrap();
            },
        };
        result.valid = self.rpf.verify(&proof, &commitment);
        JsValue::from_serde(&result).unwrap()
    }
}

impl Default for RangeProofFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{commitment::HomomorphicCommitmentFactory, keys::PublicKey, ristretto::RistrettoPublicKey};
    use rand::rngs::OsRng;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn it_fails_with_invalid_hex_input() {
        let factory = RangeProofFactory::new();
        let result = factory.create_proof("", 123).into_serde::<RangeProofResult>().unwrap();
        assert_eq!(result.error.is_empty(), false);
        assert!(result.proof.is_empty());
    }

    #[wasm_bindgen_test]
    fn it_creates_a_valid_proof() {
        let factory = RangeProofFactory::new();
        let (sk, _) = RistrettoPublicKey::random_keypair(&mut OsRng);
        let result = factory
            .create_proof(&sk.to_hex(), 123)
            .into_serde::<RangeProofResult>()
            .unwrap();
        let commitment = PedersenCommitmentFactory::default().commit_value(&sk, 123);
        assert!(factory.rpf.verify(&from_hex(&result.proof).unwrap(), &commitment));
        let result = factory
            .verify(&commitment.to_hex(), &result.proof)
            .into_serde::<VerificationResult>()
            .unwrap();
        assert!(result.valid);
    }
}
