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

use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::{
    extended_range_proof::ExtendedRangeProofService,
    range_proof::RangeProofService,
    ristretto::{
        bulletproofs_plus::BulletproofsPlusService,
        dalek_range_proof::DalekRangeProofService,
        pedersen::{
            commitment_factory::PedersenCommitmentFactory,
            extended_commitment_factory::ExtendedPedersenCommitmentFactory,
            PedersenCommitment,
        },
        RistrettoSecretKey,
    },
    tari_utilities::hex::from_hex,
};

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

#[derive(Default, Serialize, Deserialize)]
pub struct RecoverResult {
    mask: String,
    error: String,
}

#[wasm_bindgen]
pub struct RangeProofFactory {
    rpf: DalekRangeProofService,
    //    cf: PedersenCommitmentFactory,
}

#[wasm_bindgen]
impl RangeProofFactory {
    /// Create a new `RangeProofFactory`
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
                result.error = format!("Range proof is invalid. {}", e);
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

#[wasm_bindgen]
pub struct ExtendedRangeProofFactory {
    rpf: BulletproofsPlusService,
}

#[wasm_bindgen]
impl ExtendedRangeProofFactory {
    /// Create a new `RangeProofFactory`
    pub fn new() -> Self {
        let cf = ExtendedPedersenCommitmentFactory::default();
        let rpf = BulletproofsPlusService::init(64, 1, cf).unwrap();
        ExtendedRangeProofFactory { rpf }
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
                result.error = format!("Range proof is invalid. {}", e);
                return JsValue::from_serde(&result).unwrap();
            },
        };
        result.valid = self.rpf.verify(&proof, &commitment);
        JsValue::from_serde(&result).unwrap()
    }

    pub fn construct_proof_with_recovery_seed_nonce(&self, mask: &str, value: u64, seed_nonce: &str) -> JsValue {
        let mut result = RangeProofResult::default();
        let mask = match RistrettoSecretKey::from_hex(mask) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid mask".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let seed_nonce = match RistrettoSecretKey::from_hex(seed_nonce) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid seed nonce".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        match self
            .rpf
            .construct_proof_with_recovery_seed_nonce(&mask, value, &seed_nonce)
        {
            Ok(p) => result.proof = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        JsValue::from_serde(&result).unwrap()
    }

    pub fn recover_mask(&self, proof: &str, commitment: &str, seed_nonce: &str) -> JsValue {
        let mut result = RecoverResult::default();
        let proof = match from_hex(proof) {
            Ok(v) => v,
            Err(e) => {
                result.error = format!("Range proof is invalid. {}", e);
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid commitment".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let seed_nonce = match RistrettoSecretKey::from_hex(seed_nonce) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid seed nonce".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        match self.rpf.recover_mask(&proof, &commitment, &seed_nonce) {
            Ok(p) => result.mask = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        JsValue::from_serde(&result).unwrap()
    }

    pub fn verify_mask(&self, commitment: &str, mask: &str, value: u64) -> JsValue {
        let mut result = VerificationResult::default();
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid commitment".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        let mask = match RistrettoSecretKey::from_hex(mask) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid mask".to_string();
                return JsValue::from_serde(&result).unwrap();
            },
        };
        match self.rpf.verify_mask(&commitment, &mask, value) {
            Ok(p) => result.valid = p,
            Err(e) => result.error = e.to_string(),
        };
        JsValue::from_serde(&result).unwrap()
    }
}

impl Default for ExtendedRangeProofFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{commitment::HomomorphicCommitmentFactory, keys::PublicKey, ristretto::RistrettoPublicKey};

    #[wasm_bindgen_test]
    fn dalek_range_proof_fails_with_invalid_hex_input() {
        let factory = RangeProofFactory::new();
        let result = factory.create_proof("", 123).into_serde::<RangeProofResult>().unwrap();
        assert!(!result.error.is_empty());
        assert!(result.proof.is_empty());
    }

    #[wasm_bindgen_test]
    fn dalek_range_proof_creates_a_valid_proof() {
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

    #[wasm_bindgen_test]
    fn bulletproof_plus_fails_with_invalid_hex_input() {
        let factory = ExtendedRangeProofFactory::new();
        let result = factory.create_proof("", 123).into_serde::<RangeProofResult>().unwrap();
        assert!(!result.error.is_empty());
        assert!(result.proof.is_empty());
    }

    #[wasm_bindgen_test]
    fn bulletproof_plus_creates_a_valid_proof() {
        let factory = ExtendedRangeProofFactory::new();
        let (sk, _) = RistrettoPublicKey::random_keypair(&mut OsRng);
        let value = 123;
        let commitment = ExtendedPedersenCommitmentFactory::default().commit_value(&sk, value);

        // Non-rewindable range proof
        let proof_result = factory
            .create_proof(&sk.to_hex(), value)
            .into_serde::<RangeProofResult>()
            .unwrap();
        let proof_verification_result = factory
            .verify(&commitment.to_hex(), &proof_result.proof)
            .into_serde::<VerificationResult>()
            .unwrap();
        assert!(proof_verification_result.valid);

        // Rewindable range proof
        // - Create
        let (seed_nonce, _) = RistrettoPublicKey::random_keypair(&mut OsRng);
        let proof_result = factory
            .construct_proof_with_recovery_seed_nonce(&sk.to_hex(), value, &seed_nonce.to_hex())
            .into_serde::<RangeProofResult>()
            .unwrap();
        assert!(factory.rpf.verify(&from_hex(&proof_result.proof).unwrap(), &commitment));
        // - Recover the blinding factor (mask)
        let recover_result = factory
            .recover_mask(&proof_result.proof, &commitment.to_hex(), &seed_nonce.to_hex())
            .into_serde::<RecoverResult>()
            .unwrap();
        let mask_verification_result = factory
            .verify_mask(&commitment.to_hex(), &recover_result.mask, value)
            .into_serde::<VerificationResult>()
            .unwrap();
        assert!(mask_verification_result.valid);

        // To print to `console.log`:
        // use crate::wasm::range_proofs::test::__rt::log;
        // log(&format_args!("blinding_factor: {}", &sk.to_hex()));
        // log(&format_args!("mask           : {}", &recover_result.mask));
    }
}
