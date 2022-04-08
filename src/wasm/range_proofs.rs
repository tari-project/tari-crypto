// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Range proof proving and verification functions

use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::{
    range_proof::RangeProofService,
    ristretto::{
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        DalekRangeProofService,
        RistrettoSecretKey,
    },
    tari_utilities::hex::from_hex,
};

/// Generated from [RangeProofFactory::create_proof]
#[derive(Default, Serialize, Deserialize)]
pub struct RangeProofResult {
    proof: String,
    error: String,
}

/// Generated when calling [RangeProofFactory::verify]
#[derive(Default, Serialize, Deserialize)]
pub struct VerificationResult {
    valid: bool,
    error: String,
}

/// A factory to prove and verify range proofs
#[wasm_bindgen]
pub struct RangeProofFactory {
    rpf: DalekRangeProofService,
}

#[wasm_bindgen]
impl RangeProofFactory {
    /// Create a new `RangeProofFactory`
    pub fn new() -> Self {
        let cf = PedersenCommitmentFactory::default();
        let rpf = DalekRangeProofService::new(64, &cf).unwrap();
        RangeProofFactory { rpf }
    }

    /// Creates a new range proof for the given key-value pair. Returns a [JsValue] of a serialized
    /// [RangeProofResult]
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

    /// Verifies the given range proof and commitment. Returns a [JsValue] of a serialized [VerificationResult]
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

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{commitment::HomomorphicCommitmentFactory, keys::PublicKey, ristretto::RistrettoPublicKey};

    #[wasm_bindgen_test]
    fn it_fails_with_invalid_hex_input() {
        let factory = RangeProofFactory::new();
        let result = factory.create_proof("", 123).into_serde::<RangeProofResult>().unwrap();
        assert!(!result.error.is_empty());
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
