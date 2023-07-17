// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Range proof proving and verification functions

use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::{
    extended_range_proof::ExtendedRangeProofService,
    range_proof::RangeProofService,
    ristretto::{
        bulletproofs_plus::BulletproofsPlusService,
        pedersen::{extended_commitment_factory::ExtendedPedersenCommitmentFactory, PedersenCommitment},
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

/// Generated from [RangeProofFactory::create_proof]
#[derive(Default, Serialize, Deserialize)]
pub struct RecoverResult {
    mask: String,
    error: String,
}

/// A factory to prove and verify extended range proofs
#[wasm_bindgen]
pub struct ExtendedRangeProofFactory {
    range_proof_service: BulletproofsPlusService,
}

#[wasm_bindgen]
impl ExtendedRangeProofFactory {
    /// Create a new `RangeProofFactory`
    pub fn new() -> Self {
        let factory = ExtendedPedersenCommitmentFactory::default();
        let range_proof_service = BulletproofsPlusService::init(64, 1, factory).unwrap();
        ExtendedRangeProofFactory { range_proof_service }
    }

    /// Creates a new range proof for the given key-value pair.
    pub fn create_proof(&self, key: &str, value: u64) -> JsValue {
        let mut result = RangeProofResult::default();
        let key = match RistrettoSecretKey::from_hex(key) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid private key".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        match self.range_proof_service.construct_proof(&key, value) {
            Ok(p) => result.proof = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// Verifies the given range proof and commitment.
    pub fn verify(&self, commitment: &str, proof: &str) -> JsValue {
        let mut result = VerificationResult::default();
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid private key".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        let proof = match from_hex(proof) {
            Ok(v) => v,
            Err(e) => {
                result.error = format!("Range proof is invalid. {e}");
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        result.valid = self.range_proof_service.verify(&proof, &commitment);
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// Construct a proof with a recovery seed nonce
    pub fn construct_proof_with_recovery_seed_nonce(&self, mask: &str, value: u64, seed_nonce: &str) -> JsValue {
        let mut result = RangeProofResult::default();
        let mask = match RistrettoSecretKey::from_hex(mask) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid mask".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        let seed_nonce = match RistrettoSecretKey::from_hex(seed_nonce) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid seed nonce".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        match self
            .range_proof_service
            .construct_proof_with_recovery_seed_nonce(&mask, value, &seed_nonce)
        {
            Ok(p) => result.proof = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// Recover a mask from a proof
    pub fn recover_mask(&self, proof: &str, commitment: &str, seed_nonce: &str) -> JsValue {
        let mut result = RecoverResult::default();
        let proof = match from_hex(proof) {
            Ok(v) => v,
            Err(e) => {
                result.error = format!("Range proof is invalid. {e}");
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid commitment".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        let seed_nonce = match RistrettoSecretKey::from_hex(seed_nonce) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid seed nonce".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        match self.range_proof_service.recover_mask(&proof, &commitment, &seed_nonce) {
            Ok(p) => result.mask = p.to_hex(),
            Err(e) => result.error = e.to_string(),
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    /// Verify that a mask and value is the one used in a proof
    pub fn verify_mask(&self, commitment: &str, mask: &str, value: u64) -> JsValue {
        let mut result = VerificationResult::default();
        let commitment = match PedersenCommitment::from_hex(commitment) {
            Ok(commitment) => commitment,
            _ => {
                result.error = "Invalid commitment".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        let mask = match RistrettoSecretKey::from_hex(mask) {
            Ok(k) => k,
            _ => {
                result.error = "Invalid mask".to_string();
                return serde_wasm_bindgen::to_value(&result).unwrap();
            },
        };
        match self.range_proof_service.verify_mask(&commitment, &mask, value) {
            Ok(p) => result.valid = p,
            Err(e) => result.error = e.to_string(),
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
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
    fn bulletproof_plus_fails_with_invalid_hex_input() {
        let factory = ExtendedRangeProofFactory::new();
        let result: RangeProofResult = serde_wasm_bindgen::from_value(factory.create_proof("", 123)).unwrap();
        assert!(!result.error.is_empty());
        assert!(result.proof.is_empty());
    }

    #[wasm_bindgen_test]
    fn bulletproof_plus_creates_a_valid_proof() {
        let factory = ExtendedRangeProofFactory::new();
        let (blinding_factor, _) = RistrettoPublicKey::random_keypair(&mut OsRng);
        let value = 123;
        let commitment = ExtendedPedersenCommitmentFactory::default().commit_value(&blinding_factor, value);

        // Non-rewindable range proof
        let proof_result: RangeProofResult =
            serde_wasm_bindgen::from_value(factory.create_proof(&blinding_factor.to_hex(), value)).unwrap();
        let proof_verification_result: VerificationResult =
            serde_wasm_bindgen::from_value(factory.verify(&commitment.to_hex(), &proof_result.proof)).unwrap();
        assert!(proof_verification_result.valid);

        // Rewindable range proof
        // - Create
        let (seed_nonce, _) = RistrettoPublicKey::random_keypair(&mut OsRng);
        let proof_result: RangeProofResult = serde_wasm_bindgen::from_value(
            factory.construct_proof_with_recovery_seed_nonce(&blinding_factor.to_hex(), value, &seed_nonce.to_hex()),
        )
        .unwrap();
        assert!(factory
            .range_proof_service
            .verify(&from_hex(&proof_result.proof).unwrap(), &commitment));
        // - Recover the blinding factor (mask)
        let recover_result: RecoverResult = serde_wasm_bindgen::from_value(factory.recover_mask(
            &proof_result.proof,
            &commitment.to_hex(),
            &seed_nonce.to_hex(),
        ))
        .unwrap();
        let mask_verification_result: VerificationResult =
            serde_wasm_bindgen::from_value(factory.verify_mask(&commitment.to_hex(), &recover_result.mask, value))
                .unwrap();
        assert!(mask_verification_result.valid);

        // To print to `console.log`:
        // use crate::wasm::range_proofs::test::__rt::log;
        // log(&format_args!("blinding_factor: {}", &blinding_factor.to_hex()));
        // log(&format_args!("mask           : {}", &recover_result.mask));
    }
}
