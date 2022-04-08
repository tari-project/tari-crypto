// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Functions for creating and opening commitments

use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::{
    commitment::HomomorphicCommitmentFactory,
    ristretto::{
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

/// Returned from [commit()]
#[derive(Default, Serialize, Deserialize)]
pub struct CommitmentResult {
    /// The commitment, if successful
    pub commitment: Option<String>,
    /// The error if the commitment could not be created, otherwise empty
    pub error: String,
}

/// Commits a value and blinding factor (private key) using a Pedersen commitment. Returns a
/// [JsValue] containing a serialized [CommitmentResult]
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

/// Commits two private keys into a Pedersen commitment.
#[wasm_bindgen]
pub fn commit_private_keys(key_1: &str, key_2: &str) -> JsValue {
    let mut result = CommitmentResult::default();
    let factory = PedersenCommitmentFactory::default();
    let k_1 = match RistrettoSecretKey::from_hex(key_1) {
        Ok(k) => k,
        _ => {
            result.error = format!("Private key for '{}' does not exist", key_1);
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let k_2 = match RistrettoSecretKey::from_hex(key_2) {
        Ok(k) => k,
        _ => {
            result.error = format!("Private key for '{}' does not exist", key_2);
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let commitment = factory.commit(&k_1, &k_2);
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

#[cfg(test)]
mod test {
    use rand::rngs::OsRng;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::keys::SecretKey;

    mod commit {
        use super::*;

        #[wasm_bindgen_test]
        fn it_fails_for_invalid_key() {
            let val = commit("aa", 123).into_serde::<CommitmentResult>().unwrap();
            assert!(!val.error.is_empty());
            assert!(val.commitment.is_none());
        }

        #[wasm_bindgen_test]
        fn it_produces_a_commitment_with_given_key() {
            let key = RistrettoSecretKey::random(&mut OsRng);
            let expected_commit = PedersenCommitmentFactory::default().commit_value(&key, 123);
            let commitment = commit(&key.to_hex(), 123).into_serde::<CommitmentResult>().unwrap();
            assert!(commitment.error.is_empty());
            assert_eq!(commitment.commitment, Some(expected_commit.to_hex()))
        }
    }

    mod commit_private_keys {
        use super::*;

        #[wasm_bindgen_test]
        fn it_fails_for_empty_input() {
            let val = commit_private_keys("", "").into_serde::<CommitmentResult>().unwrap();
            assert!(!val.error.is_empty());
            assert!(val.commitment.is_none());
        }

        #[wasm_bindgen_test]
        fn it_produces_a_commitment_with_given_keys() {
            let key1 = RistrettoSecretKey::random(&mut OsRng);
            let key2 = RistrettoSecretKey::random(&mut OsRng);
            let commitment = commit_private_keys(&key1.to_hex(), &key2.to_hex())
                .into_serde::<CommitmentResult>()
                .unwrap();
            let expected_commit = PedersenCommitmentFactory::default().commit(&key1, &key2);
            assert!(commitment.error.is_empty());
            assert_eq!(commitment.commitment, Some(expected_commit.to_hex()))
        }
    }

    mod opens {
        use super::*;

        #[wasm_bindgen_test]
        fn it_returns_false_for_zero_length_input() {
            assert!(!opens("", 123, ""));
        }

        #[wasm_bindgen_test]
        fn it_returns_true_if_key_value_opens_commitment() {
            let key = RistrettoSecretKey::random(&mut OsRng);
            let commitment = PedersenCommitmentFactory::default().commit_value(&key, 123);
            assert!(opens(&key.to_hex(), 123, &commitment.to_hex()));
        }
    }
}
