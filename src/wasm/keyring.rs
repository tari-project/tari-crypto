// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::collections::HashMap;

use rand::rngs::OsRng;
use tari_utilities::hex::Hex;
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

/// KeyRing is an in-memory key-value store for secret keys. Each secret key has a user-defined id associated with it.
/// Additionally, it provides methods to sign and verify signatures using these stored keys.
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

#[cfg(test)]
mod test {
    use blake2::{digest::Output, Digest};
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{hash::blake2::Blake256, keys::SecretKey, ristretto::RistrettoSchnorr};

    const SAMPLE_CHALLENGE: &str = "გამარჯობა";

    fn new_keyring() -> KeyRing {
        let mut kr = KeyRing::new();
        kr.new_key("a".into());
        kr.new_key("b".into());
        kr
    }

    fn hash<T: AsRef<[u8]>>(preimage: T) -> Output<Blake256> {
        Blake256::digest(preimage.as_ref())
    }

    fn create_commitment(k: &RistrettoSecretKey, v: u64) -> PedersenCommitment {
        PedersenCommitmentFactory::default().commit_value(k, v)
    }

    impl KeyRing {
        fn expect_public_key(&self, id: &str) -> &RistrettoPublicKey {
            let (_, pk) = self.keys.get(id).unwrap();
            pk
        }

        fn expect_private_key(&self, id: &str) -> &RistrettoSecretKey {
            let (sk, _) = self.keys.get(id).unwrap();
            sk
        }
    }

    #[wasm_bindgen_test]
    fn it_has_an_empty_default() {
        let kr = KeyRing::default();
        assert!(kr.is_empty());
        assert_eq!(kr.len(), 0);
        assert!(kr.private_key("").is_none());
        assert!(kr.private_key("not here").is_none());
        assert!(kr.public_key("").is_none());
        assert!(kr.public_key("nor here").is_none());
    }

    mod new_key {
        use super::*;

        #[wasm_bindgen_test]
        fn it_adds_a_new_random_keypair() {
            let mut kr = KeyRing::new();
            assert!(kr.public_key("a").is_none());
            assert!(kr.public_key("b").is_none());

            assert_eq!(kr.new_key("a".into()), 1);
            assert_eq!(kr.new_key("b".into()), 2);
            assert_eq!(kr.len(), 2);

            let sk_a = kr.expect_private_key("a");
            let pk_a = kr.expect_public_key("a");
            assert_eq!(*pk_a, RistrettoPublicKey::from_secret_key(sk_a));

            let sk_b = kr.expect_private_key("b");
            assert_ne!(sk_a, sk_b);
        }
    }

    mod sign {
        use super::*;

        fn sign(kr: &KeyRing, id: &str) -> Result<RistrettoSchnorr, String> {
            let result = kr.sign(id, SAMPLE_CHALLENGE).into_serde::<SignResult>().unwrap();
            if !result.error.is_empty() {
                return Err(result.error);
            }
            let p_r = RistrettoPublicKey::from_hex(&result.public_nonce.unwrap()).unwrap();
            let s = RistrettoSecretKey::from_hex(&result.signature.unwrap()).unwrap();
            Ok(RistrettoSchnorr::new(p_r, s))
        }

        #[wasm_bindgen_test]
        fn it_fails_if_key_doesnt_exist() {
            let kr = new_keyring();
            sign(&kr, "doesn-exist").unwrap_err();
        }

        #[wasm_bindgen_test]
        fn it_produces_a_valid_signature() {
            let kr = new_keyring();
            let sig = sign(&kr, "a").unwrap();
            let pk = kr.expect_public_key("a");
            assert!(sig.verify_challenge(pk, &hash(SAMPLE_CHALLENGE)));
        }
    }

    mod opens {
        use super::*;

        #[wasm_bindgen_test]
        fn it_returns_false_if_key_doesnt_exist() {
            let kr = new_keyring();
            assert!(!kr.opens("doesnt-exist", 0, ""),);
            assert!(!kr.opens("doesnt-exist", u64::MAX, ""),);
            let c = create_commitment(kr.expect_private_key("a"), 0);
            assert!(!kr.opens("doesnt-exist", 0, &c.to_hex()),);
        }

        #[wasm_bindgen_test]
        fn it_returns_false_does_not_open_commitment() {
            let kr = new_keyring();
            let c = create_commitment(&RistrettoSecretKey::random(&mut OsRng), 123);
            assert!(!kr.opens("a", 123, &c.to_hex()),);

            let c = create_commitment(kr.expect_private_key("a"), 123);
            assert!(!kr.opens("a", 321, &c.to_hex()),);

            let c = create_commitment(kr.expect_private_key("a"), 123);
            assert!(!kr.opens("b", 123, &c.to_hex()),);
        }

        #[wasm_bindgen_test]
        fn it_returns_true_if_commitment_opened() {
            let kr = new_keyring();
            let c = create_commitment(kr.expect_private_key("a"), 123);
            assert!(kr.opens("a", 123, &c.to_hex()));
        }
    }

    mod commit {
        use super::*;

        fn commit(kr: &KeyRing, id: &str, value: u64) -> Result<PedersenCommitment, String> {
            let result = kr.commit(id, value).into_serde::<CommitmentResult>().unwrap();
            if !result.error.is_empty() {
                return Err(result.error);
            }
            Ok(PedersenCommitment::from_hex(&result.commitment.unwrap()).unwrap())
        }

        #[wasm_bindgen_test]
        fn it_fails_if_key_doesnt_exist() {
            let kr = new_keyring();
            commit(&kr, "doesnt-exist", 0).unwrap_err();
        }

        #[wasm_bindgen_test]
        fn it_produces_a_commitment_that_can_be_opened() {
            let kr = new_keyring();
            let c = commit(&kr, "a", 0).unwrap();
            assert!(kr.opens("a", 0, &c.to_hex()));
            let c = commit(&kr, "a", u64::MAX).unwrap();
            assert!(kr.opens("a", u64::MAX, &c.to_hex()));
        }

        #[wasm_bindgen_test]
        fn it_produces_a_valid_commitment() {
            let kr = new_keyring();
            let expected_commit = create_commitment(kr.expect_private_key("a"), 123);
            let c = commit(&kr, "a", 123).unwrap();
            assert_eq!(c, expected_commit);
        }
    }
}
