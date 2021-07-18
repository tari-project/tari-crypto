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

//! Simple cryptographic key functions. It's generally not very efficient to use these functions to do lots of cool
//! stuff with private and public keys, because the keys are translated to- and from hex every time you make a call
//! using a function from this module. You should use a [KeyRing] instead. But sometimes, these functions are handy.

use crate::{
    common::Blake256,
    keys::{PublicKey, SecretKey},
    ristretto::{
        pedersen::{PedersenCommitment, PedersenCommitmentFactory},
        RistrettoComSig,
        RistrettoPublicKey,
        RistrettoSchnorr,
        RistrettoSecretKey,
    },
};
use blake2::Digest;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tari_utilities::hex::{from_hex, Hex};
use wasm_bindgen::prelude::*;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SignatureVerifyResult {
    pub result: bool,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SignResult {
    pub public_nonce: Option<String>,
    pub signature: Option<String>,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ComSignResult {
    pub public_nonce: Option<String>,
    pub u: Option<String>,
    pub v: Option<String>,
    pub error: String,
}

/// Create an return a new private- public key pair
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let (k, p) = RistrettoPublicKey::random_keypair(&mut OsRng);
    let pair = (k.to_hex(), p.to_hex());
    JsValue::from_serde(&pair).unwrap()
}

/// Returns a public key object from a public key hex string, or false if the hex string does not represent a valid
/// public key
#[wasm_bindgen]
pub fn pubkey_from_hex(hex: &str) -> JsValue {
    match RistrettoPublicKey::from_hex(hex) {
        Ok(pk) => JsValue::from_serde(&pk).unwrap_or_else(|_| JsValue::from_bool(false)),
        Err(_) => JsValue::from_bool(false),
    }
}

/// Calculate the public key associated with a private key. If the input is not a valid hex string representing a
/// private key, `None` is returned
#[wasm_bindgen]
pub fn pubkey_from_secret(k: &str) -> Option<String> {
    match RistrettoSecretKey::from_hex(k) {
        Ok(k) => Some(RistrettoPublicKey::from_secret_key(&k).to_hex()),
        _ => None,
    }
}

/// Generate a Schnorr signature of the message using the given private key
#[wasm_bindgen]
pub fn sign(private_key: &str, msg: &str) -> JsValue {
    let mut result = SignResult::default();
    let k = match RistrettoSecretKey::from_hex(private_key) {
        Ok(k) => k,
        _ => {
            result.error = "Invalid private key".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    sign_message_with_key(&k, msg, None, &mut result);
    JsValue::from_serde(&result).unwrap()
}

/// Generate a Schnorr signature of a challenge (that has already been hashed) using the given private
/// key and a specified private nonce. DO NOT reuse nonces. This method is provide for cases where a
/// public nonce has been used in the message.
#[wasm_bindgen]
pub fn sign_challenge_with_nonce(private_key: &str, private_nonce: &str, challenge_as_hex: &str) -> JsValue {
    let mut result = SignResult::default();
    let k = match RistrettoSecretKey::from_hex(private_key) {
        Ok(k) => k,
        _ => {
            result.error = "Invalid private key".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let r = match RistrettoSecretKey::from_hex(private_nonce) {
        Ok(r) => r,
        _ => {
            result.error = "Invalid private nonce".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let e = match from_hex(challenge_as_hex) {
        Ok(e) => e,
        _ => {
            result.error = "Challenge was not valid HEX".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    sign_with_key(&k, &e, Some(&r), &mut result);
    JsValue::from_serde(&result).unwrap()
}

pub(super) fn sign_message_with_key(
    k: &RistrettoSecretKey,
    msg: &str,
    r: Option<&RistrettoSecretKey>,
    result: &mut SignResult,
) {
    let e = Blake256::digest(msg.as_bytes());
    sign_with_key(k, e.as_slice(), r, result)
}

#[allow(non_snake_case)]
pub(super) fn sign_with_key(k: &RistrettoSecretKey, e: &[u8], r: Option<&RistrettoSecretKey>, result: &mut SignResult) {
    let (r, R) = match r {
        Some(r) => (r.clone(), RistrettoPublicKey::from_secret_key(r)),
        None => RistrettoPublicKey::random_keypair(&mut OsRng),
    };

    let sig = match RistrettoSchnorr::sign(k.clone(), r, e) {
        Ok(s) => s,
        Err(e) => {
            result.error = format!("Could not create signature. {}", e.to_string());
            return;
        },
    };
    result.public_nonce = Some(R.to_hex());
    result.signature = Some(sig.get_signature().to_hex());
}

/// Checks the validity of a Schnorr signature
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn check_signature(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) -> JsValue {
    let mut result = SignatureVerifyResult::default();

    let R = match RistrettoPublicKey::from_hex(pub_nonce) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{} is not a valid public nonce", pub_nonce);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let P = match RistrettoPublicKey::from_hex(pub_key) {
        Ok(p) => p,
        Err(_) => {
            result.error = format!("{} is not a valid public key", pub_key);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let s = match RistrettoSecretKey::from_hex(signature) {
        Ok(s) => s,
        Err(_) => {
            result.error = format!("{} is not a valid hex representation of a signature", signature);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let sig = RistrettoSchnorr::new(R, s);
    let msg = Blake256::digest(msg.as_bytes());
    result.result = sig.verify_challenge(&P, msg.as_slice());
    JsValue::from_serde(&result).unwrap()
}

/// Generate a Commitment signature of the message using the given private key
#[wasm_bindgen]
pub fn sign_comsig(private_key_a: &str, private_key_x: &str, msg: &str) -> JsValue {
    let mut result = ComSignResult::default();
    let a_key = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(a_key) => a_key,
        _ => {
            result.error = "Invalid private key".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let x_key = match RistrettoSecretKey::from_hex(private_key_x) {
        Ok(x_key) => x_key,
        _ => {
            result.error = "Invalid private key".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    sign_comsig_message_with_key(&a_key, &x_key, msg, None, None, &mut result);
    JsValue::from_serde(&result).unwrap()
}

/// Generate a Schnorr signature of a challenge (that has already been hashed) using the given private
/// key and a specified private nonce. DO NOT reuse nonces. This method is provide for cases where a
/// public nonce has been used
/// in the message.
#[wasm_bindgen]
pub fn sign_comsig_challenge_with_nonce(
    private_key_a: &str,
    private_key_x: &str,
    private_nonce_1: &str,
    private_nonce_2: &str,
    challenge_as_hex: &str,
) -> JsValue {
    let mut result = ComSignResult::default();
    let private_key_a = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(private_key_a) => private_key_a,
        _ => {
            result.error = "Invalid private key_a".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let private_key_x = match RistrettoSecretKey::from_hex(private_key_x) {
        Ok(private_key_x) => private_key_x,
        _ => {
            result.error = "Invalid private key_x".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let private_nonce_1 = match RistrettoSecretKey::from_hex(private_nonce_1) {
        Ok(private_nonce_1) => private_nonce_1,
        _ => {
            result.error = "Invalid private nonce_1".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let private_nonce_2 = match RistrettoSecretKey::from_hex(private_nonce_2) {
        Ok(private_nonce_2) => private_nonce_2,
        _ => {
            result.error = "Invalid private nonce_2".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let e = match from_hex(challenge_as_hex) {
        Ok(e) => e,
        _ => {
            result.error = "Challenge was not valid HEX".to_string();
            return JsValue::from_serde(&result).unwrap();
        },
    };
    sign_comsig_with_key(
        &private_key_a,
        &private_key_x,
        &e,
        Some(&private_nonce_1),
        Some(&private_nonce_2),
        &mut result,
    );
    JsValue::from_serde(&result).unwrap()
}

pub(crate) fn sign_comsig_message_with_key(
    private_key_a: &RistrettoSecretKey,
    private_key_x: &RistrettoSecretKey,
    msg: &str,
    nonce_1: Option<&RistrettoSecretKey>,
    nonce_2: Option<&RistrettoSecretKey>,
    result: &mut ComSignResult,
) {
    let e = Blake256::digest(msg.as_bytes());
    sign_comsig_with_key(private_key_a, private_key_x, e.as_slice(), nonce_1, nonce_2, result);
}

pub(crate) fn sign_comsig_with_key(
    private_key_a: &RistrettoSecretKey,
    private_key_x: &RistrettoSecretKey,
    e: &[u8],
    nonce_1: Option<&RistrettoSecretKey>,
    nonce_2: Option<&RistrettoSecretKey>,
    result: &mut ComSignResult,
) {
    let factory = PedersenCommitmentFactory::default();
    let r_1 = match nonce_1 {
        Some(v) => v.clone(),
        None => RistrettoSecretKey::random(&mut OsRng),
    };
    let r_2 = match nonce_2 {
        Some(v) => v.clone(),
        None => RistrettoSecretKey::random(&mut OsRng),
    };

    let sig = match RistrettoComSig::sign(private_key_a.clone(), private_key_x.clone(), r_2, r_1, e, &factory) {
        Ok(s) => s,
        Err(e) => {
            result.error = format!("Could not create signature. {}", e.to_string());
            return;
        },
    };
    let (public_nonce_commitment, u, v) = sig.complete_signature_tuple();
    result.public_nonce = Some(public_nonce_commitment.to_hex());
    result.u = Some(u.to_hex());
    result.v = Some(v.to_hex());
}

/// Checks the validity of a Schnorr signature
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn check_comsig_signature(
    pub_nonce_commitment: &str,
    signature_u: &str,
    signature_v: &str,
    commitment: &str,
    msg: &str,
) -> JsValue {
    let mut result = SignatureVerifyResult::default();

    let R = match PedersenCommitment::from_hex(pub_nonce_commitment) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{} is not a valid public nonce", pub_nonce_commitment);
            return JsValue::from_serde(&result).unwrap();
        },
    };
    let factory = PedersenCommitmentFactory::default();

    let public_commitment = match PedersenCommitment::from_hex(commitment) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{} is not a valid commitment", commitment);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let u = match RistrettoSecretKey::from_hex(signature_u) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{} is not a valid hex representation of a signature", signature_u);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let v = match RistrettoSecretKey::from_hex(signature_v) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{} is not a valid hex representation of a signature", signature_v);
            return JsValue::from_serde(&result).unwrap();
        },
    };

    let sig = RistrettoComSig::new(R, u, v);
    let msg = Blake256::digest(msg.as_bytes());
    result.result = sig.verify_challenge(&public_commitment, msg.as_slice(), &factory);
    JsValue::from_serde(&result).unwrap()
}

/// Create a secret key modulo the Ristretto prime group order using the given little-endian byte array represented as a
/// hex string. If the hex string does not represent 32 bytes the function will return false
#[wasm_bindgen]
pub fn secret_key_from_hex_bytes(private_key_hex: &str) -> JsValue {
    match RistrettoSecretKey::from_hex(private_key_hex) {
        Ok(sk) => JsValue::from_serde(&sk).unwrap_or_else(|_| JsValue::from_bool(false)),
        Err(_) => JsValue::from_bool(false),
    }
}

/// A function that accepts two private keys and adds them together and returns the result. Will return false if
/// either key is invalid
#[wasm_bindgen]
pub fn add_secret_keys(private_key_a: &str, private_key_b: &str) -> JsValue {
    let k_a = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let k_b = match RistrettoSecretKey::from_hex(private_key_b) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let result_key = k_a + k_b;
    JsValue::from_serde(&result_key).unwrap()
}

/// A function that accepts two private keys and subtracts the second from the first. Will return false if
/// either key is invalid
#[wasm_bindgen]
pub fn subtract_secret_keys(private_key_a: &str, private_key_b: &str) -> JsValue {
    let k_a = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let k_b = match RistrettoSecretKey::from_hex(private_key_b) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let result_key = k_a - k_b;
    JsValue::from_serde(&result_key).unwrap()
}

/// A function that accepts two private keys and multiplies them together and returns the result. Will return false if
/// either key is invalid
#[wasm_bindgen]
pub fn multiply_secret_keys(private_key_a: &str, private_key_b: &str) -> JsValue {
    let k_a = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let k_b = match RistrettoSecretKey::from_hex(private_key_b) {
        Ok(k) => k,
        _ => return JsValue::from_bool(false),
    };

    let result_key = k_a * k_b;
    JsValue::from_serde(&result_key).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        commitment::HomomorphicCommitmentFactory,
        signatures::{CommitmentSignature, SchnorrSignature},
        tari_utilities::{hex, ByteArray},
    };
    use blake2::digest::Output;
    use wasm_bindgen_test::*;

    const SAMPLE_CHALLENGE: &str =
        "Cormac was completely aware that he was being manipulated, but how he could not see.";

    fn hash<T: AsRef<[u8]>>(preimage: T) -> Output<Blake256> {
        Blake256::digest(preimage.as_ref())
    }

    fn hash_hex<T: AsRef<[u8]>>(preimage: T) -> String {
        hex::to_hex(&hash(preimage))
    }

    fn random_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
        RistrettoPublicKey::random_keypair(&mut OsRng)
    }

    fn create_signature(msg: &str) -> (RistrettoSchnorr, RistrettoPublicKey, RistrettoSecretKey) {
        let (sk, pk) = random_keypair();
        let (nonce, _) = random_keypair();
        let sig = SchnorrSignature::sign(sk.clone(), nonce, &hash(msg)).unwrap();

        (sig, pk, sk)
    }

    fn create_commsig(msg: &str) -> (RistrettoComSig, PedersenCommitment) {
        let factory = PedersenCommitmentFactory::default();
        let (sk_a, _) = random_keypair();
        let (sk_x, _) = random_keypair();
        let (nonce_a, _) = random_keypair();
        let (nonce_x, _) = random_keypair();
        let sig = CommitmentSignature::<RistrettoPublicKey, _>::sign(
            sk_a.clone(),
            sk_x.clone(),
            nonce_a,
            nonce_x,
            &hash(msg),
            &factory,
        )
        .unwrap();
        let commitment = factory.commit(&sk_x, &sk_a);

        (sig, commitment)
    }

    fn key_hex() -> (RistrettoSecretKey, String) {
        let key = RistrettoSecretKey::random(&mut OsRng);
        let key_hex = key.to_hex();
        (key, key_hex)
    }

    #[wasm_bindgen_test]
    fn it_generates_a_keypair() {
        let (k, p) = generate_keypair().into_serde::<(String, String)>().unwrap();
        let sk = RistrettoSecretKey::from_hex(&k).unwrap();
        let derived_pk = RistrettoPublicKey::from_secret_key(&sk);
        let pk = RistrettoPublicKey::from_hex(&p).unwrap();
        assert_eq!(derived_pk, pk);
    }

    mod pubkey_from_hex {
        use super::*;

        #[wasm_bindgen_test]
        fn it_returns_false_if_invalid() {
            assert!(!pubkey_from_hex("").as_bool().unwrap());
            assert!(
                !pubkey_from_hex("123456789012345678901234567890ab123456789012345678901234567890ab")
                    .as_bool()
                    .unwrap()
            );
        }
    }

    mod pubkey_from_secret {
        use super::*;

        #[wasm_bindgen_test]
        fn it_returns_none_if_invalid() {
            assert!(pubkey_from_secret("").is_none());
            assert!(pubkey_from_secret("123456789012345678901234567890ab").is_none());
            assert!(pubkey_from_secret("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
        }

        #[wasm_bindgen_test]
        fn it_returns_public_key_from_secret() {
            let key = RistrettoSecretKey::random(&mut OsRng);
            let expected_pk = RistrettoPublicKey::from_secret_key(&key);
            let pk = RistrettoPublicKey::from_hex(&pubkey_from_secret(&key.to_hex()).unwrap()).unwrap();
            assert_eq!(pk, expected_pk);
        }
    }

    mod sign {
        use super::*;

        fn sign(private_key: &str, msg: &str) -> SignResult {
            super::sign(private_key, msg).into_serde().unwrap()
        }

        #[wasm_bindgen_test]
        fn it_returns_error_if_invalid() {
            assert_eq!(sign("", SAMPLE_CHALLENGE).error.is_empty(), false);
            assert!(!sign(&["0"; 32].join(""), SAMPLE_CHALLENGE).error.is_empty());
        }

        #[wasm_bindgen_test]
        fn it_returns_a_valid_signature() {
            let (sk, pk) = random_keypair();
            let result = sign(&sk.to_hex(), SAMPLE_CHALLENGE);
            assert!(result.error.is_empty());
            let p_nonce = RistrettoPublicKey::from_hex(&result.public_nonce.unwrap()).unwrap();
            let s = RistrettoSecretKey::from_hex(&result.signature.unwrap()).unwrap();
            assert!(SchnorrSignature::new(p_nonce, s).verify_challenge(&pk, &hash(SAMPLE_CHALLENGE)));
        }

        #[wasm_bindgen_test]
        fn it_does_not_reuse_the_nonce() {
            let (sk, _) = random_keypair();
            let result = sign(&sk.to_hex(), SAMPLE_CHALLENGE);
            let p_nonce1 = RistrettoPublicKey::from_hex(&result.public_nonce.unwrap()).unwrap();
            let result = sign(&sk.to_hex(), SAMPLE_CHALLENGE);
            let p_nonce2 = RistrettoPublicKey::from_hex(&result.public_nonce.unwrap()).unwrap();
            assert_ne!(p_nonce1, p_nonce2);
        }
    }

    mod sign_challenge_with_nonce {
        use super::*;

        fn sign_challenge_with_nonce(private_key: &str, private_nonce: &str, msg: &str) -> SignResult {
            super::sign_challenge_with_nonce(private_key, private_nonce, msg)
                .into_serde()
                .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_returns_error_if_invalid() {
            let (_, key) = key_hex();
            assert_eq!(
                sign_challenge_with_nonce(&key, "", &hash_hex(SAMPLE_CHALLENGE))
                    .error
                    .is_empty(),
                false
            );
            assert_eq!(
                sign_challenge_with_nonce(&["0"; 33].join(""), &key, &hash_hex(SAMPLE_CHALLENGE))
                    .error
                    .is_empty(),
                false
            );
        }

        #[wasm_bindgen_test]
        fn it_returns_error_if_challenge_not_hashed() {
            let (_, r) = key_hex();
            let (_, sk) = key_hex();
            let result = sign_challenge_with_nonce(&sk, &r, &hex::to_hex(SAMPLE_CHALLENGE.as_bytes()));
            assert!(result.error.contains("An invalid challenge was provided"));
        }

        #[wasm_bindgen_test]
        fn it_returns_a_valid_signature() {
            let (r, expected_pr) = random_keypair();
            let (sk, pk) = random_keypair();
            let e = hash(SAMPLE_CHALLENGE);
            let result = sign_challenge_with_nonce(&sk.to_hex(), &r.to_hex(), &hex::to_hex(&e));
            assert_eq!(result.error, "");
            let p_nonce = RistrettoPublicKey::from_hex(&result.public_nonce.unwrap()).unwrap();
            assert_eq!(p_nonce, expected_pr);
            let s = RistrettoSecretKey::from_hex(&result.signature.unwrap()).unwrap();
            assert!(SchnorrSignature::new(p_nonce, s).verify_challenge(&pk, &hash(SAMPLE_CHALLENGE)));
        }
    }

    mod check_signature {
        use super::*;

        fn check_signature(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) -> SignatureVerifyResult {
            super::check_signature(pub_nonce, signature, pub_key, msg)
                .into_serde()
                .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_errors_given_invalid_data() {
            fn it_errors(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) {
                let result = check_signature(pub_nonce, signature, pub_key, msg);
                assert_eq!(
                    result.error.is_empty(),
                    false,
                    "check_signature did not fail with args ({}, {}, {}, {})",
                    pub_nonce,
                    signature,
                    pub_key,
                    msg
                );
                assert_eq!(result.result, false);
            }

            it_errors("", "", "", SAMPLE_CHALLENGE);

            let (sig, pk, _) = create_signature(SAMPLE_CHALLENGE);
            it_errors(&sig.get_public_nonce().to_hex(), &"", &pk.to_hex(), SAMPLE_CHALLENGE);
        }

        #[wasm_bindgen_test]
        fn it_fails_if_verification_is_invalid() {
            fn it_fails(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) {
                let result = check_signature(pub_nonce, signature, pub_key, msg);
                assert_eq!(result.error.is_empty(), true,);
                assert_eq!(result.result, false);
            }

            let (sig, pk, _) = create_signature(SAMPLE_CHALLENGE);
            it_fails(
                &RistrettoPublicKey::default().to_hex(),
                &sig.get_signature().to_hex(),
                &pk.to_hex(),
                SAMPLE_CHALLENGE,
            );
            it_fails(
                &sig.get_public_nonce().to_hex(),
                &sig.get_signature().to_hex(),
                &pk.to_hex(),
                "wrong challenge",
            );
            it_fails(
                &sig.get_public_nonce().to_hex(),
                &sig.get_signature().to_hex(),
                &RistrettoPublicKey::default().to_hex(),
                SAMPLE_CHALLENGE,
            );
        }

        #[wasm_bindgen_test]
        fn it_succeeds_given_valid_data() {
            let (sig, pk, _) = create_signature(SAMPLE_CHALLENGE);
            let result = check_signature(
                &sig.get_public_nonce().to_hex(),
                &sig.get_signature().to_hex(),
                &pk.to_hex(),
                SAMPLE_CHALLENGE,
            );
            assert!(result.error.is_empty());
            assert!(result.result);
        }
    }

    mod sign_comsig {
        use super::*;

        fn sign_comsig(private_key_a: &str, private_key_x: &str, msg: &str) -> ComSignResult {
            super::sign_comsig(private_key_a, private_key_x, msg)
                .into_serde()
                .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, msg: &str) {
                let result = sign_comsig(a, x, msg);
                assert_eq!(result.error.is_empty(), false);
                assert_eq!(result.public_nonce.is_some(), false);
                assert_eq!(result.v.is_some(), false);
                assert_eq!(result.u.is_some(), false);
            }

            let (sk, _) = random_keypair();
            it_fails("", "", SAMPLE_CHALLENGE);
            it_fails(&["0"; 33].join(""), &sk.to_hex(), SAMPLE_CHALLENGE);
            it_fails(&sk.to_hex(), &["0"; 33].join(""), SAMPLE_CHALLENGE);
        }

        #[wasm_bindgen_test]
        fn it_produces_a_valid_commitment_signature() {
            let (x, _) = random_keypair();
            let a = RistrettoSecretKey::from(123);
            let commitment = PedersenCommitmentFactory::default().commit(&x, &a);

            let result = sign_comsig(&a.to_hex(), &x.to_hex(), SAMPLE_CHALLENGE);
            assert!(result.error.is_empty());
            let u = RistrettoSecretKey::from_hex(&result.u.unwrap()).unwrap();
            let v = RistrettoSecretKey::from_hex(&result.v.unwrap()).unwrap();
            let public_nonce_commit = PedersenCommitment::from_hex(&result.public_nonce.unwrap()).unwrap();
            let comsig = CommitmentSignature::new(public_nonce_commit, u, v);
            assert!(comsig.verify(
                &commitment,
                &RistrettoSecretKey::from_bytes(&hash(SAMPLE_CHALLENGE)).unwrap(),
                &PedersenCommitmentFactory::default()
            ));
        }

        #[wasm_bindgen_test]
        fn it_does_not_reuse_nonces() {
            let (x, _) = random_keypair();
            let (a, _) = random_keypair();
            let result1 = sign_comsig(&a.to_hex(), &x.to_hex(), SAMPLE_CHALLENGE);
            let result2 = sign_comsig(&a.to_hex(), &x.to_hex(), SAMPLE_CHALLENGE);
            assert_ne!(result1.u.unwrap(), result2.u.unwrap());
            assert_ne!(result1.v.unwrap(), result2.v.unwrap());
            assert_ne!(result1.public_nonce.unwrap(), result2.public_nonce.unwrap());
        }
    }

    mod sign_comsig_challenge_with_nonce {
        use super::*;

        fn sign_comsig_challenge_with_nonce(
            private_key_a: &str,
            private_key_x: &str,
            private_nonce_1: &str,
            private_nonce_2: &str,
        ) -> ComSignResult {
            super::sign_comsig_challenge_with_nonce(
                private_key_a,
                private_key_x,
                private_nonce_1,
                private_nonce_2,
                &hex::to_hex(&hash(SAMPLE_CHALLENGE)),
            )
            .into_serde()
            .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, n_a: &str, n_x: &str) {
                let result = sign_comsig_challenge_with_nonce(a, x, n_a, n_x);
                assert_eq!(result.error.is_empty(), false);
                assert_eq!(result.public_nonce.is_some(), false);
                assert_eq!(result.v.is_some(), false);
                assert_eq!(result.u.is_some(), false);
            }

            let (sk, _) = random_keypair();
            it_fails("", "", "", "");
            it_fails("", &sk.to_hex(), &sk.to_hex(), &sk.to_hex());
            it_fails(&["0"; 33].join(""), &sk.to_hex(), &sk.to_hex(), &sk.to_hex());
        }

        #[wasm_bindgen_test]
        fn it_uses_the_given_nonces() {
            let (sk, _) = random_keypair();
            let (r1, _) = random_keypair();
            let (r2, _) = random_keypair();
            let expected_p_nonce = PedersenCommitmentFactory::default().commit(&r1, &r2);
            let result = sign_comsig_challenge_with_nonce(&sk.to_hex(), &sk.to_hex(), &r1.to_hex(), &r2.to_hex());
            assert_eq!(result.error.is_empty(), true);
            assert_eq!(
                PedersenCommitment::from_hex(&result.public_nonce.unwrap()).unwrap(),
                expected_p_nonce
            );
        }
    }

    mod check_comsig_signature {
        use super::*;

        fn check_comsig_signature(
            nonce_commit: &str,
            u: &str,
            v: &str,
            commitment: &str,
            msg: &str,
        ) -> SignatureVerifyResult {
            super::check_comsig_signature(nonce_commit, u, v, commitment, msg)
                .into_serde()
                .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_errors_given_invalid_data() {
            fn it_errors(nonce_commit: &str, signature_u: &str, signature_v: &str, commitment: &str) {
                let result =
                    check_comsig_signature(nonce_commit, signature_u, signature_v, commitment, SAMPLE_CHALLENGE);
                assert_eq!(
                    result.error.is_empty(),
                    false,
                    "check_comsig_signature did not fail with args ({}, {}, {}, {})",
                    nonce_commit,
                    signature_u,
                    signature_v,
                    commitment
                );
                assert_eq!(result.result, false);
            }

            it_errors("", "", "", "");

            let (sig, commit) = create_commsig(SAMPLE_CHALLENGE);
            it_errors(&sig.public_nonce().to_hex(), "", "", &commit.to_hex());
            it_errors(&sig.public_nonce().to_hex(), &sig.u().to_hex(), &sig.v().to_hex(), "");
        }

        #[wasm_bindgen_test]
        fn it_fails_if_verification_is_invalid() {
            fn it_fails(pub_nonce_commit: &str, signature_u: &str, signature_v: &str, commit: &str, msg: &str) {
                let result = check_comsig_signature(pub_nonce_commit, signature_u, signature_v, commit, msg);
                assert_eq!(result.error.is_empty(), true);
                assert_eq!(result.result, false);
            }

            let (sig, commit) = create_commsig(SAMPLE_CHALLENGE);
            it_fails(
                &RistrettoPublicKey::default().to_hex(),
                &sig.u().to_hex(),
                &sig.v().to_hex(),
                &commit.to_hex(),
                SAMPLE_CHALLENGE,
            );
            it_fails(
                &sig.public_nonce().to_hex(),
                &sig.u().to_hex(),
                &sig.v().to_hex(),
                &commit.to_hex(),
                "wrong challenge",
            );
            it_fails(
                &sig.public_nonce().to_hex(),
                &sig.u().to_hex(),
                &sig.v().to_hex(),
                &PedersenCommitment::default().to_hex(),
                SAMPLE_CHALLENGE,
            );
        }

        #[wasm_bindgen_test]
        fn it_succeeds_given_valid_data() {
            let (sig, commit) = create_commsig(SAMPLE_CHALLENGE);
            let result = check_comsig_signature(
                &sig.public_nonce().to_hex(),
                &sig.u().to_hex(),
                &sig.v().to_hex(),
                &commit.to_hex(),
                SAMPLE_CHALLENGE,
            );
            assert!(result.error.is_empty());
            assert!(result.result);
        }
    }

    mod secret_key_from_hex_bytes {
        use super::*;

        #[wasm_bindgen_test]
        fn fail_case() {
            fn it_fails(private_key_hex: &str) {
                assert_eq!(secret_key_from_hex_bytes(private_key_hex).as_bool().unwrap(), false);
            }

            it_fails("");
            it_fails(&["0"; 31].join(""));
            it_fails(&["0"; 33].join(""));
        }

        #[wasm_bindgen_test]
        fn success_case() {
            fn it_succeeds(private_key_hex: &str, expected_sk: &RistrettoSecretKey) {
                let sk = secret_key_from_hex_bytes(private_key_hex)
                    .into_serde::<RistrettoSecretKey>()
                    .unwrap();
                assert_eq!(sk, *expected_sk);
            }

            it_succeeds(&RistrettoSecretKey::default().to_hex(), &RistrettoSecretKey::default());
            let (sk, _) = random_keypair();
            it_succeeds(&sk.to_hex(), &sk);
        }
    }

    mod secret_key_maths {
        use super::*;

        fn it_fails<F: Fn(&str, &str) -> JsValue>(subject: F, k_a: &str, k_b: &str) {
            assert_eq!((subject)(k_a, k_b).as_bool().unwrap(), false);
        }
        fn it_succeeds<F: Fn(&str, &str) -> JsValue>(subject: F, k_a: &str, k_b: &str) -> RistrettoSecretKey {
            (subject)(&k_a, &k_b).into_serde::<RistrettoSecretKey>().unwrap()
        }

        #[wasm_bindgen_test]
        fn fail_case() {
            let valid_hex = RistrettoSecretKey::default().to_hex();
            it_fails(add_secret_keys, "", "");
            it_fails(add_secret_keys, &valid_hex, "");
            it_fails(add_secret_keys, "", &valid_hex);

            it_fails(subtract_secret_keys, "", "");
            it_fails(subtract_secret_keys, &valid_hex, "");
            it_fails(subtract_secret_keys, "", &valid_hex);

            it_fails(multiply_secret_keys, "", "");
            it_fails(multiply_secret_keys, &valid_hex, "");
            it_fails(multiply_secret_keys, "", &valid_hex);
        }

        #[wasm_bindgen_test]
        fn success_case() {
            let (key_a, _) = random_keypair();
            let (key_b, _) = random_keypair();
            let sk = it_succeeds(add_secret_keys, &key_a.to_hex(), &key_b.to_hex());
            assert_eq!(sk, &key_a + &key_b);

            let sk = it_succeeds(subtract_secret_keys, &key_a.to_hex(), &key_b.to_hex());
            assert_eq!(sk, &key_a - &key_b);

            let sk = it_succeeds(multiply_secret_keys, &key_a.to_hex(), &key_b.to_hex());
            assert_eq!(sk, key_a * key_b);
        }
    }
}
