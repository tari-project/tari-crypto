// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Simple cryptographic key functions. It's generally not very efficient to use these functions to do lots of cool
//! stuff with private and public keys, because the keys are translated to- and from hex every time you make a call
//! using a function from this module. You should use a [crate::wasm::keyring::KeyRing] instead. But sometimes, these
//! functions are handy.

use blake2::Digest;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tari_utilities::hex::{from_hex, Hex};
use wasm_bindgen::prelude::*;

use crate::{
    hash::blake2::Blake256,
    keys::{PublicKey, SecretKey},
    ristretto::{
        pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
        RistrettoComAndPubSig,
        RistrettoComSig,
        RistrettoPublicKey,
        RistrettoSchnorr,
        RistrettoSecretKey,
    },
};

/// Result of calling [check_signature] and [check_comsig_signature] and [check_comandpubsig_signature]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SignatureVerifyResult {
    /// True if the signature was valid
    pub result: bool,
    /// Will contain the error if one occurred, otherwise empty
    pub error: String,
}

/// Result of calling [sign]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SignResult {
    /// The public nonce of the signature, if successful
    pub public_nonce: Option<String>,
    /// The signature, if successful
    pub signature: Option<String>,
    /// Will contain the error if one occurred, otherwise empty
    pub error: String,
}

/// Result of calling [sign_comsig]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ComSignResult {
    /// The public nonce of the signature, if successful
    pub public_nonce: Option<String>,
    /// The `u` component of the signature
    pub u: Option<String>,
    /// The `v` component of the signature
    pub v: Option<String>,
    /// Will contain the error if one occurred, otherwise empty
    pub error: String,
}

/// Result of calling [sign_comandpubsig]
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ComAndPubSignResult {
    /// The ephemeral commitment of the signature, if successful
    pub ephemeral_commitment: Option<String>,
    /// The ephemeral pubkey of the signature, if successful
    pub ephemeral_pubkey: Option<String>,
    /// The `u_a` component of the signature
    pub u_a: Option<String>,
    /// The `u_x` component of the signature
    pub u_x: Option<String>,
    /// The `u_y` component of the signature
    pub u_y: Option<String>,
    /// Will contain the error if one occurred, otherwise empty
    pub error: String,
}

/// Create an return a new private- public key pair
#[wasm_bindgen]
pub fn generate_keypair() -> JsValue {
    let (k, p) = RistrettoPublicKey::random_keypair(&mut OsRng);
    let pair = (k.to_hex(), p.to_hex());
    serde_wasm_bindgen::to_value(&pair).unwrap()
}

/// Returns a public key object from a public key hex string, or false if the hex string does not represent a valid
/// public key
#[wasm_bindgen]
pub fn pubkey_from_hex(hex: &str) -> JsValue {
    match RistrettoPublicKey::from_hex(hex) {
        Ok(pk) => serde_wasm_bindgen::to_value(&pk).unwrap_or_else(|_| JsValue::from_bool(false)),
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
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    sign_message_with_key(&k, msg, None, &mut result);
    serde_wasm_bindgen::to_value(&result).unwrap()
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
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let r = match RistrettoSecretKey::from_hex(private_nonce) {
        Ok(r) => r,
        _ => {
            result.error = "Invalid private nonce".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let e = match from_hex(challenge_as_hex) {
        Ok(e) => e,
        _ => {
            result.error = "Challenge was not valid HEX".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    sign_with_key(&k, &e, Some(&r), &mut result);
    serde_wasm_bindgen::to_value(&result).unwrap()
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
            result.error = format!("Could not create signature. {e}");
            return;
        },
    };
    result.public_nonce = Some(R.to_hex());
    result.signature = Some(sig.get_signature().to_hex());
}

/// Checks the validity of a Schnorr signature. Returns a [JsValue] of a serialized [SignatureVerifyResult]
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn check_signature(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) -> JsValue {
    let mut result = SignatureVerifyResult::default();

    let R = match RistrettoPublicKey::from_hex(pub_nonce) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{pub_nonce} is not a valid public nonce");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let P = match RistrettoPublicKey::from_hex(pub_key) {
        Ok(p) => p,
        Err(_) => {
            result.error = format!("{pub_key} is not a valid public key");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let s = match RistrettoSecretKey::from_hex(signature) {
        Ok(s) => s,
        Err(_) => {
            result.error = format!("{signature} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let sig = RistrettoSchnorr::new(R, s);
    let msg = Blake256::digest(msg.as_bytes());
    result.result = sig.verify_challenge(&P, msg.as_slice());
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Generate a Commitment signature of the message using the given private key
#[wasm_bindgen]
pub fn sign_comsig(private_key_a: &str, private_key_x: &str, msg: &str) -> JsValue {
    let mut result = ComSignResult::default();
    let a_key = match RistrettoSecretKey::from_hex(private_key_a) {
        Ok(a_key) => a_key,
        _ => {
            result.error = "Invalid private key".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let x_key = match RistrettoSecretKey::from_hex(private_key_x) {
        Ok(x_key) => x_key,
        _ => {
            result.error = "Invalid private key".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    sign_comsig_message_with_key(&a_key, &x_key, msg, None, None, &mut result);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Generate a Commitment signature of a challenge (that has already been hashed) using the given private
/// key and a specified private nonce. DO NOT reuse nonces. This method is provided for cases where a
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
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let private_key_x = match RistrettoSecretKey::from_hex(private_key_x) {
        Ok(private_key_x) => private_key_x,
        _ => {
            result.error = "Invalid private key_x".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let private_nonce_1 = match RistrettoSecretKey::from_hex(private_nonce_1) {
        Ok(private_nonce_1) => private_nonce_1,
        _ => {
            result.error = "Invalid private nonce_1".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let private_nonce_2 = match RistrettoSecretKey::from_hex(private_nonce_2) {
        Ok(private_nonce_2) => private_nonce_2,
        _ => {
            result.error = "Invalid private nonce_2".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let e = match from_hex(challenge_as_hex) {
        Ok(e) => e,
        _ => {
            result.error = "Challenge was not valid HEX".to_string();
            return serde_wasm_bindgen::to_value(&result).unwrap();
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
    serde_wasm_bindgen::to_value(&result).unwrap()
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

    let sig = match RistrettoComSig::sign(private_key_a, private_key_x, &r_2, &r_1, e, &factory) {
        Ok(s) => s,
        Err(e) => {
            result.error = format!("Could not create signature. {e}");
            return;
        },
    };
    let (public_nonce_commitment, u, v) = sig.complete_signature_tuple();
    result.public_nonce = Some(public_nonce_commitment.to_hex());
    result.u = Some(u.to_hex());
    result.v = Some(v.to_hex());
}

/// Checks the validity of a Commitment signature
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
            result.error = format!("{pub_nonce_commitment} is not a valid public nonce");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let factory = PedersenCommitmentFactory::default();

    let public_commitment = match PedersenCommitment::from_hex(commitment) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{commitment} is not a valid commitment");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let u = match RistrettoSecretKey::from_hex(signature_u) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{signature_u} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let v = match RistrettoSecretKey::from_hex(signature_v) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{signature_v} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let sig = RistrettoComSig::new(R, u, v);
    let msg = Blake256::digest(msg.as_bytes());
    result.result = sig.verify_challenge(&public_commitment, msg.as_slice(), &factory);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Generate a commitment and public key signature of the message using the given private keys
#[wasm_bindgen]
pub fn sign_comandpubsig(private_key_a: &str, private_key_x: &str, private_key_y: &str, msg: &str) -> JsValue {
    let mut result = ComAndPubSignResult::default();
    let a_key = if let Ok(a_key) = RistrettoSecretKey::from_hex(private_key_a) {
        a_key
    } else {
        result.error = "Invalid private key".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let x_key = if let Ok(x_key) = RistrettoSecretKey::from_hex(private_key_x) {
        x_key
    } else {
        result.error = "Invalid private key".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let y_key = if let Ok(y_key) = RistrettoSecretKey::from_hex(private_key_y) {
        y_key
    } else {
        result.error = "Invalid private key".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    sign_comandpubsig_message_with_key(&a_key, &x_key, &y_key, msg, None, None, None, &mut result);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Generate a commitment and public key signature of a challenge (that has already been hashed)
/// using the given private keys and specified private nonces. DO NOT reuse nonces. This method
/// is provided for cases where public nonces have been used in the message.
#[wasm_bindgen]
pub fn sign_comandpubsig_challenge_with_nonce(
    private_key_a: &str,
    private_key_x: &str,
    private_key_y: &str,
    private_nonce_a: &str,
    private_nonce_x: &str,
    private_nonce_y: &str,
    challenge_as_hex: &str,
) -> JsValue {
    let mut result = ComAndPubSignResult::default();
    let private_key_a = if let Ok(private_key_a) = RistrettoSecretKey::from_hex(private_key_a) {
        private_key_a
    } else {
        result.error = "Invalid private key_a".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let private_key_x = if let Ok(private_key_x) = RistrettoSecretKey::from_hex(private_key_x) {
        private_key_x
    } else {
        result.error = "Invalid private key_x".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let private_key_y = if let Ok(private_key_y) = RistrettoSecretKey::from_hex(private_key_y) {
        private_key_y
    } else {
        result.error = "Invalid private key_y".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let private_nonce_a = if let Ok(private_nonce_a) = RistrettoSecretKey::from_hex(private_nonce_a) {
        private_nonce_a
    } else {
        result.error = "Invalid private nonce_a".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let private_nonce_x = if let Ok(private_nonce_x) = RistrettoSecretKey::from_hex(private_nonce_x) {
        private_nonce_x
    } else {
        result.error = "Invalid private nonce_x".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    let private_nonce_y = if let Ok(private_nonce_y) = RistrettoSecretKey::from_hex(private_nonce_y) {
        private_nonce_y
    } else {
        result.error = "Invalid private nonce_y".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };

    let e = if let Ok(e) = from_hex(challenge_as_hex) {
        e
    } else {
        result.error = "Challenge was not valid HEX".to_string();
        return serde_wasm_bindgen::to_value(&result).unwrap();
    };
    sign_comandpubsig_with_key(
        &private_key_a,
        &private_key_x,
        &private_key_y,
        &e,
        Some(&private_nonce_a),
        Some(&private_nonce_x),
        Some(&private_nonce_y),
        &mut result,
    );
    serde_wasm_bindgen::to_value(&result).unwrap()
}

pub(crate) fn sign_comandpubsig_message_with_key(
    private_key_a: &RistrettoSecretKey,
    private_key_x: &RistrettoSecretKey,
    private_key_y: &RistrettoSecretKey,
    msg: &str,
    nonce_a: Option<&RistrettoSecretKey>,
    nonce_x: Option<&RistrettoSecretKey>,
    nonce_y: Option<&RistrettoSecretKey>,
    result: &mut ComAndPubSignResult,
) {
    let e = Blake256::digest(msg.as_bytes());
    sign_comandpubsig_with_key(
        private_key_a,
        private_key_x,
        private_key_y,
        e.as_slice(),
        nonce_a,
        nonce_x,
        nonce_y,
        result,
    );
}

pub(crate) fn sign_comandpubsig_with_key(
    private_key_a: &RistrettoSecretKey,
    private_key_x: &RistrettoSecretKey,
    private_key_y: &RistrettoSecretKey,
    e: &[u8],
    nonce_a: Option<&RistrettoSecretKey>,
    nonce_x: Option<&RistrettoSecretKey>,
    nonce_y: Option<&RistrettoSecretKey>,
    result: &mut ComAndPubSignResult,
) {
    let factory = PedersenCommitmentFactory::default();
    let nonce_a = match nonce_a {
        Some(v) => v.clone(),
        None => RistrettoSecretKey::random(&mut OsRng),
    };
    let nonce_x = match nonce_x {
        Some(v) => v.clone(),
        None => RistrettoSecretKey::random(&mut OsRng),
    };
    let nonce_y = match nonce_y {
        Some(v) => v.clone(),
        None => RistrettoSecretKey::random(&mut OsRng),
    };

    let sig = match RistrettoComAndPubSig::sign(
        private_key_a,
        private_key_x,
        private_key_y,
        &nonce_a,
        &nonce_x,
        &nonce_y,
        e,
        &factory,
    ) {
        Ok(s) => s,
        Err(e) => {
            result.error = format!("Could not create signature. {e}");
            return;
        },
    };
    let (ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y) = sig.complete_signature_tuple();
    result.ephemeral_commitment = Some(ephemeral_commitment.to_hex());
    result.ephemeral_pubkey = Some(ephemeral_pubkey.to_hex());
    result.u_a = Some(u_a.to_hex());
    result.u_x = Some(u_x.to_hex());
    result.u_y = Some(u_y.to_hex());
}

/// Checks the validity of a Commitment signature
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn check_comandpubsig_signature(
    ephemeral_commitment: &str,
    ephemeral_pubkey: &str,
    u_a: &str,
    u_x: &str,
    u_y: &str,
    commitment: &str,
    pubkey: &str,
    msg: &str,
) -> JsValue {
    let mut result = SignatureVerifyResult::default();

    let ephemeral_commitment = match PedersenCommitment::from_hex(ephemeral_commitment) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{ephemeral_commitment} is not a valid ephemeral commitment");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let ephemeral_pubkey = match RistrettoPublicKey::from_hex(ephemeral_pubkey) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{ephemeral_pubkey} is not a valid ephemeral pubkey");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let factory = PedersenCommitmentFactory::default();

    let commitment = match PedersenCommitment::from_hex(commitment) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{commitment} is not a valid commitment");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let pubkey = match RistrettoPublicKey::from_hex(pubkey) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{pubkey} is not a valid pubkey");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let u_a = match RistrettoSecretKey::from_hex(u_a) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{u_a} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let u_x = match RistrettoSecretKey::from_hex(u_x) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{u_x} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };
    let u_y = match RistrettoSecretKey::from_hex(u_y) {
        Ok(n) => n,
        Err(_) => {
            result.error = format!("{u_y} is not a valid hex representation of a signature");
            return serde_wasm_bindgen::to_value(&result).unwrap();
        },
    };

    let sig = RistrettoComAndPubSig::new(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y);
    let msg = Blake256::digest(msg.as_bytes());
    result.result = sig.verify_challenge(&commitment, &pubkey, msg.as_slice(), &factory, &mut OsRng);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/// Create a secret key modulo the Ristretto prime group order using the given little-endian byte array represented as a
/// hex string. If the hex string does not represent 32 bytes the function will return false
#[wasm_bindgen]
pub fn secret_key_from_hex_bytes(private_key_hex: &str) -> JsValue {
    match RistrettoSecretKey::from_hex(private_key_hex) {
        Ok(sk) => serde_wasm_bindgen::to_value(&sk).unwrap_or_else(|_| JsValue::from_bool(false)),
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
    serde_wasm_bindgen::to_value(&result_key).unwrap()
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
    serde_wasm_bindgen::to_value(&result_key).unwrap()
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
    serde_wasm_bindgen::to_value(&result_key).unwrap()
}

#[cfg(test)]
mod test {
    use blake2::digest::Output;
    use wasm_bindgen_test::*;

    use super::*;
    use crate::{
        commitment::HomomorphicCommitmentFactory,
        signatures::{CommitmentAndPublicKeySignature, CommitmentSignature, SchnorrSignature},
        tari_utilities::{hex, ByteArray},
    };

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
        let sig =
            CommitmentSignature::<RistrettoPublicKey, _>::sign(&sk_a, &sk_x, &nonce_a, &nonce_x, &hash(msg), &factory)
                .unwrap();
        let commitment = factory.commit(&sk_x, &sk_a);

        (sig, commitment)
    }

    fn create_comandpubsig(msg: &str) -> (RistrettoComAndPubSig, PedersenCommitment, RistrettoPublicKey) {
        let factory = PedersenCommitmentFactory::default();
        let (sk_a, _) = random_keypair();
        let (sk_x, _) = random_keypair();
        let (sk_y, _) = random_keypair();
        let (nonce_a, _) = random_keypair();
        let (nonce_x, _) = random_keypair();
        let (nonce_y, _) = random_keypair();
        let sig = CommitmentAndPublicKeySignature::<RistrettoPublicKey, _>::sign(
            &sk_a,
            &sk_x,
            &sk_y,
            &nonce_a,
            &nonce_x,
            &nonce_y,
            &hash(msg),
            &factory,
        )
        .unwrap();
        let commitment = factory.commit(&sk_x, &sk_a);
        let pubkey = RistrettoPublicKey::from_secret_key(&sk_y);

        (sig, commitment, pubkey)
    }

    fn key_hex() -> (RistrettoSecretKey, String) {
        let key = RistrettoSecretKey::random(&mut OsRng);
        let key_hex = key.to_hex();
        (key, key_hex)
    }

    #[wasm_bindgen_test]
    fn it_generates_a_keypair() {
        let (k, p): (String, String) = serde_wasm_bindgen::from_value(generate_keypair()).unwrap();
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
            serde_wasm_bindgen::from_value(super::sign(private_key, msg)).unwrap()
        }

        #[wasm_bindgen_test]
        fn it_returns_error_if_invalid() {
            assert!(!sign("", SAMPLE_CHALLENGE).error.is_empty());
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
            serde_wasm_bindgen::from_value(super::sign_challenge_with_nonce(private_key, private_nonce, msg)).unwrap()
        }

        #[wasm_bindgen_test]
        fn it_returns_error_if_invalid() {
            let (_, key) = key_hex();
            assert!(!sign_challenge_with_nonce(&key, "", &hash_hex(SAMPLE_CHALLENGE))
                .error
                .is_empty());
            assert!(
                !sign_challenge_with_nonce(&["0"; 33].join(""), &key, &hash_hex(SAMPLE_CHALLENGE))
                    .error
                    .is_empty()
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
            serde_wasm_bindgen::from_value(super::check_signature(pub_nonce, signature, pub_key, msg)).unwrap()
        }

        #[wasm_bindgen_test]
        fn it_errors_given_invalid_data() {
            fn it_errors(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) {
                let result = check_signature(pub_nonce, signature, pub_key, msg);
                assert!(
                    !result.error.is_empty(),
                    "check_signature did not fail with args ({}, {}, {}, {})",
                    pub_nonce,
                    signature,
                    pub_key,
                    msg
                );
                assert!(!result.result);
            }

            it_errors("", "", "", SAMPLE_CHALLENGE);

            let (sig, pk, _) = create_signature(SAMPLE_CHALLENGE);
            it_errors(&sig.get_public_nonce().to_hex(), "", &pk.to_hex(), SAMPLE_CHALLENGE);
        }

        #[wasm_bindgen_test]
        fn it_fails_if_verification_is_invalid() {
            fn it_fails(pub_nonce: &str, signature: &str, pub_key: &str, msg: &str) {
                let result = check_signature(pub_nonce, signature, pub_key, msg);
                assert!(result.error.is_empty());
                assert!(!result.result);
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
            serde_wasm_bindgen::from_value(super::sign_comsig(private_key_a, private_key_x, msg)).unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, msg: &str) {
                let result = sign_comsig(a, x, msg);
                assert!(!result.error.is_empty());
                assert!(result.public_nonce.is_none());
                assert!(result.v.is_none());
                assert!(result.u.is_none());
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
            serde_wasm_bindgen::from_value(super::sign_comsig_challenge_with_nonce(
                private_key_a,
                private_key_x,
                private_nonce_1,
                private_nonce_2,
                &hex::to_hex(&hash(SAMPLE_CHALLENGE)),
            ))
            .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, n_a: &str, n_x: &str) {
                let result = sign_comsig_challenge_with_nonce(a, x, n_a, n_x);
                assert!(!result.error.is_empty());
                assert!(result.public_nonce.is_none());
                assert!(result.v.is_none());
                assert!(result.u.is_none());
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
            assert!(result.error.is_empty());
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
            serde_wasm_bindgen::from_value(super::check_comsig_signature(nonce_commit, u, v, commitment, msg)).unwrap()
        }

        #[wasm_bindgen_test]
        fn it_errors_given_invalid_data() {
            fn it_errors(nonce_commit: &str, signature_u: &str, signature_v: &str, commitment: &str) {
                let result =
                    check_comsig_signature(nonce_commit, signature_u, signature_v, commitment, SAMPLE_CHALLENGE);
                assert!(
                    !result.error.is_empty(),
                    "check_comsig_signature did not fail with args ({}, {}, {}, {})",
                    nonce_commit,
                    signature_u,
                    signature_v,
                    commitment
                );
                assert!(!result.result);
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
                assert!(result.error.is_empty());
                assert!(!result.result);
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

    mod sign_comandpubsig {
        use super::*;

        fn sign_comandpubsig(
            private_key_a: &str,
            private_key_x: &str,
            private_key_y: &str,
            msg: &str,
        ) -> ComAndPubSignResult {
            serde_wasm_bindgen::from_value(super::sign_comandpubsig(
                private_key_a,
                private_key_x,
                private_key_y,
                msg,
            ))
            .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, y: &str, msg: &str) {
                let result = sign_comandpubsig(a, x, y, msg);
                assert!(!result.error.is_empty());
                assert!(result.ephemeral_commitment.is_none());
                assert!(result.ephemeral_pubkey.is_none());
                assert!(result.u_a.is_none());
                assert!(result.u_x.is_none());
                assert!(result.u_y.is_none());
            }

            let (sk, _) = random_keypair();
            it_fails("", "", "", SAMPLE_CHALLENGE);
            it_fails(&["0"; 33].join(""), &["0"; 33].join(""), &sk.to_hex(), SAMPLE_CHALLENGE);
            it_fails(&["0"; 33].join(""), &sk.to_hex(), &["0"; 33].join(""), SAMPLE_CHALLENGE);
            it_fails(&sk.to_hex(), &["0"; 33].join(""), &["0"; 33].join(""), SAMPLE_CHALLENGE);
        }

        #[wasm_bindgen_test]
        fn it_produces_a_valid_commitment_signature() {
            let (x, _) = random_keypair();
            let (y, _) = random_keypair();
            let a = RistrettoSecretKey::from(123);
            let commitment = PedersenCommitmentFactory::default().commit(&x, &a);
            let pubkey = RistrettoPublicKey::from_secret_key(&y);

            let result = sign_comandpubsig(&a.to_hex(), &x.to_hex(), &y.to_hex(), SAMPLE_CHALLENGE);
            assert!(result.error.is_empty());
            let u_a = RistrettoSecretKey::from_hex(&result.u_a.unwrap()).unwrap();
            let u_x = RistrettoSecretKey::from_hex(&result.u_x.unwrap()).unwrap();
            let u_y = RistrettoSecretKey::from_hex(&result.u_y.unwrap()).unwrap();
            let ephemeral_commitment = PedersenCommitment::from_hex(&result.ephemeral_commitment.unwrap()).unwrap();
            let ephemeral_pubkey = RistrettoPublicKey::from_hex(&result.ephemeral_pubkey.unwrap()).unwrap();
            let comsig = CommitmentAndPublicKeySignature::new(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y);
            assert!(comsig.verify(
                &commitment,
                &pubkey,
                &RistrettoSecretKey::from_bytes(&hash(SAMPLE_CHALLENGE)).unwrap(),
                &PedersenCommitmentFactory::default(),
                &mut OsRng
            ));
        }

        #[wasm_bindgen_test]
        fn it_does_not_reuse_nonces() {
            let (a, _) = random_keypair();
            let (x, _) = random_keypair();
            let (y, _) = random_keypair();
            let result1 = sign_comandpubsig(&a.to_hex(), &x.to_hex(), &y.to_hex(), SAMPLE_CHALLENGE);
            let result2 = sign_comandpubsig(&a.to_hex(), &x.to_hex(), &y.to_hex(), SAMPLE_CHALLENGE);
            assert_ne!(result1.u_a.unwrap(), result2.u_a.unwrap());
            assert_ne!(result1.u_x.unwrap(), result2.u_x.unwrap());
            assert_ne!(result1.u_y.unwrap(), result2.u_y.unwrap());
            assert_ne!(
                result1.ephemeral_commitment.unwrap(),
                result2.ephemeral_commitment.unwrap()
            );
            assert_ne!(result1.ephemeral_pubkey.unwrap(), result2.ephemeral_pubkey.unwrap());
        }
    }

    mod sign_comandpubsig_challenge_with_nonce {
        use super::*;

        fn sign_comandpubsig_challenge_with_nonce(
            private_key_a: &str,
            private_key_x: &str,
            private_key_y: &str,
            private_nonce_a: &str,
            private_nonce_x: &str,
            private_nonce_y: &str,
        ) -> ComAndPubSignResult {
            serde_wasm_bindgen::from_value(super::sign_comandpubsig_challenge_with_nonce(
                private_key_a,
                private_key_x,
                private_key_y,
                private_nonce_a,
                private_nonce_x,
                private_nonce_y,
                &hex::to_hex(&hash(SAMPLE_CHALLENGE)),
            ))
            .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_fails_if_given_invalid_data() {
            fn it_fails(a: &str, x: &str, y: &str, n_a: &str, n_x: &str, n_y: &str) {
                let result = sign_comandpubsig_challenge_with_nonce(a, x, y, n_a, n_x, n_y);
                assert!(!result.error.is_empty());
                assert!(result.ephemeral_commitment.is_none());
                assert!(result.ephemeral_pubkey.is_none());
                assert!(result.u_a.is_none());
                assert!(result.u_x.is_none());
                assert!(result.u_y.is_none());
            }

            let (sk, _) = random_keypair();
            it_fails("", "", "", "", "", "");
            it_fails("", &sk.to_hex(), &sk.to_hex(), &sk.to_hex(), &sk.to_hex(), &sk.to_hex());
            it_fails(
                &["0"; 33].join(""),
                &sk.to_hex(),
                &sk.to_hex(),
                &sk.to_hex(),
                &sk.to_hex(),
                &sk.to_hex(),
            );
        }

        #[wasm_bindgen_test]
        fn it_uses_the_given_nonces() {
            let (sk, _) = random_keypair();
            let (r_a, _) = random_keypair();
            let (r_x, _) = random_keypair();
            let (r_y, _) = random_keypair();
            let expected_ephemeral_commitment = PedersenCommitmentFactory::default().commit(&r_x, &r_a);
            let expected_ephemeral_pubkey = RistrettoPublicKey::from_secret_key(&r_y);
            let result = sign_comandpubsig_challenge_with_nonce(
                &sk.to_hex(),
                &sk.to_hex(),
                &sk.to_hex(),
                &r_a.to_hex(),
                &r_x.to_hex(),
                &r_y.to_hex(),
            );
            assert!(result.error.is_empty());
            assert_eq!(
                PedersenCommitment::from_hex(&result.ephemeral_commitment.unwrap()).unwrap(),
                expected_ephemeral_commitment
            );
            assert_eq!(
                RistrettoPublicKey::from_hex(&result.ephemeral_pubkey.unwrap()).unwrap(),
                expected_ephemeral_pubkey
            );
        }
    }

    mod check_comandpubsig_signature {
        use super::*;

        fn check_comandpubsig_signature(
            ephemeral_commitment: &str,
            ephemeral_pubkey: &str,
            u_a: &str,
            u_x: &str,
            u_y: &str,
            commitment: &str,
            pubkey: &str,
            msg: &str,
        ) -> SignatureVerifyResult {
            serde_wasm_bindgen::from_value(super::check_comandpubsig_signature(
                ephemeral_commitment,
                ephemeral_pubkey,
                u_a,
                u_x,
                u_y,
                commitment,
                pubkey,
                msg,
            ))
            .unwrap()
        }

        #[wasm_bindgen_test]
        fn it_errors_given_invalid_data() {
            fn it_errors(
                ephemeral_commitment: &str,
                ephemeral_pubkey: &str,
                u_a: &str,
                u_x: &str,
                u_y: &str,
                commitment: &str,
                pubkey: &str,
            ) {
                let result = check_comandpubsig_signature(
                    ephemeral_commitment,
                    ephemeral_pubkey,
                    u_a,
                    u_x,
                    u_y,
                    commitment,
                    pubkey,
                    SAMPLE_CHALLENGE,
                );
                assert!(
                    !result.error.is_empty(),
                    "check_comsig_signature did not fail with args ({}, {}, {}, {}, {}, {}, {})",
                    ephemeral_commitment,
                    ephemeral_pubkey,
                    u_a,
                    u_x,
                    u_y,
                    commitment,
                    pubkey
                );
                assert!(!result.result);
            }

            it_errors("", "", "", "", "", "", "");

            let (sig, commitment, pubkey) = create_comandpubsig(SAMPLE_CHALLENGE);
            it_errors(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                "",
                "",
                "",
                &commitment.to_hex(),
                &pubkey.to_hex(),
            );
            it_errors(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                "",
                "",
            );
        }

        #[wasm_bindgen_test]
        fn it_fails_if_verification_is_invalid() {
            fn it_fails(
                ephemeral_commitment: &str,
                ephemeral_pubkey: &str,
                u_a: &str,
                u_x: &str,
                u_y: &str,
                commitment: &str,
                pubkey: &str,
                msg: &str,
            ) {
                let result = check_comandpubsig_signature(
                    ephemeral_commitment,
                    ephemeral_pubkey,
                    u_a,
                    u_x,
                    u_y,
                    commitment,
                    pubkey,
                    msg,
                );
                assert!(result.error.is_empty());
                assert!(!result.result);
            }

            let (sig, commitment, pubkey) = create_comandpubsig(SAMPLE_CHALLENGE);
            it_fails(
                &RistrettoPublicKey::default().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &commitment.to_hex(),
                &pubkey.to_hex(),
                SAMPLE_CHALLENGE,
            );
            it_fails(
                &sig.ephemeral_commitment().to_hex(),
                &RistrettoPublicKey::default().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &commitment.to_hex(),
                &pubkey.to_hex(),
                SAMPLE_CHALLENGE,
            );
            it_fails(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &commitment.to_hex(),
                &pubkey.to_hex(),
                "wrong challenge",
            );
            it_fails(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &PedersenCommitment::default().to_hex(),
                &pubkey.to_hex(),
                SAMPLE_CHALLENGE,
            );
            it_fails(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &commitment.to_hex(),
                &RistrettoPublicKey::default().to_hex(),
                SAMPLE_CHALLENGE,
            );
        }

        #[wasm_bindgen_test]
        fn it_succeeds_given_valid_data() {
            let (sig, commitment, pubkey) = create_comandpubsig(SAMPLE_CHALLENGE);
            let result = check_comandpubsig_signature(
                &sig.ephemeral_commitment().to_hex(),
                &sig.ephemeral_pubkey().to_hex(),
                &sig.u_a().to_hex(),
                &sig.u_x().to_hex(),
                &sig.u_y().to_hex(),
                &commitment.to_hex(),
                &pubkey.to_hex(),
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
                assert!(!secret_key_from_hex_bytes(private_key_hex).as_bool().unwrap());
            }

            it_fails("");
            it_fails(&["0"; 31].join(""));
            it_fails(&["0"; 33].join(""));
        }

        #[wasm_bindgen_test]
        fn success_case() {
            fn it_succeeds(private_key_hex: &str, expected_sk: &RistrettoSecretKey) {
                let sk: RistrettoSecretKey =
                    serde_wasm_bindgen::from_value(secret_key_from_hex_bytes(private_key_hex)).unwrap();
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
            assert!(!(subject)(k_a, k_b).as_bool().unwrap());
        }
        fn it_succeeds<F: Fn(&str, &str) -> JsValue>(subject: F, k_a: &str, k_b: &str) -> RistrettoSecretKey {
            serde_wasm_bindgen::from_value((subject)(k_a, k_b)).unwrap()
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
