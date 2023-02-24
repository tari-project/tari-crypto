// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    ffi::CStr,
    os::raw::{c_char, c_int},
};

use digest::Digest;
use rand::rngs::OsRng;
use tari_utilities::ByteArray;

use crate::{
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    ffi::error::{INVALID_SECRET_KEY_SER, NULL_POINTER, OK, SIGNING_ERROR, STR_CONV_ERR},
    hash::blake2::Blake256,
    keys::{PublicKey, SecretKey},
    ristretto::{
        pedersen::commitment_factory::PedersenCommitmentFactory,
        RistrettoComAndPubSig,
        RistrettoComSig,
        RistrettoPublicKey,
        RistrettoSchnorr,
        RistrettoSecretKey,
    },
};

pub const KEY_LENGTH: usize = 32;

type KeyArray = [u8; KEY_LENGTH];

/// Generate a new key pair and copies the values into the provided arrays.
/// If `pub_key` is null, then only a private key is generated.
///
/// # Safety
/// The *caller* must manage memory for the results. Besides checking for null values, this function assumes that at
/// least `KEY_LENGTH` bytes have been allocated in `priv_key` and `pub_key`.
#[no_mangle]
pub unsafe extern "C" fn random_keypair(priv_key: *mut KeyArray, pub_key: *mut KeyArray) -> c_int {
    if priv_key.is_null() {
        return NULL_POINTER;
    }
    if pub_key.is_null() {
        let k = RistrettoSecretKey::random(&mut OsRng);
        (*priv_key).copy_from_slice(k.as_bytes());
    } else {
        let (k, p) = RistrettoPublicKey::random_keypair(&mut OsRng);
        (*priv_key).copy_from_slice(k.as_bytes());
        (*pub_key).copy_from_slice(p.as_bytes());
    }
    OK
}

/// Generate a Schnorr signature (s, R) using the provided private key and message (k, m).
///
/// # Safety
/// The caller MUST ensure that the string is null terminated e.g. "msg\0".
/// If any args are null then the function returns -1
///
/// The public nonce and signature are returned in the provided mutable arrays.
#[no_mangle]
pub unsafe extern "C" fn sign(
    priv_key: *const KeyArray,
    msg: *const c_char,
    public_nonce: *mut KeyArray,
    signature: *mut KeyArray,
) -> c_int {
    if public_nonce.is_null() || signature.is_null() || priv_key.is_null() || msg.is_null() {
        return NULL_POINTER;
    }
    let k = match RistrettoSecretKey::from_bytes(&(*priv_key)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let pubkey = RistrettoPublicKey::from_secret_key(&k);
    let r = RistrettoSecretKey::random(&mut OsRng);
    let pub_r = RistrettoPublicKey::from_secret_key(&r);
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return STR_CONV_ERR,
    };
    let e = RistrettoSchnorr::construct_domain_separated_challenge::<_, Blake256>(&pub_r, &pubkey, msg.as_bytes());
    let sig = match RistrettoSchnorr::sign_raw(&k, r, e.as_ref()) {
        Ok(sig) => sig,
        _ => return SIGNING_ERROR,
    };
    (*public_nonce).copy_from_slice(sig.get_public_nonce().as_bytes());
    (*signature).copy_from_slice(sig.get_signature().as_bytes());
    OK
}

/// Verify that a Schnorr signature (s, R) is valid for the provided public key and message (P, m).
///
/// # Safety
/// The caller MUST ensure that the string is null terminated e.g. "msg\0".
/// If any args are null then the function returns false, and sets `err_code` to -1
#[no_mangle]
pub unsafe extern "C" fn verify(
    pub_key: *const KeyArray,
    msg: *const c_char,
    pub_nonce: *const KeyArray,
    signature: *const KeyArray,
    err_code: *mut c_int,
) -> bool {
    if pub_key.is_null() || msg.is_null() || pub_nonce.is_null() || signature.is_null() || err_code.is_null() {
        if !err_code.is_null() {
            *err_code = NULL_POINTER;
        }
        return false;
    }
    let pk = match RistrettoPublicKey::from_bytes(&(*pub_key)) {
        Ok(k) => k,
        _ => {
            *err_code = INVALID_SECRET_KEY_SER;
            return false;
        },
    };
    let r_pub = match RistrettoPublicKey::from_bytes(&(*pub_nonce)) {
        Ok(r) => r,
        _ => return false,
    };
    let sig = match RistrettoSecretKey::from_bytes(&(*signature)) {
        Ok(s) => s,
        _ => return false,
    };
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return false,
    };

    let sig = RistrettoSchnorr::new(r_pub, sig);
    sig.verify_message(&pk, msg.as_bytes())
}

/// Generate a Pedersen commitment (C) using the provided value and spending key (a, x).
///
/// # Safety
/// If any args are null the function returns the value of NULL_POINTER (-1)
/// The *caller* must manage memory for the result, this function assumes that at least `KEY_LENGTH` bytes have been
/// allocated in `commitment`
#[no_mangle]
pub unsafe extern "C" fn commitment(
    value: *const KeyArray,
    spend_key: *const KeyArray,
    commitment: *mut KeyArray,
) -> c_int {
    if value.is_null() || spend_key.is_null() || spend_key.is_null() {
        return NULL_POINTER;
    }
    let value = match RistrettoSecretKey::from_bytes(&(*value)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let spend_key = match RistrettoSecretKey::from_bytes(&(*spend_key)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let factory = PedersenCommitmentFactory::default();
    let c = factory.commit(&spend_key, &value);
    (*commitment).copy_from_slice(c.as_bytes());
    OK
}

/// Generate a commitment signature (R, u, v) using the provided value, spending key and challenge (a, x, e).
///
/// # Safety
/// If any args are null the function returns -1.
/// The caller MUST ensure that the string is null terminated e.g. "msg\0".
/// The *caller* must manage memory for the results, this function assumes that at least `KEY_LENGTH` bytes have been
/// allocated in `public_nonce`, `signature_u`, and `signature_v`.
#[no_mangle]
pub unsafe extern "C" fn sign_comsig(
    secret_a: *const KeyArray,
    secret_x: *const KeyArray,
    msg: *const c_char,
    public_nonce: *mut KeyArray,
    signature_u: *mut KeyArray,
    signature_v: *mut KeyArray,
) -> c_int {
    if secret_a.is_null() ||
        secret_x.is_null() ||
        msg.is_null() ||
        public_nonce.is_null() ||
        signature_u.is_null() ||
        signature_v.is_null()
    {
        return NULL_POINTER;
    }
    let secret_a = match RistrettoSecretKey::from_bytes(&(*secret_a)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let secret_x = match RistrettoSecretKey::from_bytes(&(*secret_x)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let nonce_a = RistrettoSecretKey::random(&mut OsRng);
    let nonce_x = RistrettoSecretKey::random(&mut OsRng);
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return STR_CONV_ERR,
    };
    let challenge = Blake256::digest(msg.as_bytes()).to_vec();
    let factory = PedersenCommitmentFactory::default();
    let sig = match RistrettoComSig::sign(&secret_a, &secret_x, &nonce_a, &nonce_x, &challenge, &factory) {
        Ok(sig) => sig,
        _ => return SIGNING_ERROR,
    };
    (*public_nonce).copy_from_slice(sig.public_nonce().as_bytes());
    (*signature_u).copy_from_slice(sig.u().as_bytes());
    (*signature_v).copy_from_slice(sig.v().as_bytes());
    OK
}

/// Verify that a commitment signature (R, u, v) is valid for the provided commitment and challenge (C, e).
///
/// # Safety
/// If any args are null the function returns false and sets `err_code` to -1
#[no_mangle]
pub unsafe extern "C" fn verify_comsig(
    commitment: *const KeyArray,
    msg: *const c_char,
    public_nonce: *const KeyArray,
    signature_u: *const KeyArray,
    signature_v: *const KeyArray,
    err_code: *mut c_int,
) -> bool {
    if commitment.is_null() || msg.is_null() || public_nonce.is_null() || signature_u.is_null() || signature_v.is_null()
    {
        *err_code = NULL_POINTER;
        return false;
    }
    let commitment = match HomomorphicCommitment::from_bytes(&(*commitment)) {
        Ok(k) => k,
        _ => {
            *err_code = INVALID_SECRET_KEY_SER;
            return false;
        },
    };
    let r_pub = match HomomorphicCommitment::from_bytes(&(*public_nonce)) {
        Ok(r) => r,
        _ => return false,
    };
    let u = match RistrettoSecretKey::from_bytes(&(*signature_u)) {
        Ok(s) => s,
        _ => return false,
    };
    let v = match RistrettoSecretKey::from_bytes(&(*signature_v)) {
        Ok(s) => s,
        _ => return false,
    };
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return false,
    };
    let sig = RistrettoComSig::new(r_pub, u, v);
    let challenge = Blake256::digest(msg.as_bytes());
    let challenge = match RistrettoSecretKey::from_bytes(challenge.as_slice()) {
        Ok(e) => e,
        _ => return false,
    };
    let factory = PedersenCommitmentFactory::default();
    sig.verify(&commitment, &challenge, &factory)
}

/// Generate a commitment and public key signature (ephemeral_commitment, ephermeral_pubkey, u_a, u_x, u_y) using the
/// provided value, spending key, secret key, and challenge (a, x, y, e).
///
/// # Safety
/// If any args are null the function returns -1.
/// The caller MUST ensure that the string is null terminated e.g. "msg\0".
/// The *caller* must manage memory for the results, this function assumes that at least `KEY_LENGTH` bytes have been
/// allocated in `ephemeral_commitment`, `ephemeral_pubkey`, `u_a`, `u_x`, and `u_y`.
#[no_mangle]
pub unsafe extern "C" fn sign_comandpubsig(
    a: *const KeyArray,
    x: *const KeyArray,
    y: *const KeyArray,
    msg: *const c_char,
    ephemeral_commitment: *mut KeyArray,
    ephemeral_pubkey: *mut KeyArray,
    u_a: *mut KeyArray,
    u_x: *mut KeyArray,
    u_y: *mut KeyArray,
) -> c_int {
    if a.is_null() ||
        x.is_null() ||
        y.is_null() ||
        msg.is_null() ||
        ephemeral_commitment.is_null() ||
        ephemeral_pubkey.is_null() ||
        u_a.is_null() ||
        u_x.is_null() ||
        u_y.is_null()
    {
        return NULL_POINTER;
    }
    let a = match RistrettoSecretKey::from_bytes(&(*a)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let x = match RistrettoSecretKey::from_bytes(&(*x)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let y = match RistrettoSecretKey::from_bytes(&(*y)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let r_a = RistrettoSecretKey::random(&mut OsRng);
    let r_x = RistrettoSecretKey::random(&mut OsRng);
    let r_y = RistrettoSecretKey::random(&mut OsRng);
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return STR_CONV_ERR,
    };
    let challenge = Blake256::digest(msg.as_bytes()).to_vec();
    let factory = PedersenCommitmentFactory::default();
    let sig = match RistrettoComAndPubSig::sign(&a, &x, &y, &r_a, &r_x, &r_y, &challenge, &factory) {
        Ok(sig) => sig,
        _ => return SIGNING_ERROR,
    };
    (*ephemeral_commitment).copy_from_slice(sig.ephemeral_commitment().as_bytes());
    (*ephemeral_pubkey).copy_from_slice(sig.ephemeral_pubkey().as_bytes());
    (*u_a).copy_from_slice(sig.u_a().as_bytes());
    (*u_x).copy_from_slice(sig.u_x().as_bytes());
    (*u_y).copy_from_slice(sig.u_y().as_bytes());
    OK
}

/// Verify that a commitment and public key signature (ephemeral_commitment, ephemeral_pubkey, u_a, u_a, u_x) is valid
/// for the provided commitment, public key, and challenge (C, D, e).
///
/// # Safety
/// If any args are null the function returns false and sets `err_code` to -1
#[no_mangle]
pub unsafe extern "C" fn verify_comandpubsig(
    commitment: *const KeyArray,
    pubkey: *const KeyArray,
    msg: *const c_char,
    ephemeral_commitment: *const KeyArray,
    ephemeral_pubkey: *const KeyArray,
    u_a: *const KeyArray,
    u_x: *const KeyArray,
    u_y: *const KeyArray,
    err_code: *mut c_int,
) -> bool {
    if commitment.is_null() ||
        pubkey.is_null() ||
        msg.is_null() ||
        ephemeral_commitment.is_null() ||
        ephemeral_pubkey.is_null() ||
        u_a.is_null() ||
        u_x.is_null() ||
        u_y.is_null()
    {
        *err_code = NULL_POINTER;
        return false;
    }
    let commitment = if let Ok(k) = HomomorphicCommitment::from_bytes(&(*commitment)) {
        k
    } else {
        *err_code = INVALID_SECRET_KEY_SER;
        return false;
    };
    let pubkey = if let Ok(k) = RistrettoPublicKey::from_bytes(&(*pubkey)) {
        k
    } else {
        *err_code = INVALID_SECRET_KEY_SER;
        return false;
    };
    let ephemeral_commitment = match HomomorphicCommitment::from_bytes(&(*ephemeral_commitment)) {
        Ok(r) => r,
        _ => return false,
    };
    let ephemeral_pubkey = match RistrettoPublicKey::from_bytes(&(*ephemeral_pubkey)) {
        Ok(r) => r,
        _ => return false,
    };
    let u_a = match RistrettoSecretKey::from_bytes(&(*u_a)) {
        Ok(s) => s,
        _ => return false,
    };
    let u_x = match RistrettoSecretKey::from_bytes(&(*u_x)) {
        Ok(s) => s,
        _ => return false,
    };
    let u_y = match RistrettoSecretKey::from_bytes(&(*u_y)) {
        Ok(s) => s,
        _ => return false,
    };
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return false,
    };
    let sig = RistrettoComAndPubSig::new(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y);
    let challenge = Blake256::digest(msg.as_bytes());
    let challenge = match RistrettoSecretKey::from_bytes(challenge.as_slice()) {
        Ok(e) => e,
        _ => return false,
    };
    let factory = PedersenCommitmentFactory::default();
    sig.verify(&commitment, &pubkey, &challenge, &factory, &mut OsRng)
}

#[cfg(test)]
mod test {
    use std::ptr::null_mut;

    use curve25519_dalek::scalar::Scalar;

    use super::*;

    #[test]
    pub fn test_random_keypair_with_invalid_params() {
        // both are invalid
        unsafe { assert_eq!(NULL_POINTER, random_keypair(null_mut(), null_mut())) };
        let mut pub_key: KeyArray = [0; KEY_LENGTH];
        unsafe { assert_eq!(NULL_POINTER, random_keypair(null_mut(), &mut pub_key)) };
    }

    #[test]
    pub fn test_random_keypair_with_valid_params() {
        let mut priv_key: KeyArray = [0; KEY_LENGTH];
        let priv_key_before = priv_key;
        let mut pub_key: KeyArray = [0; KEY_LENGTH];

        // Public keys is null. A new private key is set
        unsafe {
            random_keypair(&mut priv_key, null_mut());
        }
        assert_ne!(priv_key, priv_key_before);

        let priv_key_before = priv_key;
        // Both are not null.
        unsafe {
            random_keypair(&mut priv_key, &mut pub_key);
        }
        assert_ne!(priv_key, priv_key_before);
        assert_eq!(
            RistrettoPublicKey::from_secret_key(&RistrettoSecretKey(Scalar::from_bytes_mod_order(priv_key))).as_bytes(),
            pub_key
        );
    }

    #[test]
    pub fn test_sign_invalid_params() {
        unsafe {
            let priv_key = [0; KEY_LENGTH];
            let msg = "msg\0";
            let mut nonce = [0; KEY_LENGTH];
            let mut signature = [0; KEY_LENGTH];
            assert_eq!(
                sign(null_mut(), msg.as_ptr() as *const c_char, &mut nonce, &mut signature),
                NULL_POINTER
            );
            assert_eq!(sign(&priv_key, null_mut(), &mut nonce, &mut signature), NULL_POINTER);
            assert_eq!(
                sign(&priv_key, msg.as_ptr() as *const c_char, null_mut(), &mut signature),
                NULL_POINTER
            );
            assert_eq!(
                sign(&priv_key, msg.as_ptr() as *const c_char, &mut nonce, null_mut()),
                NULL_POINTER
            );
        }
    }

    #[test]
    pub fn test_sign_valid_params() {
        let priv_key = [1; KEY_LENGTH];
        let msg = "msg\0";
        let mut nonce = [0; KEY_LENGTH];
        let mut signature = [0; KEY_LENGTH];
        unsafe {
            assert_eq!(
                sign(&priv_key, msg.as_ptr() as *const c_char, &mut nonce, &mut signature),
                OK
            );
        }
    }

    #[test]
    pub fn test_verify_invalid_params() {
        let pub_key = [1; KEY_LENGTH];
        let msg = "msg\0";
        let pub_nonce = [0; KEY_LENGTH];
        let signature = [0; KEY_LENGTH];
        let mut err_code = 0i32;
        unsafe {
            assert!(!verify(
                null_mut(),
                msg.as_ptr() as *const c_char,
                &pub_nonce,
                &signature,
                &mut err_code
            ),);
            assert!(!verify(&pub_key, null_mut(), &pub_nonce, &signature, &mut err_code),);
            assert!(!verify(
                &pub_key,
                msg.as_ptr() as *const c_char,
                null_mut(),
                &signature,
                &mut err_code
            ),);
            assert!(!verify(
                &pub_key,
                msg.as_ptr() as *const c_char,
                &pub_nonce,
                null_mut(),
                &mut err_code
            ),);
            assert!(!verify(
                &pub_key,
                msg.as_ptr() as *const c_char,
                &pub_nonce,
                &signature,
                null_mut()
            ),);
        }
    }

    #[test]
    pub fn test_verify_success() {
        let mut priv_key: KeyArray = [0; KEY_LENGTH];
        let mut pub_key: KeyArray = [0; KEY_LENGTH];
        let mut pub_nonce: KeyArray = [0; KEY_LENGTH];
        let mut signature: KeyArray = [0; KEY_LENGTH];
        let msg = "msg\0";
        let mut err_code = 0i32;
        unsafe {
            random_keypair(&mut priv_key, &mut pub_key);
            sign(&priv_key, msg.as_ptr() as *const c_char, &mut pub_nonce, &mut signature);
            assert!(verify(
                &pub_key,
                msg.as_ptr() as *const c_char,
                &pub_nonce,
                &signature,
                &mut err_code
            ));
        }
    }
}
