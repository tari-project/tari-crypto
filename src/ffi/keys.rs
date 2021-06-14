// Copyright 2020. The Tari Project
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    ffi::error::{INVALID_SECRET_KEY_SER, NULL_POINTER, OK, SIGNING_ERROR, STR_CONV_ERR},
    hash::blake2::Blake256,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
};
use digest::Digest;
use libc::c_char;
use rand::rngs::OsRng;
use std::{ffi::CStr, os::raw::c_int};
use tari_utilities::ByteArray;

pub const KEY_LENGTH: usize = 32;

type KeyArray = [u8; KEY_LENGTH];

/// Generate a new key pair and copies the values into the provided arrays.
///
/// If `pub_key` is null, then only a private key is generated.
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

#[no_mangle]
pub unsafe extern "C" fn sign(
    priv_key: *const KeyArray,
    msg: *const c_char,
    nonce: *mut KeyArray,
    signature: *mut KeyArray,
) -> c_int
{
    if nonce.is_null() || signature.is_null() || priv_key.is_null() || msg.is_null() {
        return NULL_POINTER;
    }
    let k = match RistrettoSecretKey::from_bytes(&(*priv_key)) {
        Ok(k) => k,
        _ => return INVALID_SECRET_KEY_SER,
    };
    let r = RistrettoSecretKey::random(&mut OsRng);
    let msg = match CStr::from_ptr(msg).to_str() {
        Ok(s) => s,
        _ => return STR_CONV_ERR,
    };
    let challenge = Blake256::digest(msg.as_bytes()).to_vec();
    let sig = match RistrettoSchnorr::sign(k, r, &challenge) {
        Ok(sig) => sig,
        _ => return SIGNING_ERROR,
    };
    (*nonce).copy_from_slice(sig.get_public_nonce().as_bytes());
    (*signature).copy_from_slice(sig.get_signature().as_bytes());
    OK
}

#[no_mangle]
pub unsafe extern "C" fn verify(
    pub_key: *const KeyArray,
    msg: *const c_char,
    pub_nonce: *mut KeyArray,
    signature: *mut KeyArray,
    err_code: *mut c_int,
) -> bool
{
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
    let challenge = Blake256::digest(msg.as_bytes());
    let challenge = match RistrettoSecretKey::from_bytes(challenge.as_slice()) {
        Ok(e) => e,
        _ => return false,
    };
    sig.verify(&pk, &challenge)
}

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use rand::{CryptoRng, Rng};

    use super::*;
    use std::ptr::null_mut;

    #[test]
    pub fn test_random_keypair_with_invalid_params() {
        // both are invalid
        unsafe { assert_eq!(NULL_POINTER, random_keypair(null_mut(), null_mut())) };
        let mut pub_key: KeyArray = [0; KEY_LENGTH];
        unsafe { assert_eq!(NULL_POINTER, random_keypair(null_mut(), &mut pub_key)) };
    }

    // Mock for the randomness of the keys.
    impl RistrettoSecretKey {
        pub fn random<R>(_rng: &mut R) -> Self {
            RistrettoSecretKey(Scalar::from_bits([1; 32]))
        }
    }

    impl RistrettoPublicKey {
        pub fn random_keypair<R: Rng + CryptoRng>(_rng: &mut R) -> (RistrettoSecretKey, Self) {
            let k = RistrettoSecretKey(Scalar::from_bits([2; 32]));
            let pk = RistrettoPublicKey::from_secret_key(&k);
            (k, pk)
        }
    }

    #[test]
    pub fn test_random_keypair_with_valid_params() {
        let mut priv_key: KeyArray = [0; KEY_LENGTH];
        let mut pub_key: KeyArray = [0; KEY_LENGTH];

        // Public keys is null.
        unsafe {
            random_keypair(&mut priv_key, null_mut());
        }
        assert_eq!([1; 32], priv_key);

        // Both are not null.
        unsafe {
            random_keypair(&mut priv_key, &mut pub_key);
        }
        assert_eq!([2; 32], priv_key);
        assert_eq!(
            RistrettoPublicKey::from_secret_key(&RistrettoSecretKey(Scalar::from_bits(priv_key))).as_bytes(),
            pub_key
        );
    }

    #[test]
    pub fn test_sign_invalid_params() {
        unsafe {
            let priv_key = [0; KEY_LENGTH];
            let msg = "msg";
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
        let msg = "msg";
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
        let msg = "msg";
        let mut pub_nonce = [0; KEY_LENGTH];
        let mut signature = [0; KEY_LENGTH];
        let mut err_code = 0i32;
        unsafe {
            assert_eq!(
                verify(
                    null_mut(),
                    msg.as_ptr() as *const c_char,
                    &mut pub_nonce,
                    &mut signature,
                    &mut err_code
                ),
                false
            );
            assert_eq!(
                verify(&pub_key, null_mut(), &mut pub_nonce, &mut signature, &mut err_code),
                false
            );
            assert_eq!(
                verify(
                    &pub_key,
                    msg.as_ptr() as *const c_char,
                    null_mut(),
                    &mut signature,
                    &mut err_code
                ),
                false
            );
            assert_eq!(
                verify(
                    &pub_key,
                    msg.as_ptr() as *const c_char,
                    &mut pub_nonce,
                    null_mut(),
                    &mut err_code
                ),
                false
            );
            assert_eq!(
                verify(
                    &pub_key,
                    msg.as_ptr() as *const c_char,
                    &mut pub_nonce,
                    &mut signature,
                    null_mut()
                ),
                false
            );
        }
    }

    #[test]
    pub fn test_verify_success() {
        let mut priv_key: KeyArray = [0; KEY_LENGTH];
        let mut pub_key: KeyArray = [0; KEY_LENGTH];
        let mut pub_nonce: KeyArray = [0; KEY_LENGTH];
        let mut signature: KeyArray = [0; KEY_LENGTH];
        let msg = "msg";
        let mut err_code = 0i32;
        unsafe {
            random_keypair(&mut priv_key, &mut pub_key);
            sign(&priv_key, msg.as_ptr() as *const c_char, &mut pub_nonce, &mut signature);
            assert_eq!(
                verify(
                    &pub_key,
                    msg.as_ptr() as *const c_char,
                    &mut pub_nonce,
                    &mut signature,
                    &mut err_code
                ),
                true
            );
        }
    }
}
