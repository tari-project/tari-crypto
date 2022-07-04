// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Schnorr Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use std::{
    cmp::Ordering,
    ops::{Add, Mul},
};

use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;
use thiserror::Error;

use crate::keys::{PublicKey, SecretKey};

/// An error occurred during construction of a SchnorrSignature
#[derive(Clone, Debug, Error, PartialEq, Eq, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum SchnorrSignatureError {
    #[error("An invalid challenge was provided")]
    InvalidChallenge,
}

/// # SchnorrSignature
///
/// Provides a Schnorr signature that is agnostic to a specific public/private key implementation.
/// For a concrete implementation see [RistrettoSchnorr](crate::ristretto::RistrettoSchnorr).
///
/// More details on Schnorr signatures can be found at [TLU](https://tlu.tarilabs.com/cryptography/introduction-schnorr-signatures).
#[allow(non_snake_case)]
#[derive(PartialEq, Eq, Copy, Debug, Clone, Serialize, Deserialize, Hash)]
pub struct SchnorrSignature<P, K> {
    public_nonce: P,
    signature: K,
}

impl<P, K> SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    /// Create a new `SchnorrSignature`.
    pub fn new(public_nonce: P, signature: K) -> Self {
        SchnorrSignature {
            public_nonce,
            signature,
        }
    }

    /// Calculates the signature verifier `s.G`. This must be equal to `R + eK`.
    fn calc_signature_verifier(&self) -> P {
        P::from_secret_key(&self.signature)
    }

    /// Sign a challenge with the given `secret` and private `nonce`. Returns an SchnorrSignatureError if `<K as
    /// ByteArray>::from_bytes(challenge)` returns an error.
    pub fn sign(secret: K, nonce: K, challenge: &[u8]) -> Result<Self, SchnorrSignatureError>
    where K: Add<Output = K> + Mul<P, Output = P> + Mul<Output = K> {
        // s = r + e.k
        let e = match K::from_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(SchnorrSignatureError::InvalidChallenge),
        };
        let public_nonce = P::from_secret_key(&nonce);
        let ek = e * secret;
        let s = ek + nonce;
        Ok(Self::new(public_nonce, s))
    }

    /// Returns true if this signature is valid for a public key and challenge, otherwise false. This will always return
    /// false if `<K as ByteArray>::from_bytes(challenge)` returns an error.
    pub fn verify_challenge<'a>(&self, public_key: &'a P, challenge: &[u8]) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
    {
        let e = match K::from_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };
        self.verify(public_key, &e)
    }

    /// Returns true if this signature is valid for a public key and challenge scalar, otherwise false.
    pub fn verify<'a>(&self, public_key: &'a P, challenge: &K) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
    {
        let lhs = self.calc_signature_verifier();
        let rhs = &self.public_nonce + challenge * public_key;
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    /// Returns a reference to the `s` signature component.
    pub fn get_signature(&self) -> &K {
        &self.signature
    }

    /// Returns a reference to the public nonce component.
    pub fn get_public_nonce(&self) -> &P {
        &self.public_nonce
    }
}

impl<'a, 'b, P, K> Add<&'b SchnorrSignature<P, K>> for &'a SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
{
    type Output = SchnorrSignature<P, K>;

    fn add(self, rhs: &'b SchnorrSignature<P, K>) -> SchnorrSignature<P, K> {
        let r_sum = self.get_public_nonce() + rhs.get_public_nonce();
        let s_sum = self.get_signature() + rhs.get_signature();
        SchnorrSignature::new(r_sum, s_sum)
    }
}

impl<'a, P, K> Add<SchnorrSignature<P, K>> for &'a SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    for<'b> &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    for<'b> &'a K: Add<&'b K, Output = K>,
{
    type Output = SchnorrSignature<P, K>;

    fn add(self, rhs: SchnorrSignature<P, K>) -> SchnorrSignature<P, K> {
        let r_sum = self.get_public_nonce() + rhs.get_public_nonce();
        let s_sum = self.get_signature() + rhs.get_signature();
        SchnorrSignature::new(r_sum, s_sum)
    }
}

impl<P, K> Default for SchnorrSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn default() -> Self {
        SchnorrSignature::new(P::default(), K::default())
    }
}

impl<P, K> Ord for SchnorrSignature<P, K>
where
    P: Eq + Ord,
    K: Eq + ByteArray,
{
    /// Provide an efficient ordering algorithm for Schnorr signatures. It's probably not a good idea to implement `Ord`
    /// for secret keys, but in this instance, the signature is publicly known and is simply a scalar, so we use the
    /// byte representation of the scalar as the canonical ordering metric. This conversion is done if and only if
    /// the public nonces are already equal, otherwise the public nonce ordering determines the SchnorrSignature
    /// order.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.public_nonce.cmp(&other.public_nonce) {
            Ordering::Equal => self.signature.as_bytes().cmp(other.signature.as_bytes()),
            v => v,
        }
    }
}

impl<P, K> PartialOrd for SchnorrSignature<P, K>
where
    P: Eq + Ord,
    K: Eq + ByteArray,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
