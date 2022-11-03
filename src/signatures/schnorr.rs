// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Schnorr Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use std::{
    cmp::Ordering,
    ops::{Add, Mul},
};

use digest::Digest;
use serde::{Deserialize, Serialize};
use tari_utilities::ByteArray;
use thiserror::Error;

use crate::{
    hash::blake2::Blake256,
    hash_domain,
    hashing::{DomainSeparatedHash, DomainSeparatedHasher},
    keys::{PublicKey, SecretKey},
};

// Define the hashing domain for Schnorr signatures
hash_domain!(SchnorrSigChallenge, "com.tari.schnorr_signature", 1);

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
    ///
    /// WARNING: The public key and nonce are NOT bound to the challenge. This method assumes that the challenge has
    /// been constructed such that all commitments are already included in the challenge.
    ///
    /// Use [`sign_raw`] instead if this is what you want. (This method is a deprecated alias for `sign_raw`).
    ///
    /// If you want a simple API that binds the nonce and public key to the message, use [`sign_message`] instead.
    #[deprecated(
        since = "0.16.0",
        note = "This method probably doesn't do what you think it does. Please use `sign_message` or `sign_raw` \
                instead, depending on your use case. This function will be removed in v1.0.0"
    )]
    pub fn sign(secret: K, nonce: K, challenge: &[u8]) -> Result<Self, SchnorrSignatureError>
    where
        K: Add<Output = K>,
        for<'a> K: Mul<&'a K, Output = K>,
    {
        Self::sign_raw(&secret, nonce, challenge)
    }

    /// Sign a challenge with the given `secret` and private `nonce`. Returns an SchnorrSignatureError if `<K as
    /// ByteArray>::from_bytes(challenge)` returns an error.
    ///
    /// WARNING: The public key and nonce are NOT bound to the challenge. This method assumes that the challenge has
    /// been constructed such that all commitments are already included in the challenge.
    ///
    /// If you want a simple API that binds the nonce and public key to the message, use [`sign_message`] instead.
    pub fn sign_raw<'a>(secret: &'a K, nonce: K, challenge: &[u8]) -> Result<Self, SchnorrSignatureError>
    where K: Add<Output = K> + Mul<&'a K, Output = K> {
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

    /// Signs a message with the given secret key.
    ///
    /// This method correctly binds a nonce and the public key to the signature challenge, using domain-separated
    /// hashing. The hasher is also opinionated in the sense that Blake2b 256-bit digest is always used.
    ///
    /// it is possible to customise the challenge by using [`construct_domain_separated_challenge`] and [`sign_raw`]
    /// yourself, or even use [`sign_raw`] using a completely custom challenge.
    pub fn sign_message<'a, B>(secret: &'a K, message: B) -> Result<Self, SchnorrSignatureError>
    where
        K: Add<Output = K> + Mul<&'a K, Output = K>,
        B: AsRef<[u8]>,
    {
        let nonce = K::random(&mut rand::thread_rng());
        let public_nonce = P::from_secret_key(&nonce);
        let public_key = P::from_secret_key(&secret);
        let challenge = Self::construct_domain_separated_challenge::<_, Blake256>(&public_nonce, &public_key, message);
        Self::sign_raw(secret, nonce, challenge.as_ref())
    }

    /// Constructs an opinionated challenge hash for the given public nonce, public key and message.
    ///
    /// In general, the signature challenge is given by `H(R, P, m)`. Often, plain concatenation is used to construct
    /// the challenge. In this implementation, the challenge is constructed by means of domain separated hashing
    /// using the provided digest.
    ///
    /// This challenge is used in the [`sign_message`] and [`verify_message`] methods.If you wish to use a custom
    /// challenge, you can use [`sign_raw`] instead.
    pub fn construct_domain_separated_challenge<B, D>(
        public_nonce: &P,
        public_key: &P,
        message: B,
    ) -> DomainSeparatedHash<D>
    where
        B: AsRef<[u8]>,
        D: Digest,
    {
        DomainSeparatedHasher::<D, SchnorrSigChallenge>::new_with_label("challenge")
            .chain(public_nonce.as_bytes())
            .chain(public_key.as_bytes())
            .chain(message.as_ref())
            .finalize()
    }

    /// Verifies a signature created by the `sign_message` method. The function returns `true` if and only if the
    /// message was signed by the secret key corresponding to the given public key, and that the challenge was
    /// constructed using the domain-separation method defined in [`construct_domain_separated_challenge`].
    pub fn verify_message<'a, B>(&self, public_key: &'a P, message: B) -> bool
    where
        for<'b> &'b K: Mul<&'a P, Output = P>,
        for<'b> &'b P: Add<P, Output = P>,
        B: AsRef<[u8]>,
    {
        let challenge =
            Self::construct_domain_separated_challenge::<_, Blake256>(&self.public_nonce, public_key, message);
        self.verify_challenge(public_key, challenge.as_ref())
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

#[cfg(test)]
mod test {
    use crate::{hashing::DomainSeparation, signatures::SchnorrSigChallenge};

    #[test]
    fn schnorr_hash_domain() {
        assert_eq!(SchnorrSigChallenge::domain(), "com.tari.schnorr_signature");
        assert_eq!(
            SchnorrSigChallenge::domain_separation_tag("test"),
            "com.tari.schnorr_signature.v1.test"
        );
    }
}
