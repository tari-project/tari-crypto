// Copyright 2025. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Schnorr Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use digest::Digest;
use tari_utilities::{ByteArray, ByteArrayError};

use crate::{
    compressed_key::CompressedKey,
    hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation},
    keys::{PublicKey, SecretKey},
    signatures::{SchnorrSigChallenge, SchnorrSignature},
};

/// # SchnorrSignature
///
/// Provides a Schnorr signature that is agnostic to a specific public/private key implementation.
/// For a concrete implementation see [RistrettoSchnorr](crate::ristretto::RistrettoSchnorr).
///
/// More details on Schnorr signatures can be found at [TLU](https://tlu.tarilabs.com/cryptography/introduction-schnorr-signatures).
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedSchnorrSignature<P, K, H = SchnorrSigChallenge> {
    public_nonce: CompressedKey<P>,
    signature: K,
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<H>,
}

impl<P, K, H> CompressedSchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    H: DomainSeparation,
{
    /// Create a new `CompressedSchnorrSignature` from a SchnorrSignature.
    pub fn new_from_schnorr(sig: SchnorrSignature<P, K, H>) -> Self {
        let public_nonce = CompressedKey::new(sig.get_public_nonce().as_bytes());
        CompressedSchnorrSignature {
            public_nonce,
            signature: sig.signature,
            _phantom: PhantomData,
        }
    }

    /// Create a new `CompressedSchnorrSignature`.
    pub fn new(public_nonce: CompressedKey<P>, signature: K) -> Self {
        CompressedSchnorrSignature {
            public_nonce,
            signature,
            _phantom: PhantomData,
        }
    }

    pub fn to_schnorr_signature(&self) -> Result<SchnorrSignature<P, K, H>, ByteArrayError> {
        let key = self.public_nonce.to_public_key()?;
        Ok(SchnorrSignature::new(key, self.signature.clone()))
    }

    /// Constructs an opinionated challenge hash for the given public nonce, public key and message.
    ///
    /// In general, the signature challenge is given by `H(R, P, m)`. Often, plain concatenation is used to construct
    /// the challenge. In this implementation, the challenge is constructed by means of domain separated hashing
    /// using the provided digest.
    ///
    /// This challenge is used in the [`sign_message`] and [`verify_message`] methods. If you wish to use a custom
    /// challenge, you can use [`sign_raw_canonical`] or [`sign_raw_wide`] instead.
    pub fn construct_domain_separated_challenge<B, D>(
        public_nonce: &CompressedKey<P>,
        public_key: &P,
        message: B,
    ) -> DomainSeparatedHash<D>
    where
        B: AsRef<[u8]>,
        D: Digest,
    {
        DomainSeparatedHasher::<D, H>::new_with_label("challenge")
            .chain(public_nonce.as_bytes())
            .chain(public_key.as_bytes())
            .chain(message.as_ref())
            .finalize()
    }

    /// Returns a reference to the `s` signature component.
    pub fn get_signature(&self) -> &K {
        &self.signature
    }

    /// Returns a reference to the public nonce component.
    pub fn get_compressed_public_nonce(&self) -> &CompressedKey<P> {
        &self.public_nonce
    }
}

impl<P, K, H> Default for CompressedSchnorrSignature<P, K, H>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    H: DomainSeparation,
{
    fn default() -> Self {
        CompressedSchnorrSignature::new(CompressedKey::default(), K::default())
    }
}

impl<P, K, H> Ord for CompressedSchnorrSignature<P, K, H>
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

impl<P, K, H> PartialOrd for CompressedSchnorrSignature<P, K, H>
where
    P: Eq + Ord,
    K: Eq + ByteArray,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K, H> Eq for CompressedSchnorrSignature<P, K, H>
where
    P: Eq,
    K: Eq,
{
}

impl<P, K, H> PartialEq for CompressedSchnorrSignature<P, K, H>
where
    P: PartialEq,
    K: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.public_nonce.eq(&other.public_nonce) && self.signature.eq(&other.signature)
    }
}

impl<P, K, H> Hash for CompressedSchnorrSignature<P, K, H>
where
    P: Hash,
    K: Hash,
{
    fn hash<T: Hasher>(&self, state: &mut T) {
        self.public_nonce.hash(state);
        self.signature.hash(state);
    }
}
