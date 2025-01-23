// Copyright 2025. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use tari_utilities::{ByteArray, ByteArrayError};

use crate::{
    compressed_commitment::CompressedCommitment,
    keys::{PublicKey, SecretKey},
    signatures::CommitmentSignature,
};

#[allow(non_snake_case)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshDeserialize, borsh::BorshSerialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedCommitmentSignature<P, K> {
    public_nonce: CompressedCommitment<P>,
    u: K,
    v: K,
}

impl<P, K> CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    /// Creates a new [CompressedCommitment]
    pub fn new(public_nonce: CompressedCommitment<P>, u: K, v: K) -> Self {
        CompressedCommitmentSignature { public_nonce, u, v }
    }

    /// Creates a new [CompressedCommitment]
    pub fn new_from_commitment_signature(sig: CommitmentSignature<P, K>) -> Self {
        let CommitmentSignature { public_nonce, u, v } = sig;
        let public_nonce = CompressedCommitment::from_commitment(public_nonce);
        CompressedCommitmentSignature::new(public_nonce, u, v)
    }

    /// This function returns the complete signature tuple (R, u, v)
    pub fn complete_signature_tuple(&self) -> (&CompressedCommitment<P>, &K, &K) {
        (&self.public_nonce, &self.u, &self.v)
    }

    /// This function returns the first publicly known private key of the signature tuple (u)
    pub fn u(&self) -> &K {
        &self.u
    }

    /// This function returns the second publicly known private key of the signature tuple (v)
    pub fn v(&self) -> &K {
        &self.v
    }

    /// This function returns the public commitment public_nonce of the signature tuple (R)
    pub fn public_nonce(&self) -> &CompressedCommitment<P> {
        &self.public_nonce
    }

    /// Returns a canonical byte representation of the commitment signature
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(P::key_length() + K::key_length() + K::key_length());
        buf.extend_from_slice(self.public_nonce().as_bytes());
        buf.extend_from_slice(self.u().as_bytes());
        buf.extend_from_slice(self.v().as_bytes());
        buf
    }

    /// From a canonical byte representation, retrieves a commitment signature
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ByteArrayError> {
        if buf.len() != P::KEY_LEN + 2 * K::key_length() {
            return Err(ByteArrayError::IncorrectLength {});
        }
        let public_nonce = CompressedCommitment::from_canonical_bytes(&buf[0..P::KEY_LEN])?;
        let u = K::from_canonical_bytes(&buf[P::KEY_LEN..P::KEY_LEN + K::key_length()])?;
        let v = K::from_canonical_bytes(&buf[P::KEY_LEN + K::key_length()..P::KEY_LEN + 2 * K::key_length()])?;

        Ok(Self { public_nonce, u, v })
    }
}

impl<P, K> Default for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K> + ByteArray,
    K: SecretKey,
{
    fn default() -> Self {
        CompressedCommitmentSignature::new(CompressedCommitment::<P>::default(), K::default(), K::default())
    }
}

/// Provide an efficient ordering algorithm for Commitment signatures. It's probably not a good idea to implement `Ord`
/// for secret keys, but in this instance, the signature is publicly known and is simply a scalar, so we use the bytes
/// representation of the scalar as the canonical ordering metric. This conversion is done if and only if the public
/// nonces are already equal, otherwise the public nonce ordering determines the CommitmentSignature order.
impl<P, K> Ord for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.public_nonce().cmp(other.public_nonce()) {
            Ordering::Equal => {
                let this_u = self.u().as_bytes();
                let that_u = other.u().as_bytes();
                match this_u.cmp(that_u) {
                    Ordering::Equal => {
                        let this = self.v().as_bytes();
                        let that = other.v().as_bytes();
                        this.cmp(that)
                    },
                    v => v,
                }
            },
            v => v,
        }
    }
}

impl<P, K> PartialOrd for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K> PartialEq for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.public_nonce().eq(other.public_nonce()) && self.u().eq(other.u()) && self.v().eq(other.v())
    }
}

impl<P, K> Eq for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
}

impl<P, K> Hash for CompressedCommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.to_vec())
    }
}
