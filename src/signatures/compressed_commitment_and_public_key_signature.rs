// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use tari_utilities::ByteArray;

use crate::{
    compressed_commitment::CompressedCommitment,
    compressed_key::CompressedKey,
    keys::{PublicKey, SecretKey},
    signatures::CommitmentAndPublicKeySignature,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedCommitmentAndPublicKeySignature<P, K> {
    ephemeral_commitment: CompressedCommitment<P>,
    ephemeral_pubkey: CompressedKey<P>,
    u_a: K,
    u_x: K,
    u_y: K,
}

impl<P, K> CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    /// Creates a new [CommitmentSignature]
    pub fn new(
        ephemeral_commitment: CompressedCommitment<P>,
        ephemeral_pubkey: CompressedKey<P>,
        u_a: K,
        u_x: K,
        u_y: K,
    ) -> Self {
        CompressedCommitmentAndPublicKeySignature {
            ephemeral_commitment,
            ephemeral_pubkey,
            u_a,
            u_x,
            u_y,
        }
    }

    pub fn new_from_capk_signature(capk_signature: CommitmentAndPublicKeySignature<P, K>) -> Self {
        let CommitmentAndPublicKeySignature {
            ephemeral_commitment,
            ephemeral_pubkey,
            u_a,
            u_x,
            u_y,
        } = capk_signature;
        let commitment = CompressedCommitment::from_public_key(ephemeral_commitment.as_public_key());
        let public_key = CompressedKey::new_from_pk(&ephemeral_pubkey);
        CompressedCommitmentAndPublicKeySignature {
            ephemeral_commitment: commitment,
            ephemeral_pubkey: public_key,
            u_a: u_a.clone(),
            u_x: u_x.clone(),
            u_y: u_y.clone(),
        }
    }

    /// Get the signature tuple `(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y)`
    pub fn complete_signature_tuple(&self) -> (&CompressedCommitment<P>, &CompressedKey<P>, &K, &K, &K) {
        (
            &self.ephemeral_commitment,
            &self.ephemeral_pubkey,
            &self.u_a,
            &self.u_x,
            &self.u_y,
        )
    }

    /// Get the response value `u_a`
    pub fn u_a(&self) -> &K {
        &self.u_a
    }

    /// Get the response value `u_x`
    pub fn u_x(&self) -> &K {
        &self.u_x
    }

    /// Get the response value `u_y`
    pub fn u_y(&self) -> &K {
        &self.u_y
    }

    /// Get the ephemeral commitment `ephemeral_commitment`
    pub fn ephemeral_commitment(&self) -> &CompressedCommitment<P> {
        &self.ephemeral_commitment
    }

    /// Get the ephemeral public key `ephemeral_pubkey`
    pub fn ephemeral_pubkey(&self) -> &CompressedKey<P> {
        &self.ephemeral_pubkey
    }

    /// Produce a canonical byte representation of the commitment signature
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 * P::key_length() + 3 * K::key_length());
        buf.extend_from_slice(self.ephemeral_commitment().as_bytes());
        buf.extend_from_slice(self.ephemeral_pubkey().as_bytes());
        buf.extend_from_slice(self.u_a().as_bytes());
        buf.extend_from_slice(self.u_x().as_bytes());
        buf.extend_from_slice(self.u_y().as_bytes());
        buf
    }
}

impl<P, K> Default for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K> + ByteArray,
    K: SecretKey,
{
    fn default() -> Self {
        CompressedCommitmentAndPublicKeySignature::new(
            CompressedCommitment::default(),
            CompressedKey::default(),
            K::default(),
            K::default(),
            K::default(),
        )
    }
}

/// Provide a canonical ordering for commitment signatures. We use byte representations of all values in this order:
/// `ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y`
impl<P, K> Ord for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let mut compare = self.ephemeral_commitment().cmp(other.ephemeral_commitment());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.ephemeral_pubkey().cmp(other.ephemeral_pubkey());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.u_a().as_bytes().cmp(other.u_a().as_bytes());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.u_x().as_bytes().cmp(other.u_x().as_bytes());
        if compare != Ordering::Equal {
            return compare;
        }

        self.u_y().as_bytes().cmp(other.u_y().as_bytes())
    }
}

impl<P, K> PartialOrd for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K> PartialEq for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.ephemeral_commitment().eq(other.ephemeral_commitment()) &&
            self.ephemeral_pubkey().eq(other.ephemeral_pubkey()) &&
            self.u_a().eq(other.u_a()) &&
            self.u_x().eq(other.u_x()) &&
            self.u_y().eq(other.u_y())
    }
}

impl<P, K> Eq for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
}

impl<P, K> Hash for CompressedCommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.to_vec())
    }
}
