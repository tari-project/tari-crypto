// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Rewindable Range Proofs

use rand_core::{CryptoRng, RngCore};

use crate::{
    commitment::HomomorphicCommitment,
    errors::RangeProofError,
    keys::{PublicKey, SecretKey},
};
/// The length of the user message included in a range proof
pub const REWIND_USER_MESSAGE_LENGTH: usize = 21;

/// A rewindable range proof service
pub trait RewindableRangeProofService {
    /// The type of the proof
    type Proof: Sized;
    /// The type of the secret key
    type K: SecretKey;
    /// The type of the public key
    type PK: PublicKey<K = Self::K>;

    /// Construct a range proof with the ability to rewind it. Requires two rewind keys and a 19-byte message to be
    /// included in the range proof. The proof can contain 23 bytes but 4 bytes are used to confirm that a rewind
    /// was performed correctly
    fn construct_proof_with_rewind_key<R: RngCore + CryptoRng>(
        &self,
        key: &Self::K,
        value: u64,
        rewind_key: &Self::K,
        rewind_blinding_key: &Self::K,
        proof_message: &[u8; REWIND_USER_MESSAGE_LENGTH],
        rng: &mut R,
    ) -> Result<Self::Proof, RangeProofError>;

    /// Rewind a rewindable range proof to reveal the committed value and the 19 byte proof message.
    fn rewind_proof_value_only(
        &self,
        proof: &Self::Proof,
        commitment: &HomomorphicCommitment<Self::PK>,
        rewind_public_key: &Self::PK,
        rewind_blinding_public_key: &Self::PK,
    ) -> Result<RewindResult, RangeProofError>;

    /// Fully rewind a rewindable range proof to reveal the committed value, blinding factor and the 19 byte proof
    /// message.
    fn rewind_proof_commitment_data(
        &self,
        proof: &Self::Proof,
        commitment: &HomomorphicCommitment<Self::PK>,
        rewind_key: &Self::K,
        rewind_blinding_key: &Self::K,
    ) -> Result<FullRewindResult<Self::K>, RangeProofError>;
}

/// Rewind data extracted from a range proof containing the committed value and the 19 byte proof message.
#[derive(Debug, PartialEq, Eq)]
pub struct RewindResult {
    /// The committed value
    pub committed_value: u64,
    /// The 19 byte proof message
    pub proof_message: [u8; REWIND_USER_MESSAGE_LENGTH],
}

impl RewindResult {
    /// Creates a new `RewindResult`
    pub fn new(committed_value: u64, proof_message: [u8; REWIND_USER_MESSAGE_LENGTH]) -> Self {
        Self {
            committed_value,
            proof_message,
        }
    }
}

/// Rewind data extracted from a rangeproof containing the committed value, a 19 byte proof message and the blinding
/// factor.
#[derive(Debug, PartialEq, Eq)]
pub struct FullRewindResult<K>
where K: SecretKey
{
    /// The committed value
    pub committed_value: u64,
    /// The 19 byte proof message
    pub proof_message: [u8; REWIND_USER_MESSAGE_LENGTH],
    /// The blinding factor
    pub blinding_factor: K,
}

impl<K> FullRewindResult<K>
where K: SecretKey
{
    /// Creates a new `FullRewindResult`
    pub fn new(committed_value: u64, proof_message: [u8; REWIND_USER_MESSAGE_LENGTH], blinding_factor: K) -> Self {
        Self {
            committed_value,
            proof_message,
            blinding_factor,
        }
    }
}
