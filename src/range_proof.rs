// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Range proofs are used to determine if a value lies inside a particular range. Most commonly, we
//! want to prove in zero knowledge that a value is non-negative.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    commitment::HomomorphicCommitment,
    keys::{PublicKey, SecretKey},
};

pub(crate) const REWIND_PROOF_MESSAGE_LENGTH: usize = 23;
pub(crate) const REWIND_CHECK_MESSAGE: &[u8; 2] = b"TR";
pub(crate) const REWIND_USER_MESSAGE_LENGTH: usize = 21;

/// An error that has occurred when constructing or verifying a range proof
#[derive(Debug, Clone, Error, PartialEq, Deserialize, Serialize)]
#[allow(missing_docs)]
pub enum RangeProofError {
    #[error("Could not construct range proof")]
    ProofConstructionError,
    #[error("The deserialization of the range proof failed")]
    InvalidProof,
    #[error("Invalid input was provided to the RangeProofService constructor")]
    InitializationError,
    #[error("Invalid range proof provided")]
    InvalidRangeProof,
    #[error("Invalid range proof rewind, the rewind keys provided must be invalid")]
    InvalidRewind,
}

/// A trait to be implemented for more specific services that construct and verify range proofs
pub trait RangeProofService {
    /// The type of proof, usually a byte array
    type Proof: Sized;
    /// The secret key
    type K: SecretKey;
    /// The public key
    type PK: PublicKey<K = Self::K>;

    /// Construct a new range proof for the given secret key and value. The resulting proof will be sufficient
    /// evidence that the prover knows the secret key and value, and that the value lies in the range determined by
    /// the service.
    fn construct_proof(&self, key: &Self::K, value: u64) -> Result<Self::Proof, RangeProofError>;

    /// Verify the range proof against the given commitment. If this function returns true, it attests to the
    /// commitment having a value in the range [0; 2^64-1] and that the prover knew both the value and private key.
    fn verify(&self, proof: &Self::Proof, commitment: &HomomorphicCommitment<Self::PK>) -> bool;

    /// Return the maximum range of the range proof as a power of 2. i.e. if the maximum range is 2^64, this function
    /// returns 64.
    fn range(&self) -> usize;

    /// Construct a rangeproof with the ability to rewind it. Requires two rewind keys and a 19-byte message to be
    /// included in the range proof. The proof can contain 23 bytes but 4 bytes are used to confirm that a rewind
    /// was performed correctly
    fn construct_proof_with_rewind_key(
        &self,
        key: &Self::K,
        value: u64,
        rewind_key: &Self::K,
        rewind_blinding_key: &Self::K,
        proof_message: &[u8; REWIND_USER_MESSAGE_LENGTH],
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
#[derive(Debug, PartialEq)]
pub struct RewindResult {
    /// The original value `v` as a u64 value
    pub committed_value: u64,
    /// A short message stored in the proof
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
#[derive(Debug, PartialEq)]
pub struct FullRewindResult<K>
where K: SecretKey
{
    /// The original value v, stored in the commitment, as a u64
    pub committed_value: u64,
    /// A short message stored in the proof
    pub proof_message: [u8; REWIND_USER_MESSAGE_LENGTH],
    /// The original blinding factor (secret key) stored in the commitment
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
