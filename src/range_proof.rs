// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
    commitment::HomomorphicCommitment,
    keys::{CompressedPublicKey, PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const REWIND_PROOF_MESSAGE_LENGTH: usize = 23;
pub const REWIND_CHECK_MESSAGE: &[u8; 2] = b"TR";
pub const REWIND_USER_MESSAGE_LENGTH: usize = 21;

#[derive(Debug, Clone, Error, PartialEq, Deserialize, Serialize)]
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

pub trait RangeProofService {
    type P: Sized;
    type K: SecretKey;
    type PK: PublicKey<K = Self::K>;
    type CPK: CompressedPublicKey<Self::PK>;

    /// Construct a new range proof for the given secret key and value. The resulting proof will be sufficient
    /// evidence that the prover knows the secret key and value, and that the value lies in the range determined by
    /// the service.
    fn construct_proof(&self, key: &Self::K, value: u64) -> Result<Self::P, RangeProofError>;

    /// Verify the range proof against the given commitment. If this function returns true, it attests to the
    /// commitment having a value in the range [0; 2^64-1] and that the prover knew both the value and private key.
    fn verify(&self, proof: &Self::P, commitment: &Self::CPK) -> bool;

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
    ) -> Result<Self::P, RangeProofError>;

    /// Rewind a rewindable range proof to reveal the committed value and the 19 byte proof message
    fn rewind_proof_value_only(
        &self,
        proof: &Self::P,
        commitment: &Self::CPK,
        rewind_public_key: &Self::CPK,
        rewind_blinding_public_key: &Self::CPK,
    ) -> Result<RewindResult, RangeProofError>;

    /// Fully rewind a rewindable range proof to reveal the committed value, blinding factor and the 19 byte proof
    /// message.
    fn rewind_proof_commitment_data(
        &self,
        proof: &Self::P,
        commitment: &Self::CPK,
        rewind_key: &Self::K,
        rewind_blinding_key: &Self::K,
    ) -> Result<FullRewindResult<Self::K>, RangeProofError>;
}

#[derive(Debug, PartialEq)]
pub struct RewindResult {
    pub committed_value: u64,
    pub proof_message: [u8; REWIND_USER_MESSAGE_LENGTH],
}

impl RewindResult {
    pub fn new(committed_value: u64, proof_message: [u8; REWIND_USER_MESSAGE_LENGTH]) -> Self {
        Self {
            committed_value,
            proof_message,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct FullRewindResult<K>
where K: SecretKey
{
    pub committed_value: u64,
    pub proof_message: [u8; REWIND_USER_MESSAGE_LENGTH],
    pub blinding_factor: K,
}

impl<K> FullRewindResult<K>
where K: SecretKey
{
    pub fn new(committed_value: u64, proof_message: [u8; REWIND_USER_MESSAGE_LENGTH], blinding_factor: K) -> Self {
        Self {
            committed_value,
            proof_message,
            blinding_factor,
        }
    }
}
