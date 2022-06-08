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
    commitment::{ExtensionDegree, HomomorphicCommitment},
    errors::RangeProofError,
    keys::{PublicKey, SecretKey},
};

pub trait ExtendedRangeProofService {
    type Proof: Sized;
    type K: SecretKey;
    type PK: PublicKey<K = Self::K>;

    /// Constructs a new extended range proof, which may be aggregated, for the given set(s) of secret key(s) value(s)
    /// and optional minimum value promise(s). Other optional inputs are seed nonce(s) and mask(s) for mask embedding
    /// and recovery. If no mask(s) are provided together with the seed nonce(s), the secret key(s), will be embedded.
    /// The resulting (aggregated) extended proof will be sufficient evidence that the prover knows the set(s) of
    /// secret key(s) and value(s), and that each value is equal to or greater than zero or its optional minimum value
    /// promise and lies in the range determined by the service.
    fn construct_extended_proof(
        &self,
        masks: Vec<ExtendedMask<Self::K>>,
        values: Vec<u64>,
        min_value_promises: Vec<Option<u64>>,
        seed_nonce: Option<Self::K>,
    ) -> Result<Self::Proof, RangeProofError>;

    /// Verify the batch of range proofs against the given commitments and minimum value promises, and also recover the
    /// masks for all non-aggregated proofs using the provided seed-nonces. If this function returns Ok, it attests to
    /// the batch of commitments having values in the range [min_val_promise; 2^64-1] and  that the provers knew both
    /// the values and private keys for those commitments. Returned values other than 'None' indicates unverified masks
    /// for a non-aggregated proof.
    fn verify_batch_and_recover_masks(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&ExtendedStatement<Self::PK>>,
    ) -> Result<Vec<Option<ExtendedMask<Self::K>>>, RangeProofError>;

    /// Verify the batch of range proofs against the given commitments and optional minimum value promises. If this
    /// function returns Ok, it attests to the batch of commitments having values in the range [min_val_promise; 2^64-1]
    /// and that the provers knew both the values and private keys for those commitments.
    fn verify_batch(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&ExtendedStatement<Self::PK>>,
    ) -> Result<(), RangeProofError>;

    /// Recover the (unverified) mask for a non-aggregated proof using the provided seed-nonce.
    fn recover_mask(
        &self,
        proof: &Self::Proof,
        statement: &ExtendedStatement<Self::PK>,
    ) -> Result<Option<ExtendedMask<Self::K>>, RangeProofError>;

    /// Verify a recovered mask for a non-aggregated proof against the commitment.
    fn verify_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        extended_mask: &ExtendedMask<Self::K>,
        value: u64,
    ) -> Result<bool, RangeProofError>;
}

/// Rewind data extracted from a range proof containing the mask (e.g. blinding factor).
#[derive(Debug, Clone, PartialEq)]
pub struct ExtendedMask<K>
where K: SecretKey
{
    blindings: Vec<K>,
}

impl<K> ExtendedMask<K>
where K: SecretKey
{
    /// Construct a new extended mask
    pub fn assign(extension_degree: ExtensionDegree, blindings: Vec<K>) -> Result<ExtendedMask<K>, RangeProofError> {
        if blindings.is_empty() || blindings.len() != extension_degree as usize {
            Err(RangeProofError::InitializationError(
                "Extended mask length must correspond to the extension degree".to_string(),
            ))
        } else {
            Ok(Self { blindings })
        }
    }

    /// Return the extended mask blinding factors
    pub fn blindings(&self) -> Result<Vec<K>, RangeProofError> {
        if self.blindings.is_empty() {
            Err(RangeProofError::InitializationError(
                "Extended mask values not assigned yet".to_string(),
            ))
        } else {
            Ok(self.blindings.clone())
        }
    }
}

/// The range proof statement contains thevector of commitments, vector of optional minimum promised
/// values and a vector of optional seed nonces for mask recovery
#[derive(Clone)]
pub struct ExtendedStatement<PK>
where PK: PublicKey
{
    /// The aggregated commitments
    pub commitments: Vec<HomomorphicCommitment<PK>>,
    /// Optional minimum promised values
    pub minimum_value_promises: Vec<Option<u64>>,
    /// Optional seed nonce for mask recovery
    pub seed_nonce: Option<PK::K>,
}

impl<PK> ExtendedStatement<PK>
where PK: PublicKey
{
    /// Initialize a new 'ExtendedStatement' with sanity checks
    #[allow(dead_code)]
    pub fn init(
        commitments: Vec<HomomorphicCommitment<PK>>,
        minimum_value_promises: Vec<Option<u64>>,
        seed_nonce: Option<PK::K>,
    ) -> Result<Self, RangeProofError> {
        if !commitments.len().is_power_of_two() {
            return Err(RangeProofError::InitializationError(
                "Number of commitments must be a power of two".to_string(),
            ));
        }
        if !minimum_value_promises.len() == commitments.len() {
            return Err(RangeProofError::InitializationError(
                "Incorrect number of minimum value promises".to_string(),
            ));
        }
        if seed_nonce.is_some() && commitments.len() > 1 {
            return Err(RangeProofError::InitializationError(
                "Mask recovery is not supported with an aggregated statement".to_string(),
            ));
        }
        Ok(Self {
            commitments,
            minimum_value_promises,
            seed_nonce,
        })
    }
}
