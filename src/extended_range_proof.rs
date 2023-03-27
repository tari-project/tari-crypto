// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Extended range proofs

use alloc::{string::ToString, vec::Vec};

use rand_core::{CryptoRng, RngCore};

use crate::{
    commitment::{ExtensionDegree, HomomorphicCommitment},
    errors::RangeProofError,
    keys::{PublicKey, SecretKey},
};

/// A service to generate a proof that value is non-negative, using multiple blinding factors
pub trait ExtendedRangeProofService {
    /// The type of proof, usually a byte array
    type Proof: Sized;
    /// The secret key
    type K: SecretKey;
    /// The public key
    type PK: PublicKey<K = Self::K>;

    /// Construct a simple non-aggregated range proof with default minimum value promise of `0` and the ability to
    /// rewind it. Requires a rewind key (seed nonce) to be included in the range proof.
    fn construct_proof_with_recovery_seed_nonce<R: RngCore + CryptoRng>(
        &self,
        mask: &Self::K,
        value: u64,
        seed_nonce: &Self::K,
        rng: &mut R,
    ) -> Result<Self::Proof, RangeProofError>;

    /// Recover the (unverified) mask for a simple non-aggregated proof using the provided seed-nonce.
    fn recover_mask<R: RngCore + CryptoRng>(
        &self,
        proof: &Self::Proof,
        commitment: &HomomorphicCommitment<Self::PK>,
        seed_nonce: &Self::K,
        rng: &mut R,
    ) -> Result<Self::K, RangeProofError>;

    /// Verify a recovered mask for a simple non-aggregated proof against the commitment.
    fn verify_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        mask: &Self::K,
        value: u64,
    ) -> Result<bool, RangeProofError>;

    /// Constructs a new extended range proof, which may be aggregated, for the given set(s) of secret key(s) value(s)
    /// and minimum value promise(s). Other optional inputs are seed nonce(s) and mask(s) for mask embedding
    /// and recovery. If no mask(s) are provided together with the seed nonce(s), the secret key(s), will be embedded.
    /// The resulting (aggregated) extended proof will be sufficient evidence that the prover knows the set(s) of
    /// secret key(s) and value(s), and that each value is equal to or greater than zero or its minimum value
    /// promise and lies in the range determined by the service.
    fn construct_extended_proof<R: RngCore + CryptoRng>(
        &self,
        extended_witnesses: Vec<ExtendedWitness<Self::K>>,
        seed_nonce: Option<Self::K>,
        rng: &mut R,
    ) -> Result<Self::Proof, RangeProofError>;

    /// Verify the batch of range proofs against the given commitments and minimum value promises, and also recover the
    /// masks for all non-aggregated proofs using the provided seed-nonces. If this function returns Ok, it attests to
    /// the batch of commitments having values in the range [min_val_promise; 2^64-1] and  that the provers knew both
    /// the values and private keys for those commitments. Returned values other than 'None' indicates unverified masks
    /// for a non-aggregated proof.
    /// Note:
    ///   Batch recovery of masks is more expensive than linear mask recovery for the same amount of proofs, so
    ///   that is not promoted. The primary action here is batch verification at a logarithmic cost, with the
    ///   additional benefit to recover masks at an added linear cost.
    fn verify_batch_and_recover_masks<R: RngCore + CryptoRng>(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&AggregatedPrivateStatement<Self::PK>>,
        rng: &mut R,
    ) -> Result<Vec<Option<ExtendedMask<Self::K>>>, RangeProofError>;

    /// Verify the batch of range proofs against the given commitments and minimum value promises. If this
    /// function returns Ok, it attests to the batch of commitments having values in the range [min_val_promise; 2^64-1]
    /// and that the provers knew both the values and private keys for those commitments.
    fn verify_batch<R: RngCore + CryptoRng>(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&AggregatedPublicStatement<Self::PK>>,
        rng: &mut R,
    ) -> Result<(), RangeProofError>;

    /// Recover the (unverified) extended mask for a non-aggregated proof using the provided seed-nonce.
    fn recover_extended_mask<R: RngCore + CryptoRng>(
        &self,
        proof: &Self::Proof,
        statement: &AggregatedPrivateStatement<Self::PK>,
        rng: &mut R,
    ) -> Result<Option<ExtendedMask<Self::K>>, RangeProofError>;

    /// Verify a recovered extended mask for a non-aggregated proof against the commitment.
    fn verify_extended_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        extended_mask: &ExtendedMask<Self::K>,
        value: u64,
    ) -> Result<bool, RangeProofError>;
}

/// Extended blinding factor vector used as part of the witness to construct an extended proof, or rewind data
/// extracted from a range proof containing the mask (e.g. blinding factor vector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedMask<K>
where K: SecretKey
{
    secrets: Vec<K>,
}

impl<K> ExtendedMask<K>
where K: SecretKey
{
    /// Construct a new extended mask
    pub fn assign(extension_degree: ExtensionDegree, secrets: Vec<K>) -> Result<ExtendedMask<K>, RangeProofError> {
        if secrets.is_empty() || secrets.len() != extension_degree as usize {
            Err(RangeProofError::InitializationError {
                reason: "Extended mask length must correspond to the extension degree".to_string(),
            })
        } else {
            Ok(Self { secrets })
        }
    }

    /// Return the extended mask secrets
    pub fn secrets(&self) -> Vec<K> {
        self.secrets.clone()
    }
}

/// The (public) statement contains the commitment and a minimum promised value
#[derive(Clone)]
pub struct Statement<PK>
where PK: PublicKey
{
    /// The commitments
    pub commitment: HomomorphicCommitment<PK>,
    /// Minimum promised value
    pub minimum_value_promise: u64,
}

/// The aggregated public range proof statement contains the vector of commitments and a vector of minimum
/// promised values
#[derive(Clone)]
pub struct AggregatedPublicStatement<PK>
where PK: PublicKey
{
    /// The aggregated statement
    pub statements: Vec<Statement<PK>>,
}

impl<PK> AggregatedPublicStatement<PK>
where PK: PublicKey
{
    /// Initialize a new public 'ExtendedStatement' with sanity checks:
    /// - `statements` must be a power of 2 as mandated by the `bulletproofs_plus` implementation
    pub fn init(statements: Vec<Statement<PK>>) -> Result<Self, RangeProofError> {
        if !statements.len().is_power_of_two() {
            return Err(RangeProofError::InitializationError {
                reason: "Number of commitments must be a power of two".to_string(),
            });
        }
        Ok(Self { statements })
    }
}

/// The aggregated private range proof statement contains the (public) range proof statement and an optional seed nonce
/// for mask recovery
#[derive(Clone)]
pub struct AggregatedPrivateStatement<PK>
where PK: PublicKey
{
    /// The aggregated commitments and minimum promised values
    pub statements: Vec<Statement<PK>>,
    /// Optional private seed nonce for mask recovery
    pub recovery_seed_nonce: Option<PK::K>,
}

impl<PK> AggregatedPrivateStatement<PK>
where PK: PublicKey
{
    /// Initialize a new private 'ExtendedStatement' with sanity checks that supports recovery:
    /// - `statements` must be a power of 2 as mandated by the `bulletproofs_plus` implementation
    /// - mask recovery is not supported with an aggregated statement/proof
    pub fn init(statements: Vec<Statement<PK>>, recovery_seed_nonce: Option<PK::K>) -> Result<Self, RangeProofError> {
        if recovery_seed_nonce.is_some() && statements.len() > 1 {
            return Err(RangeProofError::InitializationError {
                reason: "Mask recovery is not supported with an aggregated statement".to_string(),
            });
        }
        if !statements.len().is_power_of_two() {
            return Err(RangeProofError::InitializationError {
                reason: "Number of commitments must be a power of two".to_string(),
            });
        }
        Ok(Self {
            statements,
            recovery_seed_nonce,
        })
    }
}

/// The extended witness contains the extended mask (blinding factor vector), value and a minimum value
/// promise; this will be used to construct the extended range proof
#[derive(Clone)]
pub struct ExtendedWitness<K>
where K: SecretKey
{
    /// Extended blinding factors of the commitment
    pub mask: ExtendedMask<K>,
    /// Value of the commitment
    pub value: u64,
    /// Minimum promised values
    pub minimum_value_promise: u64,
}

impl<K> ExtendedWitness<K>
where K: SecretKey
{
    /// Create a new private 'ExtendedWitness' to construct an extended range proof
    pub fn new(mask: ExtendedMask<K>, value: u64, minimum_value_promise: u64) -> Self {
        Self {
            mask,
            value,
            minimum_value_promise,
        }
    }
}
