// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Extended range proofs

use std::{string::ToString, vec::Vec};

use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    fn construct_proof_with_recovery_seed_nonce(
        &self,
        mask: &Self::K,
        value: u64,
        seed_nonce: &Self::K,
    ) -> Result<Self::Proof, RangeProofError>;

    /// Recover the (unverified) mask for a simple non-aggregated proof using the provided seed-nonce.
    fn recover_mask(
        &self,
        proof: &Self::Proof,
        commitment: &HomomorphicCommitment<Self::PK>,
        seed_nonce: &Self::K,
    ) -> Result<Self::K, RangeProofError>;

    /// Verify a recovered mask for a simple non-aggregated proof against the commitment. Returns
    /// `Err(RangeProofError::InvalidMask)` if the mask and value do not open the commitment.
    fn verify_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        mask: &Self::K,
        value: u64,
    ) -> Result<(), RangeProofError>;

    /// Constructs a new extended range proof, which may be aggregated, for the given set(s) of secret key(s) value(s)
    /// and minimum value promise(s). Other optional inputs are seed nonce(s) and mask(s) for mask embedding
    /// and recovery. If no mask(s) are provided together with the seed nonce(s), the secret key(s), will be embedded.
    /// The resulting (aggregated) extended proof will be sufficient evidence that the prover knows the set(s) of
    /// secret key(s) and value(s), and that each value is equal to or greater than zero or its minimum value
    /// promise and lies in the range determined by the service.
    fn construct_extended_proof(
        &self,
        extended_witnesses: Vec<ExtendedWitness<Self::K>>,
        seed_nonce: Option<Self::K>,
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
    fn verify_batch_and_recover_masks(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&AggregatedPrivateStatement<Self::PK>>,
    ) -> Result<Vec<Option<ExtendedMask<Self::K>>>, RangeProofError>;

    /// Verify the batch of range proofs against the given commitments and minimum value promises. If this
    /// function returns Ok, it attests to the batch of commitments having values in the range [min_val_promise; 2^64-1]
    /// and that the provers knew both the values and private keys for those commitments.
    fn verify_batch(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&AggregatedPublicStatement<Self::PK>>,
    ) -> Result<(), RangeProofError>;

    /// Recover the (unverified) extended mask for a non-aggregated proof using the provided seed-nonce.
    fn recover_extended_mask(
        &self,
        proof: &Self::Proof,
        statement: &AggregatedPrivateStatement<Self::PK>,
    ) -> Result<Option<ExtendedMask<Self::K>>, RangeProofError>;

    /// Verify a recovered extended mask for a non-aggregated proof against the commitment. Returns
    /// `Err(RangeProofError::InvalidMask)` if the extended mask and value do not open the commitment.
    fn verify_extended_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        extended_mask: &ExtendedMask<Self::K>,
        value: u64,
    ) -> Result<(), RangeProofError>;
}

/// Extended blinding factor vector used as part of the witness to construct an extended proof, or rewind data
/// extracted from a range proof containing the mask (e.g. blinding factor vector).
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ExtendedMask<K>
where K: SecretKey
{
    secrets: Vec<K>,
}

impl<K> core::fmt::Debug for ExtendedMask<K>
where K: SecretKey
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedMask")
            .field("len", &self.secrets.len())
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

impl<K> ConstantTimeEq for ExtendedMask<K>
where K: SecretKey
{
    fn ct_eq(&self, other: &Self) -> Choice {
        self.secrets.as_slice().ct_eq(other.secrets.as_slice())
    }
}

impl<K> PartialEq for ExtendedMask<K>
where K: SecretKey
{
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Clone, Zeroize)]
pub struct AggregatedPrivateStatement<PK>
where PK: PublicKey
{
    /// The aggregated commitments and minimum promised values
    pub statements: Vec<Statement<PK>>,
    /// Optional private seed nonce for mask recovery
    pub recovery_seed_nonce: Option<PK::K>,
}

impl<PK> core::fmt::Debug for AggregatedPrivateStatement<PK>
where PK: PublicKey + core::fmt::Debug
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AggregatedPrivateStatement")
            .field("statements", &self.statements)
            .field(
                "recovery_seed_nonce",
                &self.recovery_seed_nonce.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
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
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
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

impl<K> core::fmt::Debug for ExtendedWitness<K>
where K: SecretKey
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedWitness")
            .field("mask", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("minimum_value_promise", &"[REDACTED]")
            .finish()
    }
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

#[cfg(test)]
mod test {
    use subtle::ConstantTimeEq;
    use zeroize::Zeroize;

    use super::*;
    use crate::{
        commitment::{ExtensionDegree, HomomorphicCommitmentFactory},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey, pedersen::commitment_factory::PedersenCommitmentFactory},
    };

    #[test]
    fn extended_mask_constant_time_eq_and_redacted_debug() {
        let k1 = RistrettoSecretKey::from(42u64);
        let k2 = RistrettoSecretKey::from(43u64);
        assert!(ExtendedMask::<RistrettoSecretKey>::assign(ExtensionDegree::DefaultPedersen, vec![]).is_err());
        assert!(
            ExtendedMask::<RistrettoSecretKey>::assign(ExtensionDegree::AddOneBasePoint, vec![k1.clone()]).is_err()
        );

        let mask1 = ExtendedMask::assign(ExtensionDegree::DefaultPedersen, vec![k1.clone()]).unwrap();
        let mask1_copy = ExtendedMask::assign(ExtensionDegree::DefaultPedersen, vec![k1]).unwrap();
        let mask2 = ExtendedMask::assign(ExtensionDegree::DefaultPedersen, vec![k2]).unwrap();
        assert!(bool::from(mask1.ct_eq(&mask1_copy)));
        assert_eq!(mask1, mask1_copy);
        assert!(!bool::from(mask1.ct_eq(&mask2)));
        assert_ne!(mask1, mask2);

        let mask_debug = format!("{mask1:?}");
        assert!(mask_debug.contains("[REDACTED]"));

        let witness = ExtendedWitness::new(mask1, 100, 50);
        let witness_debug = format!("{witness:?}");
        assert!(witness_debug.contains("[REDACTED]"));
        assert!(!witness_debug.contains("100"));
        assert!(!witness_debug.contains("50"));
    }

    #[test]
    fn aggregated_statements_validation_and_zeroize() {
        assert!(AggregatedPublicStatement::<RistrettoPublicKey>::init(vec![]).is_err());
        assert!(AggregatedPrivateStatement::<RistrettoPublicKey>::init(vec![], None).is_err());

        let factory = PedersenCommitmentFactory::default();
        let mask = RistrettoSecretKey::from(7u64);
        let commitment = factory.commit_value(&mask, 500);
        let stmt = Statement {
            commitment,
            minimum_value_promise: 100,
        };

        let pub_stmt = AggregatedPublicStatement::init(vec![stmt.clone()]).unwrap();
        assert_eq!(pub_stmt.statements.len(), 1);
        assert!(AggregatedPublicStatement::init(vec![stmt.clone(), stmt.clone(), stmt.clone()]).is_err());

        let nonce = RistrettoSecretKey::from(99u64);
        assert!(AggregatedPrivateStatement::init(vec![stmt.clone(), stmt.clone()], Some(nonce.clone())).is_err());

        let mut priv_stmt = AggregatedPrivateStatement::init(vec![stmt], Some(nonce)).unwrap();
        let priv_debug = format!("{priv_stmt:?}");
        assert!(priv_debug.contains("[REDACTED]"));
        priv_stmt.zeroize();
        assert!(priv_stmt.statements.is_empty());
        assert!(priv_stmt.recovery_seed_nonce.is_none());
    }
}
