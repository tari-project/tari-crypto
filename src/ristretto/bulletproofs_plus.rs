// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Bulletproofs+ implementation

use alloc::vec::Vec;
use core::slice;
use std::convert::TryFrom;

pub use bulletproofs_plus::ristretto::RistrettoRangeProof;
use bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    extended_mask::ExtendedMask as BulletproofsExtendedMask,
    generators::pedersen_gens::ExtensionDegree as BulletproofsExtensionDegree,
    range_parameters::RangeParameters,
    range_proof::{RangeProof, VerifyAction},
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    PedersenGens,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use log::*;

use crate::{
    alloc::string::ToString,
    commitment::{ExtensionDegree as CommitmentExtensionDegree, HomomorphicCommitment},
    errors::RangeProofError,
    extended_range_proof,
    extended_range_proof::{
        AggregatedPrivateStatement,
        AggregatedPublicStatement,
        ExtendedRangeProofService,
        ExtendedWitness,
        Statement,
    },
    range_proof::RangeProofService,
    ristretto::{
        pedersen::extended_commitment_factory::ExtendedPedersenCommitmentFactory,
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

const LOG_TARGET: &str = "tari_crypto::ristretto::bulletproof_plus";

/// A wrapper around the Tari library implementation of Bulletproofs+ range proofs.
pub struct BulletproofsPlusService {
    generators: RangeParameters<RistrettoPoint>,
    transcript_label: &'static str,
}

/// An extended mask for the Ristretto curve
pub type RistrettoExtendedMask = extended_range_proof::ExtendedMask<RistrettoSecretKey>;
/// An extended witness for the Ristretto curve
pub type RistrettoExtendedWitness = ExtendedWitness<RistrettoSecretKey>;
/// A range proof statement for the Ristretto curve
pub type RistrettoStatement = Statement<RistrettoPublicKey>;
/// An aggregated statement for the Ristretto curve
pub type RistrettoAggregatedPublicStatement = AggregatedPublicStatement<RistrettoPublicKey>;
/// An aggregated private statement for the Ristretto curve
pub type RistrettoAggregatedPrivateStatement = AggregatedPrivateStatement<RistrettoPublicKey>;
/// A set of generators for the Ristretto curve
pub type BulletproofsPlusRistrettoPedersenGens = PedersenGens<RistrettoPoint>;

impl TryFrom<&RistrettoExtendedMask> for Vec<Scalar> {
    type Error = RangeProofError;

    fn try_from(extended_mask: &RistrettoExtendedMask) -> Result<Self, Self::Error> {
        Ok(extended_mask.secrets().iter().map(|k| k.0).collect())
    }
}

impl TryFrom<&BulletproofsExtendedMask> for RistrettoExtendedMask {
    type Error = RangeProofError;

    fn try_from(extended_mask: &BulletproofsExtendedMask) -> Result<Self, Self::Error> {
        let secrets = extended_mask
            .blindings()
            .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })?;
        RistrettoExtendedMask::assign(
            CommitmentExtensionDegree::try_from_size(secrets.len())
                .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })?,
            secrets.iter().map(|k| RistrettoSecretKey(*k)).collect(),
        )
    }
}

impl TryFrom<&RistrettoExtendedMask> for BulletproofsExtendedMask {
    type Error = RangeProofError;

    fn try_from(extended_mask: &RistrettoExtendedMask) -> Result<Self, Self::Error> {
        let extension_degree = BulletproofsExtensionDegree::try_from_size(extended_mask.secrets().len())
            .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })?;
        BulletproofsExtendedMask::assign(extension_degree, Vec::try_from(extended_mask)?)
            .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })
    }
}

impl BulletproofsPlusService {
    /// Create a new BulletProofsPlusService containing the generators - this will err if each of 'bit_length' and
    /// 'aggregation_factor' is not a power of two
    pub fn init(
        bit_length: usize,
        aggregation_factor: usize,
        factory: ExtendedPedersenCommitmentFactory,
    ) -> Result<Self, RangeProofError> {
        Ok(Self {
            generators: RangeParameters::init(bit_length, aggregation_factor, BulletproofsPlusRistrettoPedersenGens {
                h_base: factory.h_base,
                h_base_compressed: factory.h_base_compressed,
                g_base_vec: factory.g_base_vec,
                g_base_compressed_vec: factory.g_base_compressed_vec,
                extension_degree: BulletproofsExtensionDegree::try_from_size(factory.extension_degree as usize)
                    .map_err(|e| RangeProofError::InitializationError { reason: e.to_string() })?,
            })
            .map_err(|e| RangeProofError::InitializationError { reason: e.to_string() })?,
            transcript_label: "Tari Bulletproofs+",
        })
    }

    /// Use a custom domain separated transcript label
    pub fn custom_transcript_label(&mut self, transcript_label: &'static str) {
        self.transcript_label = transcript_label;
    }

    /// Helper function to return the serialized proof's extension degree
    pub fn extension_degree(serialized_proof: &[u8]) -> Result<CommitmentExtensionDegree, RangeProofError> {
        let extension_degree = RistrettoRangeProof::extension_degree_from_proof_bytes(serialized_proof)
            .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })?;
        CommitmentExtensionDegree::try_from_size(extension_degree as usize)
            .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })
    }

    /// Helper function to prepare a batch of public range statements
    pub fn prepare_public_range_statements(
        &self,
        statements: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Vec<RangeStatement<RistrettoPoint>> {
        let mut range_statements = Vec::with_capacity(statements.len());
        for statement in statements {
            range_statements.push(RangeStatement {
                generators: self.generators.clone(),
                commitments: statement.statements.iter().map(|v| v.commitment.0.point()).collect(),
                commitments_compressed: statement
                    .statements
                    .iter()
                    .map(|v| *v.commitment.0.compressed())
                    .collect(),
                minimum_value_promises: statement
                    .statements
                    .iter()
                    .map(|v| Some(v.minimum_value_promise))
                    .collect(),
                seed_nonce: None,
            });
        }
        range_statements
    }

    /// Helper function to prepare a batch of private range statements
    pub fn prepare_private_range_statements(
        &self,
        statements: Vec<&RistrettoAggregatedPrivateStatement>,
    ) -> Vec<RangeStatement<RistrettoPoint>> {
        let mut range_statements = Vec::with_capacity(statements.len());
        for statement in statements {
            range_statements.push(RangeStatement {
                generators: self.generators.clone(),
                commitments: statement.statements.iter().map(|v| v.commitment.0.point()).collect(),
                commitments_compressed: statement
                    .statements
                    .iter()
                    .map(|v| *v.commitment.0.compressed())
                    .collect(),
                minimum_value_promises: statement
                    .statements
                    .iter()
                    .map(|v| Some(v.minimum_value_promise))
                    .collect(),
                seed_nonce: statement.recovery_seed_nonce.as_ref().map(|n| n.0),
            });
        }
        range_statements
    }

    /// Helper function to deserialize a batch of range proofs
    pub fn deserialize_range_proofs(
        &self,
        proofs: &[&<BulletproofsPlusService as RangeProofService>::Proof],
    ) -> Result<Vec<RangeProof<RistrettoPoint>>, RangeProofError> {
        let mut range_proofs = Vec::with_capacity(proofs.len());
        for (i, proof) in proofs.iter().enumerate() {
            match RistrettoRangeProof::from_bytes(proof)
                .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })
            {
                Ok(rp) => {
                    range_proofs.push(rp);
                },
                Err(e) => {
                    return Err(RangeProofError::InvalidRangeProof {
                        reason: format!("Range proof at index '{i}' could not be deserialized ({e})"),
                    });
                },
            }
        }
        Ok(range_proofs)
    }
}

impl RangeProofService for BulletproofsPlusService {
    type K = RistrettoSecretKey;
    type PK = RistrettoPublicKey;
    type Proof = Vec<u8>;

    fn construct_proof(&self, key: &Self::K, value: u64) -> Result<Self::Proof, RangeProofError> {
        let commitment = self
            .generators
            .pc_gens()
            .commit(&Scalar::from(value), &[key.0])
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;
        let opening = CommitmentOpening::new(value, vec![key.0]);
        let witness = RangeWitness::init(vec![opening])
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;
        let statement = RangeStatement::init(self.generators.clone(), vec![commitment], vec![None], None)
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        let proof = RistrettoRangeProof::prove(self.transcript_label, &statement, &witness)
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        Ok(proof.to_bytes())
    }

    fn verify(&self, proof: &Self::Proof, commitment: &HomomorphicCommitment<Self::PK>) -> bool {
        match RistrettoRangeProof::from_bytes(proof)
            .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })
        {
            Ok(rp) => {
                let statement = RangeStatement {
                    generators: self.generators.clone(),
                    commitments: vec![commitment.0.clone().into()],
                    commitments_compressed: vec![*commitment.0.compressed()],
                    minimum_value_promises: vec![None],
                    seed_nonce: None,
                };
                match RistrettoRangeProof::verify_batch(
                    self.transcript_label,
                    &[statement],
                    &[rp.clone()],
                    VerifyAction::VerifyOnly,
                ) {
                    Ok(_) => true,
                    Err(e) => {
                        if self.generators.extension_degree() != rp.extension_degree() {
                            error!(
                                target: LOG_TARGET,
                                "Generators' extension degree ({:?}) and proof's extension degree ({:?}) do not \
                                 match; consider using a BulletproofsPlusService with a matching extension degree",
                                self.generators.extension_degree(),
                                rp.extension_degree()
                            );
                        }
                        error!(target: LOG_TARGET, "Internal range proof error ({})", e.to_string());
                        false
                    },
                }
            },
            Err(e) => {
                error!(
                    target: LOG_TARGET,
                    "Range proof could not be deserialized ({})",
                    e.to_string()
                );
                false
            },
        }
    }

    fn range(&self) -> usize {
        self.generators.bit_length()
    }
}

impl ExtendedRangeProofService for BulletproofsPlusService {
    type K = RistrettoSecretKey;
    type PK = RistrettoPublicKey;
    type Proof = Vec<u8>;

    fn construct_proof_with_recovery_seed_nonce(
        &self,
        mask: &Self::K,
        value: u64,
        seed_nonce: &Self::K,
    ) -> Result<Self::Proof, RangeProofError> {
        let commitment = self
            .generators
            .pc_gens()
            .commit(&Scalar::from(value), &[mask.0])
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;
        let opening = CommitmentOpening::new(value, vec![mask.0]);
        let witness = RangeWitness::init(vec![opening])
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;
        let statement = RangeStatement::init(
            self.generators.clone(),
            vec![commitment],
            vec![None],
            Some(seed_nonce.0),
        )
        .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        let proof = RistrettoRangeProof::prove(self.transcript_label, &statement, &witness)
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        Ok(proof.to_bytes())
    }

    fn construct_extended_proof(
        &self,
        extended_witnesses: Vec<RistrettoExtendedWitness>,
        seed_nonce: Option<Self::K>,
    ) -> Result<Self::Proof, RangeProofError> {
        if extended_witnesses.is_empty() {
            return Err(RangeProofError::ProofConstructionError {
                reason: "Extended witness vector cannot be empty".to_string(),
            });
        }
        let mut commitments = Vec::with_capacity(extended_witnesses.len());
        let mut openings = Vec::with_capacity(extended_witnesses.len());
        let mut min_value_promises = Vec::with_capacity(extended_witnesses.len());
        for witness in &extended_witnesses {
            commitments.push(
                self.generators
                    .pc_gens()
                    .commit(&Scalar::from(witness.value), &Vec::try_from(&witness.mask)?)
                    .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?,
            );
            openings.push(CommitmentOpening::new(witness.value, Vec::try_from(&witness.mask)?));
            min_value_promises.push(witness.minimum_value_promise);
        }
        let witness = RangeWitness::init(openings)
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;
        let statement = RangeStatement::init(
            self.generators.clone(),
            commitments,
            min_value_promises.iter().map(|v| Some(*v)).collect(),
            seed_nonce.map(|s| s.0),
        )
        .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        let proof = RistrettoRangeProof::prove(self.transcript_label, &statement, &witness)
            .map_err(|e| RangeProofError::ProofConstructionError { reason: e.to_string() })?;

        Ok(proof.to_bytes())
    }

    fn verify_batch_and_recover_masks(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoAggregatedPrivateStatement>,
    ) -> Result<Vec<Option<RistrettoExtendedMask>>, RangeProofError> {
        // Prepare the range statements
        let range_statements = self.prepare_private_range_statements(statements);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs)?;

        // Verify and recover
        let mut recovered_extended_masks = Vec::new();
        match RistrettoRangeProof::verify_batch(
            self.transcript_label,
            &range_statements,
            &range_proofs,
            VerifyAction::RecoverAndVerify,
        ) {
            Ok(recovered_masks) => {
                if recovered_masks.is_empty() {
                    // A mask vector should always be returned so this is a valid error condition
                    return Err(RangeProofError::InvalidRewind {
                        reason: "Range proof(s) verified Ok, but no mask vector returned".to_string(),
                    });
                } else {
                    for recovered_mask in recovered_masks {
                        if let Some(mask) = &recovered_mask {
                            recovered_extended_masks.push(Some(RistrettoExtendedMask::try_from(mask)?));
                        } else {
                            recovered_extended_masks.push(None);
                        }
                    }
                }
            },
            Err(e) => {
                return Err(RangeProofError::InvalidRangeProof {
                    reason: format!("Internal range proof(s) error ({e})"),
                })
            },
        };
        Ok(recovered_extended_masks)
    }

    fn verify_batch(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Result<(), RangeProofError> {
        // Prepare the range statements
        let range_statements = self.prepare_public_range_statements(statements);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs)?;

        // Verify
        match RistrettoRangeProof::verify_batch(
            self.transcript_label,
            &range_statements,
            &range_proofs,
            VerifyAction::VerifyOnly,
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(RangeProofError::InvalidRangeProof {
                reason: format!("Internal range proof(s) error ({e})"),
            }),
        }
    }

    fn verify_batch_with_first_blame(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Result<(), Option<usize>> {
        // Prepare the range statements
        let range_statements = self.prepare_public_range_statements(statements);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs).map_err(|_| None)?;

        // Try to verify the entire batch
        if RistrettoRangeProof::verify_batch(
            self.transcript_label,
            &range_statements,
            &range_proofs,
            VerifyAction::VerifyOnly,
        )
        .is_ok()
        {
            return Ok(());
        }

        // If the batch fails, perform a binary search to identify a failing proof
        let mut left = 0;
        let mut right = range_proofs.len();

        while left < right {
            let mid = if (left + right) % 2 == 0 {
                (left + right) / 2
            } else {
                (left + right) / 2 + 1
            };

            // Which side is the failure on?
            let failure_on_left = RistrettoRangeProof::verify_batch(
                self.transcript_label,
                &range_statements[left..mid],
                &range_proofs[left..mid],
                VerifyAction::VerifyOnly,
            )
            .is_err();

            if failure_on_left {
                // Are we done?
                if left == mid - 1 {
                    return Err(Some(left));
                }

                // Discard the right side and continue
                right = mid;
            } else {
                // Are we done?
                if right == mid + 1 {
                    return Err(Some(right));
                }

                // Discard the left side and continue
                left = mid;
            }
        }

        // We should never get here! If we do, some has gone wrong unexpectedly
        Err(None)
    }

    fn verify_batch_with_all_blame(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoAggregatedPublicStatement>,
    ) -> Result<(), Option<Vec<usize>>> {
        // Prepare the range statements
        let range_statements = self.prepare_public_range_statements(statements);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs).map_err(|_| None)?;

        // Try to verify the entire batch
        if RistrettoRangeProof::verify_batch(
            self.transcript_label,
            &range_statements,
            &range_proofs,
            VerifyAction::VerifyOnly,
        )
        .is_ok()
        {
            return Ok(());
        }

        let mut failures = Vec::with_capacity(range_proofs.len());

        // If the batch fails, verify all proofs and identify failures
        for (index, (proof, statement)) in range_proofs.iter().zip(range_statements.iter()).enumerate() {
            if RistrettoRangeProof::verify_batch(
                self.transcript_label,
                slice::from_ref(statement),
                slice::from_ref(proof),
                VerifyAction::VerifyOnly,
            )
            .is_err()
            {
                failures.push(index);
            }
        }

        // Ensure that we have found at least one failed proof; otherwise, something has gone wrong unexpectedly
        if failures.is_empty() {
            return Err(None);
        }

        Err(Some(failures))
    }

    fn recover_mask(
        &self,
        proof: &Self::Proof,
        commitment: &HomomorphicCommitment<Self::PK>,
        seed_nonce: &Self::K,
    ) -> Result<Self::K, RangeProofError> {
        match RistrettoRangeProof::from_bytes(proof)
            .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })
        {
            Ok(rp) => {
                let statement = RangeStatement {
                    generators: self.generators.clone(),
                    commitments: vec![commitment.0.point()],
                    commitments_compressed: vec![*commitment.0.compressed()],
                    minimum_value_promises: vec![None],
                    seed_nonce: Some(seed_nonce.0),
                };
                // Prepare the range statement

                match RistrettoRangeProof::verify_batch(
                    self.transcript_label,
                    &vec![statement],
                    &[rp],
                    VerifyAction::RecoverOnly,
                ) {
                    Ok(recovered_mask) => {
                        if recovered_mask.is_empty() {
                            Err(RangeProofError::InvalidRewind {
                                reason: "Mask could not be recovered".to_string(),
                            })
                        } else if let Some(mask) = &recovered_mask[0] {
                            Ok(RistrettoSecretKey(
                                mask.blindings()
                                    .map_err(|e| RangeProofError::InvalidRewind { reason: e.to_string() })?[0],
                            ))
                        } else {
                            Err(RangeProofError::InvalidRewind {
                                reason: "Mask could not be recovered".to_string(),
                            })
                        }
                    },
                    Err(e) => Err(RangeProofError::InvalidRangeProof {
                        reason: format!("Internal range proof error ({e})"),
                    }),
                }
            },
            Err(e) => Err(RangeProofError::InvalidRangeProof {
                reason: format!("Range proof could not be deserialized ({e})"),
            }),
        }
    }

    fn recover_extended_mask(
        &self,
        proof: &Self::Proof,
        statement: &RistrettoAggregatedPrivateStatement,
    ) -> Result<Option<RistrettoExtendedMask>, RangeProofError> {
        match RistrettoRangeProof::from_bytes(proof)
            .map_err(|e| RangeProofError::InvalidRangeProof { reason: e.to_string() })
        {
            Ok(rp) => {
                // Prepare the range statement
                let range_statements = self.prepare_private_range_statements(vec![statement]);

                match RistrettoRangeProof::verify_batch(
                    self.transcript_label,
                    &range_statements,
                    &[rp],
                    VerifyAction::RecoverOnly,
                ) {
                    Ok(recovered_mask) => {
                        if recovered_mask.is_empty() {
                            Ok(None)
                        } else if let Some(mask) = &recovered_mask[0] {
                            Ok(Some(RistrettoExtendedMask::try_from(mask)?))
                        } else {
                            Ok(None)
                        }
                    },
                    Err(e) => Err(RangeProofError::InvalidRangeProof {
                        reason: format!("Internal range proof error ({e})"),
                    }),
                }
            },
            Err(e) => Err(RangeProofError::InvalidRangeProof {
                reason: format!("Range proof could not be deserialized ({e})"),
            }),
        }
    }

    fn verify_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        mask: &Self::K,
        value: u64,
    ) -> Result<bool, RangeProofError> {
        match self
            .generators
            .pc_gens()
            .commit(&Scalar::from(value), &[mask.0])
            .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })
        {
            Ok(val) => Ok(val == commitment.0.point()),
            Err(e) => Err(e),
        }
    }

    fn verify_extended_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        extended_mask: &RistrettoExtendedMask,
        value: u64,
    ) -> Result<bool, RangeProofError> {
        match self
            .generators
            .pc_gens()
            .commit(&Scalar::from(value), &Vec::try_from(extended_mask)?)
            .map_err(|e| RangeProofError::RPExtensionDegree { reason: e.to_string() })
        {
            Ok(val) => Ok(val == commitment.0.point()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, vec::Vec};

    use bulletproofs_plus::protocols::scalar_protocol::ScalarProtocol;
    use curve25519_dalek::scalar::Scalar;
    use rand::Rng;

    use crate::{
        commitment::{
            ExtendedHomomorphicCommitmentFactory,
            ExtensionDegree as CommitmentExtensionDegree,
            HomomorphicCommitmentFactory,
        },
        extended_range_proof::ExtendedRangeProofService,
        range_proof::RangeProofService,
        ristretto::{
            bulletproofs_plus::{
                BulletproofsPlusService,
                RistrettoAggregatedPrivateStatement,
                RistrettoAggregatedPublicStatement,
                RistrettoExtendedMask,
                RistrettoExtendedWitness,
                RistrettoStatement,
            },
            pedersen::extended_commitment_factory::ExtendedPedersenCommitmentFactory,
            RistrettoSecretKey,
        },
    };

    static EXTENSION_DEGREE: [CommitmentExtensionDegree; 6] = [
        CommitmentExtensionDegree::DefaultPedersen,
        CommitmentExtensionDegree::AddOneBasePoint,
        CommitmentExtensionDegree::AddTwoBasePoints,
        CommitmentExtensionDegree::AddThreeBasePoints,
        CommitmentExtensionDegree::AddFourBasePoints,
        CommitmentExtensionDegree::AddFiveBasePoints,
    ];

    /// 'BulletproofsPlusService' initialization should only succeed when both bit length and aggregation size are a
    /// power of 2 and when bit_length <= 64
    // Initialize the range proof service, checking that it behaves correctly
    #[test]
    fn test_service_init() {
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            for bit_length in [1, 2, 4, 5, 128] {
                for aggregation_size in [1, 2, 3] {
                    let bullet_proofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone());
                    if bit_length.is_power_of_two() && aggregation_size.is_power_of_two() && bit_length <= 64 {
                        assert!(bullet_proofs_plus_service.is_ok());
                    } else {
                        assert!(bullet_proofs_plus_service.is_err());
                    }
                }
            }
        }
    }

    /// Test non-extended range proof service functionality
    /// These proofs are not aggregated and do not use extension or batch verification
    /// Using nontrivial aggregation or extension or an invalid value should fail
    #[test]
    fn test_range_proof_service() {
        let mut rng = rand::thread_rng();
        const BIT_LENGTH: usize = 4;
        const AGGREGATION_FACTORS: [usize; 2] = [1, 2];

        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();

            for aggregation_factor in AGGREGATION_FACTORS {
                let bulletproofs_plus_service =
                    BulletproofsPlusService::init(BIT_LENGTH, aggregation_factor, factory.clone()).unwrap();
                assert_eq!(bulletproofs_plus_service.range(), BIT_LENGTH);

                for value in [0, 1, u64::MAX] {
                    let key = RistrettoSecretKey(Scalar::random_not_zero(&mut rng));
                    let proof = bulletproofs_plus_service.construct_proof(&key, value);
                    // This should only succeed with trivial aggregation and extension and a valid value
                    if extension_degree == CommitmentExtensionDegree::DefaultPedersen &&
                        aggregation_factor == 1 &&
                        value >> (BIT_LENGTH - 1) <= 1
                    {
                        // The proof should succeed
                        let proof = proof.unwrap();

                        // Successful verification
                        assert!(bulletproofs_plus_service.verify(&proof, &factory.commit_value(&key, value)));

                        // Failed verification (due to a bad mask)
                        assert!(!bulletproofs_plus_service.verify(
                            &proof,
                            &factory.commit_value(&RistrettoSecretKey(Scalar::random_not_zero(&mut rng)), value)
                        ));
                    } else {
                        assert!(proof.is_err());
                    }
                }
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_construct_verify_extended_proof_with_recovery() {
        static BIT_LENGTH: [usize; 2] = [2, 64];
        static AGGREGATION_SIZE: [usize; 2] = [1, 2];
        let mut rng = rand::thread_rng();
        for extension_degree in [
            CommitmentExtensionDegree::DefaultPedersen,
            CommitmentExtensionDegree::AddFiveBasePoints,
        ] {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            // bit length and aggregation size are chosen so that 'BulletProofsPlusService::init' will always succeed
            for bit_length in BIT_LENGTH {
                // 0. Batch data
                let mut private_masks: Vec<Option<RistrettoExtendedMask>> = vec![];
                let mut public_masks: Vec<Option<RistrettoExtendedMask>> = vec![];
                let mut proofs = vec![];
                let mut statements_private = vec![];
                let mut statements_public = vec![];
                #[allow(clippy::mutable_key_type)]
                let mut commitment_value_map_private = HashMap::new();

                #[allow(clippy::cast_possible_truncation)]
                let (value_min, value_max) = (0u64, ((1u128 << bit_length) - 1) as u64);
                for aggregation_size in AGGREGATION_SIZE {
                    // 1. Prover's service
                    let bulletproofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone()).unwrap();

                    // 2. Create witness data
                    let mut statements = vec![];
                    let mut extended_witnesses = vec![];
                    for m in 0..aggregation_size {
                        let value = rng.gen_range(value_min..value_max);
                        let minimum_value_promise = if m == 0 { value / 3 } else { 0 };
                        let secrets =
                            vec![RistrettoSecretKey(Scalar::random_not_zero(&mut rng)); extension_degree as usize];
                        let extended_mask = RistrettoExtendedMask::assign(extension_degree, secrets.clone()).unwrap();
                        let commitment = factory.commit_value_extended(&secrets, value).unwrap();
                        statements.push(RistrettoStatement {
                            commitment: commitment.clone(),
                            minimum_value_promise,
                        });
                        extended_witnesses.push(RistrettoExtendedWitness {
                            mask: extended_mask.clone(),
                            value,
                            minimum_value_promise,
                        });
                        if m == 0 {
                            if aggregation_size == 1 {
                                private_masks.push(Some(extended_mask));
                                public_masks.push(None);
                            } else {
                                private_masks.push(None);
                                public_masks.push(None);
                            }
                        }
                        commitment_value_map_private.insert(commitment, value);
                    }

                    // 3. Generate the statement
                    let seed_nonce = if aggregation_size == 1 {
                        Some(RistrettoSecretKey(Scalar::random_not_zero(&mut rng)))
                    } else {
                        None
                    };
                    statements_private.push(
                        RistrettoAggregatedPrivateStatement::init(statements.clone(), seed_nonce.clone()).unwrap(),
                    );
                    statements_public.push(RistrettoAggregatedPublicStatement::init(statements).unwrap());

                    // 4. Create the proof
                    let proof = bulletproofs_plus_service.construct_extended_proof(extended_witnesses, seed_nonce);
                    proofs.push(proof.unwrap());
                }

                if proofs.is_empty() {
                    panic!("Proofs cannot be empty");
                } else {
                    // 5. Verifier's service
                    let aggregation_factor = *AGGREGATION_SIZE.iter().max().unwrap();
                    let bulletproofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_factor, factory.clone()).unwrap();

                    // 6. Verify the entire batch as the commitment owner, i.e. the prover self
                    // --- Only recover the masks
                    for (i, proof) in proofs.iter().enumerate() {
                        let recovered_private_mask = bulletproofs_plus_service
                            .recover_extended_mask(proof, &statements_private[i])
                            .unwrap();
                        assert_eq!(private_masks[i], recovered_private_mask);
                        for statement in &statements_private[i].statements {
                            if let Some(this_mask) = recovered_private_mask.clone() {
                                assert!(bulletproofs_plus_service
                                    .verify_extended_mask(
                                        &statement.commitment,
                                        &this_mask,
                                        *commitment_value_map_private.get(&statement.commitment).unwrap()
                                    )
                                    .unwrap());
                            }
                        }
                    }
                    // --- Recover the masks and verify the proofs
                    let statements_ref = statements_private.iter().collect::<Vec<_>>();
                    let proofs_ref = proofs.iter().collect::<Vec<_>>();
                    let recovered_private_masks = bulletproofs_plus_service
                        .verify_batch_and_recover_masks(proofs_ref.clone(), statements_ref.clone())
                        .unwrap();
                    assert_eq!(private_masks, recovered_private_masks);
                    for (index, aggregated_statement) in statements_private.iter().enumerate() {
                        for statement in &aggregated_statement.statements {
                            if let Some(this_mask) = recovered_private_masks[index].clone() {
                                // Verify the recovered mask
                                assert!(bulletproofs_plus_service
                                    .verify_extended_mask(
                                        &statement.commitment,
                                        &this_mask,
                                        *commitment_value_map_private.get(&statement.commitment).unwrap()
                                    )
                                    .unwrap());

                                // Also verify that the extended commitment factory can open the commitment
                                assert!(factory
                                    .open_value_extended(
                                        &this_mask.secrets(),
                                        *commitment_value_map_private.get(&statement.commitment).unwrap(),
                                        &statement.commitment,
                                    )
                                    .unwrap());
                            }
                        }
                    }

                    // // 7. Verify the entire batch as public entity
                    let statements_ref = statements_public.iter().collect::<Vec<_>>();
                    assert!(bulletproofs_plus_service
                        .verify_batch(proofs_ref, statements_ref)
                        .is_ok());
                }
            }
        }
    }

    #[test]
    // Test correctness of single aggregated proofs of varying extension degree
    fn test_single_aggregated_extended_proof() {
        let mut rng = rand::thread_rng();

        const BIT_LENGTH: usize = 4;
        const AGGREGATION_FACTOR: usize = 2;

        for extension_degree in [
            CommitmentExtensionDegree::DefaultPedersen,
            CommitmentExtensionDegree::AddFiveBasePoints,
        ] {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let bulletproofs_plus_service =
                BulletproofsPlusService::init(BIT_LENGTH, AGGREGATION_FACTOR, factory.clone()).unwrap();

            let (value_min, value_max) = (0u64, (1u64 << BIT_LENGTH) - 1);

            let mut statements = Vec::with_capacity(AGGREGATION_FACTOR);
            let mut extended_witnesses = Vec::with_capacity(AGGREGATION_FACTOR);

            // Set up the statements and witnesses
            for _ in 0..AGGREGATION_FACTOR {
                let value = rng.gen_range(value_min..value_max);
                let minimum_value_promise = value / 3;
                let secrets = vec![RistrettoSecretKey(Scalar::random_not_zero(&mut rng)); extension_degree as usize];
                let extended_mask = RistrettoExtendedMask::assign(extension_degree, secrets.clone()).unwrap();
                let commitment = factory.commit_value_extended(&secrets, value).unwrap();

                statements.push(RistrettoStatement {
                    commitment: commitment.clone(),
                    minimum_value_promise,
                });
                extended_witnesses.push(RistrettoExtendedWitness {
                    mask: extended_mask.clone(),
                    value,
                    minimum_value_promise,
                });
            }

            // Aggregate the statements
            let aggregated_statement = RistrettoAggregatedPublicStatement::init(statements).unwrap();

            // Generate an aggregate proof
            let proof = bulletproofs_plus_service
                .construct_extended_proof(extended_witnesses, None)
                .unwrap();

            // Verify the proof
            assert!(bulletproofs_plus_service
                .verify_batch(vec![&proof], vec![&aggregated_statement])
                .is_ok());
        }
    }

    #[test]
    fn test_construct_verify_simple_extended_proof_with_recovery() {
        let bit_length = 64usize;
        let aggregation_size = 1usize;
        let extension_degree = CommitmentExtensionDegree::DefaultPedersen;
        let mut rng = rand::thread_rng();
        let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let (value_min, value_max) = (0u64, ((1u128 << bit_length) - 1) as u64);
        // 1. Prover's service
        let mut provers_bulletproofs_plus_service =
            BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone()).unwrap();
        provers_bulletproofs_plus_service.custom_transcript_label("123 range proof");

        // 2. Create witness data
        let value = rng.gen_range(value_min..value_max);
        let minimum_value_promise = value / 3;
        let secrets = vec![RistrettoSecretKey(Scalar::random_not_zero(&mut rng)); extension_degree as usize];
        let extended_mask = RistrettoExtendedMask::assign(extension_degree, secrets.clone()).unwrap();
        let commitment = factory.commit_value_extended(&secrets, value).unwrap();
        let extended_witness = RistrettoExtendedWitness {
            mask: extended_mask.clone(),
            value,
            minimum_value_promise,
        };
        let private_mask = Some(extended_mask);

        // 4. Create the proof
        let seed_nonce = Some(RistrettoSecretKey(Scalar::random_not_zero(&mut rng)));
        let proof = provers_bulletproofs_plus_service
            .construct_extended_proof(vec![extended_witness.clone()], seed_nonce.clone())
            .unwrap();

        // 5. Verifier's service
        let mut verifiers_bulletproofs_plus_service =
            BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone()).unwrap();

        // 6. Verify as the commitment owner, i.e. the prover self
        // --- Generate the private statement
        let statement_private = RistrettoAggregatedPrivateStatement::init(
            vec![RistrettoStatement {
                commitment: commitment.clone(),
                minimum_value_promise,
            }],
            seed_nonce,
        )
        .unwrap();
        // --- Only recover the mask (use the wrong transcript label for the service - will fail)
        let recovered_private_mask = verifiers_bulletproofs_plus_service
            .recover_extended_mask(&proof, &statement_private)
            .unwrap();
        assert_ne!(private_mask, recovered_private_mask);
        // --- Only recover the mask (use the correct transcript label for the service)
        verifiers_bulletproofs_plus_service.custom_transcript_label("123 range proof");
        let recovered_private_mask = verifiers_bulletproofs_plus_service
            .recover_extended_mask(&proof, &statement_private)
            .unwrap();
        assert_eq!(private_mask, recovered_private_mask);
        if let Some(this_mask) = recovered_private_mask {
            assert!(verifiers_bulletproofs_plus_service
                .verify_extended_mask(
                    &statement_private.statements[0].commitment,
                    &this_mask,
                    extended_witness.value,
                )
                .unwrap());
        } else {
            panic!("A mask should have been recovered!");
        }
        // --- Recover the masks and verify the proof
        let recovered_private_masks = verifiers_bulletproofs_plus_service
            .verify_batch_and_recover_masks(vec![&proof], vec![&statement_private])
            .unwrap();
        assert_eq!(vec![private_mask], recovered_private_masks);
        if let Some(this_mask) = recovered_private_masks[0].clone() {
            // Verify the recovered mask
            assert!(verifiers_bulletproofs_plus_service
                .verify_extended_mask(
                    &statement_private.statements[0].commitment,
                    &this_mask,
                    extended_witness.value,
                )
                .unwrap());

            // Also verify that the extended commitment factory can open the commitment
            assert!(factory
                .open_value_extended(
                    &this_mask.secrets(),
                    extended_witness.value,
                    &statement_private.statements[0].commitment,
                )
                .unwrap());
        } else {
            panic!("A mask should have been recovered!");
        }

        // // 7. Verify the proof as public entity
        let statement_public = RistrettoAggregatedPublicStatement::init(vec![RistrettoStatement {
            commitment,
            minimum_value_promise,
        }])
        .unwrap();
        assert!(verifiers_bulletproofs_plus_service
            .verify_batch(vec![&proof], vec![&statement_public])
            .is_ok());
    }

    #[test]
    fn test_construct_verify_simple_proof_with_recovery() {
        let bit_length = 64usize;
        let aggregation_size = 1usize;
        let extension_degree = CommitmentExtensionDegree::DefaultPedersen;
        let mut rng = rand::thread_rng();
        let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let (value_min, value_max) = (0u64, ((1u128 << bit_length) - 1) as u64);
        // 1. Prover's service
        let mut provers_bulletproofs_plus_service =
            BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone()).unwrap();
        provers_bulletproofs_plus_service.custom_transcript_label("123 range proof");

        // 2. Create witness data
        let value = rng.gen_range(value_min..value_max);
        let mask = RistrettoSecretKey(Scalar::random_not_zero(&mut rng));
        let commitment = factory.commit_value(&mask, value);

        // 4. Create the proof
        let seed_nonce = RistrettoSecretKey(Scalar::random_not_zero(&mut rng));
        let proof = provers_bulletproofs_plus_service
            .construct_proof_with_recovery_seed_nonce(&mask, value, &seed_nonce)
            .unwrap();

        // 5. Verifier's service
        let mut verifiers_bulletproofs_plus_service =
            BulletproofsPlusService::init(bit_length, aggregation_size, factory.clone()).unwrap();

        // 6. Mask recovery as the commitment owner, i.e. the prover self
        // --- Recover the mask (use the wrong transcript label for the service - will fail)
        let recovered_mask = verifiers_bulletproofs_plus_service
            .recover_mask(&proof, &commitment, &seed_nonce)
            .unwrap();
        assert_ne!(mask, recovered_mask);
        // --- Recover the mask (use the correct transcript label for the service)
        verifiers_bulletproofs_plus_service.custom_transcript_label("123 range proof");
        let recovered_mask = verifiers_bulletproofs_plus_service
            .recover_mask(&proof, &commitment, &seed_nonce)
            .unwrap();
        assert_eq!(mask, recovered_mask);
        // --- Verify that the mask opens the commitment
        assert!(verifiers_bulletproofs_plus_service
            .verify_mask(&commitment, &recovered_mask, value)
            .unwrap());
        // --- Also verify that the commitment factory can open the commitment
        assert!(factory.open_value(&recovered_mask, value, &commitment));

        // 7. Verify the proof as private or public entity
        assert!(verifiers_bulletproofs_plus_service.verify(&proof, &commitment));
    }
}
