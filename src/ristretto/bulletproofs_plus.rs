// Copyright 2019 The Tari Project
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

pub use bulletproofs_plus::ristretto::RistrettoRangeProof;
use bulletproofs_plus::{
    commitment_opening::CommitmentOpening,
    extended_mask::ExtendedMask as BulletproofsExtendedMask,
    generators::pedersen_gens::ExtensionDegree as BulletproofsExtensionDegree,
    range_parameters::RangeParameters,
    range_proof::RangeProof,
    range_statement::RangeStatement,
    range_witness::RangeWitness,
    PedersenGens,
};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use log::*;

use crate::{
    commitment::{ExtensionDegree as RistrettoExtensionDegree, HomomorphicCommitment},
    errors::RangeProofError,
    extended_range_proof,
    extended_range_proof::{ExtendedRangeProofService, ExtendedStatement},
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

pub type RistrettoExtendedMask = extended_range_proof::ExtendedMask<RistrettoSecretKey>;
pub type RistrettoExtendedStatement = ExtendedStatement<RistrettoSecretKey, RistrettoPublicKey>;
pub type BulletproofsPlusRistrettoPedersenGens = PedersenGens<RistrettoPoint>;

impl RistrettoExtendedMask {
    /// Helper function to converts a RistrettoExtendedMask to a BulletproofsExtendedMask
    #[allow(dead_code)]
    pub fn convert_to(&self) -> Result<BulletproofsExtendedMask, RangeProofError> {
        let extension_degree = BulletproofsExtensionDegree::try_from_size(self.blindings()?.len())
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))?;
        BulletproofsExtendedMask::assign(extension_degree, self.as_scalar()?)
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))
    }

    /// Helper function to converts a BulletproofsExtendedMask to a RistrettoExtendedMask
    pub fn convert_from(extended_mask: &BulletproofsExtendedMask) -> Result<Self, RangeProofError> {
        let blindings = extended_mask
            .blindings()
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))?;
        RistrettoExtendedMask::assign(
            RistrettoExtensionDegree::try_from_size(blindings.len())
                .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))?,
            blindings.iter().map(|k| RistrettoSecretKey(*k)).collect(),
        )
    }

    /// Return the blinding factor vector as a vector of Scalars
    pub fn as_scalar(&self) -> Result<Vec<Scalar>, RangeProofError> {
        Ok(self.blindings()?.iter().map(|k| k.0).collect())
    }
}

impl BulletproofsPlusService {
    /// Create a new BulletProofsPlusService containing the generators - this will err if each of 'bit_length' and
    /// 'aggregation_factor' is not a power of two
    #[allow(dead_code)]
    pub fn init(
        bit_length: usize,
        aggregation_factor: usize,
        pc_gens: ExtendedPedersenCommitmentFactory,
    ) -> Result<Self, RangeProofError> {
        Ok(Self {
            generators: RangeParameters::init(bit_length, aggregation_factor, BulletproofsPlusRistrettoPedersenGens {
                h_base: pc_gens.h_base,
                h_base_compressed: pc_gens.h_base_compressed,
                g_base_vec: pc_gens.g_base_vec,
                g_base_compressed_vec: pc_gens.g_base_compressed_vec,
                extension_degree: BulletproofsExtensionDegree::try_from_size(pc_gens.extension_degree as usize)
                    .map_err(|e| RangeProofError::InitializationError(e.to_string()))?,
            })
            .map_err(|e| RangeProofError::InitializationError(e.to_string()))?,
            transcript_label: "Tari Bulletproofs+",
        })
    }

    /// Use a custom domain separated transcript label
    #[allow(dead_code)]
    pub fn custom_transcript_label(&mut self, transcript_label: &'static str) {
        self.transcript_label = transcript_label;
    }

    /// Helper function to return the serialized proof's extension degree
    #[allow(dead_code)]
    pub fn extension_degree(serialized_proof: &[u8]) -> Result<RistrettoExtensionDegree, RangeProofError> {
        let extension_degree = RistrettoRangeProof::extension_degree_from_proof_bytes(serialized_proof)
            .map_err(|e| RangeProofError::InvalidRangeProof(e.to_string()))?;
        RistrettoExtensionDegree::try_from_size(extension_degree as usize)
            .map_err(|e| RangeProofError::InvalidRangeProof(e.to_string()))
    }

    /// Helper function to prepare a batch of range statements
    pub fn prepare_range_statements(
        &self,
        statements: Vec<&RistrettoExtendedStatement>,
        with_seed_nonce: bool,
    ) -> Vec<RangeStatement<RistrettoPoint>> {
        let mut range_statements = Vec::with_capacity(statements.len());
        for statement in statements {
            let seed_nonce: Option<Scalar> = if with_seed_nonce {
                statement.seed_nonce.as_ref().map(|n| n.0)
            } else {
                None
            };
            range_statements.push(RangeStatement {
                generators: self.generators.clone(),
                commitments: statement.commitments.iter().map(|c| c.0.point()).collect(),
                commitments_compressed: statement.commitments.iter().map(|c| *c.0.compressed()).collect(),
                minimum_value_promises: statement.minimum_value_promises.clone(),
                seed_nonce,
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
            match RistrettoRangeProof::from_bytes(*proof).map_err(|e| RangeProofError::InvalidRangeProof(e.to_string()))
            {
                Ok(rp) => {
                    range_proofs.push(rp);
                },
                Err(e) => {
                    return Err(RangeProofError::InvalidRangeProof(format!(
                        "Range proof at index '{}' could not be deserialized ({})",
                        i, e
                    )));
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
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        let opening = CommitmentOpening::new(value, vec![key.0]);
        let witness =
            RangeWitness::init(vec![opening]).map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        let statement = RangeStatement::init(self.generators.clone(), vec![commitment], vec![None], None)
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;

        let proof = RistrettoRangeProof::prove(self.transcript_label, &statement, &witness)
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;

        Ok(proof.to_bytes())
    }

    fn verify(&self, proof: &Self::Proof, commitment: &HomomorphicCommitment<Self::PK>) -> bool {
        return match RistrettoRangeProof::from_bytes(proof)
            .map_err(|e| RangeProofError::InvalidRangeProof(e.to_string()))
        {
            Ok(rp) => {
                let statement = RangeStatement {
                    generators: self.generators.clone(),
                    commitments: vec![commitment.0.clone().into()],
                    commitments_compressed: vec![*commitment.0.compressed()],
                    minimum_value_promises: vec![None],
                    seed_nonce: None,
                };
                match RistrettoRangeProof::verify_do_not_recover_masks(self.transcript_label, &[statement], &[
                    rp.clone()
                ]) {
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
        };
    }

    fn range(&self) -> usize {
        self.generators.bit_length()
    }
}

impl ExtendedRangeProofService for BulletproofsPlusService {
    type K = RistrettoSecretKey;
    type PK = RistrettoPublicKey;
    type Proof = Vec<u8>;

    fn construct_extended_proof(
        &self,
        masks: Vec<RistrettoExtendedMask>,
        values: Vec<u64>,
        min_value_promises: Vec<Option<u64>>,
        seed_nonce: Option<Self::K>,
    ) -> Result<Self::Proof, RangeProofError> {
        if masks.is_empty() || values.is_empty() || masks.len() != values.len() {
            return Err(RangeProofError::ProofConstructionError(
                "Keys and values vectors cannot be empty and must have consistent length".to_string(),
            ));
        }
        let mut commitments = Vec::with_capacity(values.len());
        let mut openings = Vec::with_capacity(values.len());
        for i in 0..values.len() {
            // let extended_mask: Vec<Scalar> = masks[i].blindings()?.iter().map(|k| k.0).collect();
            commitments.push(
                self.generators
                    .pc_gens()
                    .commit(&Scalar::from(values[i]), &masks[i].as_scalar()?)
                    .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?,
            );
            openings.push(CommitmentOpening::new(values[i], masks[i].as_scalar()?));
        }
        let witness =
            RangeWitness::init(openings).map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        let statement = RangeStatement::init(
            self.generators.clone(),
            commitments,
            min_value_promises,
            seed_nonce.map(|s| s.0),
        )
        .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;

        let proof = RistrettoRangeProof::prove(self.transcript_label, &statement, &witness)
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;

        Ok(proof.to_bytes())
    }

    fn verify_batch_and_recover_masks(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoExtendedStatement>,
    ) -> Result<Vec<Option<RistrettoExtendedMask>>, RangeProofError> {
        // Prepare the range statements
        let range_statements = self.prepare_range_statements(statements, true);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs)?;

        // Verify and recover
        let mut recovered_extended_masks = Vec::new();
        match RistrettoRangeProof::verify_and_recover_masks(self.transcript_label, &range_statements, &range_proofs) {
            Ok(recovered_masks) => {
                if recovered_masks.is_empty() {
                    // A mask vector should always be returned so this is a valid error condition
                    return Err(RangeProofError::InvalidRewind(
                        "Range proof(s) verified Ok, but no mask vector returned".to_string(),
                    ));
                } else {
                    for recovered_mask in recovered_masks {
                        if let Some(mask) = &recovered_mask {
                            recovered_extended_masks.push(Some(RistrettoExtendedMask::convert_from(mask)?));
                        } else {
                            recovered_extended_masks.push(None);
                        }
                    }
                }
            },
            Err(e) => {
                return Err(RangeProofError::InvalidRangeProof(format!(
                    "Internal range proof(s) error ({})",
                    e
                )))
            },
        };
        Ok(recovered_extended_masks)
    }

    fn verify_batch(
        &self,
        proofs: Vec<&Self::Proof>,
        statements: Vec<&RistrettoExtendedStatement>,
    ) -> Result<(), RangeProofError> {
        // Prepare the range statements
        let range_statements = self.prepare_range_statements(statements, false);

        // Deserialize the range proofs
        let range_proofs = self.deserialize_range_proofs(&proofs)?;

        // Verify
        match RistrettoRangeProof::verify_do_not_recover_masks(self.transcript_label, &range_statements, &range_proofs)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(RangeProofError::InvalidRangeProof(format!(
                "Internal range proof(s) error ({})",
                e
            ))),
        }
    }

    fn recover_mask(
        &self,
        proof: &Self::Proof,
        statement: &RistrettoExtendedStatement,
    ) -> Result<Option<RistrettoExtendedMask>, RangeProofError> {
        return match RistrettoRangeProof::from_bytes(proof)
            .map_err(|e| RangeProofError::InvalidRangeProof(e.to_string()))
        {
            Ok(rp) => {
                // Prepare the range statement
                let range_statements = self.prepare_range_statements(vec![statement], true);

                match RistrettoRangeProof::recover_masks_ony(self.transcript_label, &range_statements, &[rp]) {
                    Ok(recovered_mask) => {
                        if recovered_mask.is_empty() {
                            Ok(None)
                        } else if let Some(mask) = &recovered_mask[0] {
                            Ok(Some(RistrettoExtendedMask::convert_from(mask)?))
                        } else {
                            Ok(None)
                        }
                    },
                    Err(e) => Err(RangeProofError::InvalidRangeProof(format!(
                        "Internal range proof error ({})",
                        e
                    ))),
                }
            },
            Err(e) => Err(RangeProofError::InvalidRangeProof(format!(
                "Range proof could not be deserialized ({})",
                e
            ))),
        };
    }

    fn verify_mask(
        &self,
        commitment: &HomomorphicCommitment<Self::PK>,
        extended_mask: &RistrettoExtendedMask,
        value: u64,
    ) -> Result<bool, RangeProofError> {
        match self
            .generators
            .pc_gens()
            .commit(&Scalar::from(value), &extended_mask.as_scalar()?)
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))
        {
            Ok(val) => Ok(val == commitment.0.point()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{borrow::Borrow, collections::HashMap};

    use bulletproofs_plus::protocols::scalar_protocol::ScalarProtocol;
    use curve25519_dalek::scalar::Scalar;
    use rand::Rng;

    use crate::{
        commitment::{
            ExtendedHomomorphicCommitmentFactory,
            ExtensionDegree as RistrettoExtensionDegree,
            HomomorphicCommitmentFactory,
        },
        extended_range_proof::ExtendedRangeProofService,
        range_proof::RangeProofService,
        ristretto::{
            bulletproofs_plus::{BulletproofsPlusService, RistrettoExtendedMask, RistrettoExtendedStatement},
            pedersen::extended_commitment_factory::ExtendedPedersenCommitmentFactory,
            RistrettoSecretKey,
        },
    };

    static EXTENSION_DEGREE: [RistrettoExtensionDegree; 6] = [
        RistrettoExtensionDegree::DefaultPedersen,
        RistrettoExtensionDegree::AddOneBasePoint,
        RistrettoExtensionDegree::AddTwoBasePoints,
        RistrettoExtensionDegree::AddThreeBasePoints,
        RistrettoExtensionDegree::AddFourBasePoints,
        RistrettoExtensionDegree::AddFiveBasePoints,
    ];

    /// 'BulletproofsPlusService' initialization should only succeed when both bit length and aggregation size are a
    /// power of 2 and when bit_length <= 64
    #[test]
    fn test_service_init() {
        for extension_degree in EXTENSION_DEGREE {
            let pc_gens = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            for bit_length in [1, 2, 3, 4, 5, 64, 128] {
                for aggregation_size in [1, 2, 3, 4, 5, 64] {
                    let bullet_proofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_size, pc_gens.clone());
                    if bit_length.is_power_of_two() && aggregation_size.is_power_of_two() && bit_length <= 64 {
                        assert!(bullet_proofs_plus_service.is_ok());
                    } else {
                        assert!(bullet_proofs_plus_service.is_err());
                    }
                }
            }
        }
    }

    /// The 'BulletproofsPlusService' interface 'construct_proof' should only accept Pedersen generators of
    /// 'ExtensionDegree::Zero' with 'aggregation_size == 1' and values proportional to the bit length
    #[test]
    fn test_construct_verify_proof() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            let pc_gens = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            // bit length and aggregation size are chosen so that 'BulletProofsPlusService::init' will always succeed
            for bit_length in [2, 4, 64] {
                for aggregation_size in [1, 2, 16] {
                    let bulletproofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_size, pc_gens.clone()).unwrap();
                    for value in [0, 1, 10, u64::MAX] {
                        let key = RistrettoSecretKey(Scalar::random_not_zero(&mut rng));
                        let proof = bulletproofs_plus_service.construct_proof(&key, value);
                        if extension_degree == RistrettoExtensionDegree::DefaultPedersen &&
                            aggregation_size == 1 &&
                            value >> (bit_length - 1) <= 1
                        {
                            assert!(proof.is_ok());
                            assert!(bulletproofs_plus_service
                                .verify(&proof.unwrap(), pc_gens.commit_value(&key, value).borrow()));
                        } else {
                            assert!(proof.is_err());
                        }
                    }
                }
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_construct_verify_extended_proof() {
        static BIT_LENGTH: [usize; 2] = [2, 64];
        static AGGREGATION_SIZE: [usize; 2] = [2, 64];
        let mut rng = rand::thread_rng();
        for extension_degree in [
            RistrettoExtensionDegree::DefaultPedersen,
            RistrettoExtensionDegree::AddFiveBasePoints,
        ] {
            let pc_gens = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            // bit length and aggregation size are chosen so that 'BulletProofsPlusService::init' will always succeed
            for bit_length in BIT_LENGTH {
                // 0.  Batch data
                let mut private_masks: Vec<Option<RistrettoExtendedMask>> = vec![];
                let mut public_masks: Vec<Option<RistrettoExtendedMask>> = vec![];
                let mut proofs = vec![];
                let mut statements_private = vec![];
                let mut statements_public = vec![];
                #[allow(clippy::mutable_key_type)]
                let mut commitment_value_map_private = HashMap::new();

                #[allow(clippy::cast_possible_truncation)]
                let (value_min, value_max) = (0u64, (1u128 << (bit_length - 1)) as u64);
                for aggregation_size in AGGREGATION_SIZE {
                    // 1. Prover's service
                    let bulletproofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_size, pc_gens.clone()).unwrap();

                    // 2. Create witness data
                    let mut masks = vec![];
                    let mut values = vec![];
                    let mut min_value_promises = vec![];
                    let mut commitments = vec![];
                    for m in 0..aggregation_size {
                        let value = rng.gen_range(value_min..value_max);
                        values.push(value);
                        if m == 0 {
                            min_value_promises.push(Some(value / 3));
                        } else {
                            min_value_promises.push(None);
                        }
                        let blindings =
                            vec![RistrettoSecretKey(Scalar::random_not_zero(&mut rng)); extension_degree as usize];
                        let extended_mask = RistrettoExtendedMask::assign(extension_degree, blindings.clone()).unwrap();
                        masks.push(extended_mask.clone());
                        let commitment = pc_gens.commit_value_extended(&blindings, value).unwrap();
                        commitments.push(commitment.clone());
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
                        RistrettoExtendedStatement::init(
                            commitments.clone(),
                            min_value_promises.clone(),
                            seed_nonce.clone(),
                        )
                        .unwrap(),
                    );
                    statements_public
                        .push(RistrettoExtendedStatement::init(commitments, min_value_promises.clone(), None).unwrap());

                    // 4. Create the proof
                    let proof = bulletproofs_plus_service.construct_extended_proof(
                        masks,
                        values,
                        min_value_promises,
                        seed_nonce,
                    );
                    proofs.push(proof.unwrap());
                }

                if proofs.is_empty() {
                    panic!("Proofs cannot be empty");
                } else {
                    // 5. Verifier's service
                    let aggregation_factor = *AGGREGATION_SIZE.iter().max().unwrap();
                    let bulletproofs_plus_service =
                        BulletproofsPlusService::init(bit_length, aggregation_factor, pc_gens.clone()).unwrap();

                    // 6. Verify the entire batch as the commitment owner, i.e. the prover self
                    // --- Only recover the masks
                    for (i, proof) in proofs.iter().enumerate() {
                        let recovered_private_mask = bulletproofs_plus_service
                            .recover_mask(proof, &statements_private[i])
                            .unwrap();
                        assert_eq!(private_masks[i], recovered_private_mask);
                        for commitment in &statements_private[i].commitments {
                            if let Some(this_mask) = recovered_private_mask.clone() {
                                assert!(bulletproofs_plus_service
                                    .verify_mask(
                                        commitment,
                                        &this_mask,
                                        *commitment_value_map_private.get(commitment).unwrap()
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
                    for (index, statement) in statements_private.iter().enumerate() {
                        for commitment in &statement.commitments {
                            if let Some(this_mask) = recovered_private_masks[index].clone() {
                                assert!(bulletproofs_plus_service
                                    .verify_mask(
                                        commitment,
                                        &this_mask,
                                        *commitment_value_map_private.get(commitment).unwrap()
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
}
