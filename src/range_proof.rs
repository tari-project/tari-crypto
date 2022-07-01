// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Range proofs are used to determine if a value lies inside a particular range. Most commonly, we
//! want to prove in zero knowledge that a value is non-negative.

use crate::{
    commitment::HomomorphicCommitment,
    errors::RangeProofError,
    keys::{PublicKey, SecretKey},
};

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
}
