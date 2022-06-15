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

use bulletproofs::{
    range_proof::{get_rewind_nonce_from_pub_key, get_secret_nonce_from_pvt_key},
    BulletproofGens,
    PedersenGens,
    RangeProof as DalekProof,
};
use merlin::Transcript;

use crate::{
    errors::RangeProofError,
    keys::PublicKey,
    range_proof::RangeProofService,
    rewindable_range_proof::{FullRewindResult, RewindResult, RewindableRangeProofService, REWIND_USER_MESSAGE_LENGTH},
    ristretto::{
        pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

/// A wrapper around the Dalek library implementation of Bulletproof range proofs.
pub struct DalekRangeProofService {
    range: usize,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

const MASK: usize = 0b111_1000; // Mask for 8,16,32,64; the valid ranges on the Dalek library
pub const REWIND_PROOF_MESSAGE_LENGTH: usize = 23;
pub const REWIND_CHECK_MESSAGE: &[u8; 2] = b"TR";

impl DalekRangeProofService {
    /// Create a new RangeProofService. The Dalek library can only generate proofs for ranges between [0; 2^range),
    /// where valid range values are 8, 16, 32 and 64.
    pub fn new(range: usize, base: &PedersenCommitmentFactory) -> Result<DalekRangeProofService, RangeProofError> {
        if range == 0 || (range | MASK != MASK) {
            return Err(RangeProofError::InitializationError("Range not valid".to_string()));
        }
        let pc_gens = PedersenGens {
            B_blinding: base.G,
            B: base.H,
        };
        let bp_gens = BulletproofGens::new(range, 1);
        Ok(DalekRangeProofService {
            range,
            pc_gens,
            bp_gens,
        })
    }
}

impl RangeProofService for DalekRangeProofService {
    type K = RistrettoSecretKey;
    type PK = RistrettoPublicKey;
    type Proof = Vec<u8>;

    fn construct_proof(&self, key: &RistrettoSecretKey, value: u64) -> Result<Vec<u8>, RangeProofError> {
        let mut pt = Transcript::new(b"tari");
        let k = key.0;
        let (proof, _) = DalekProof::prove_single(&self.bp_gens, &self.pc_gens, &mut pt, value, &k, self.range)
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        Ok(proof.to_bytes())
    }

    fn verify(&self, proof: &Self::Proof, commitment: &PedersenCommitment) -> bool {
        let rp = DalekProof::from_bytes(proof).map_err(|_| RangeProofError::InvalidProof);
        if rp.is_err() {
            return false;
        }
        let rp = rp.unwrap();
        let mut pt = Transcript::new(b"tari");
        let c = &commitment.0;
        rp.verify_single(&self.bp_gens, &self.pc_gens, &mut pt, c.compressed(), self.range)
            .is_ok()
    }

    fn range(&self) -> usize {
        self.range
    }
}

impl RewindableRangeProofService for DalekRangeProofService {
    type K = RistrettoSecretKey;
    type PK = RistrettoPublicKey;
    type Proof = Vec<u8>;

    fn construct_proof_with_rewind_key(
        &self,
        key: &RistrettoSecretKey,
        value: u64,
        rewind_key: &RistrettoSecretKey,
        rewind_blinding_key: &RistrettoSecretKey,
        proof_message: &[u8; REWIND_USER_MESSAGE_LENGTH],
    ) -> Result<Vec<u8>, RangeProofError> {
        let mut pt = Transcript::new(b"tari");
        let mut full_proof_message = [0u8; REWIND_PROOF_MESSAGE_LENGTH];
        full_proof_message[0..REWIND_CHECK_MESSAGE.len()].clone_from_slice(REWIND_CHECK_MESSAGE);
        full_proof_message[REWIND_CHECK_MESSAGE.len()..].clone_from_slice(proof_message);

        let k = key.0;
        let rk = rewind_key.0;
        let rbk = rewind_blinding_key.0;
        let (proof, _) = DalekProof::prove_single_with_rewind_key(
            &self.bp_gens,
            &self.pc_gens,
            &mut pt,
            value,
            &k,
            self.range,
            &rk,
            &rbk,
            &full_proof_message,
        )
        .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        Ok(proof.to_bytes())
    }

    fn rewind_proof_value_only(
        &self,
        proof: &Self::Proof,
        commitment: &PedersenCommitment,
        rewind_public_key: &RistrettoPublicKey,
        rewind_blinding_public_key: &RistrettoPublicKey,
    ) -> Result<RewindResult, RangeProofError> {
        let rp = DalekProof::from_bytes(proof).map_err(|_| RangeProofError::InvalidProof)?;

        let mut pt = Transcript::new(b"tari");
        let rewind_nonce_1 =
            get_rewind_nonce_from_pub_key(rewind_public_key.compressed(), commitment.as_public_key().compressed());
        let rewind_nonce_2 = get_rewind_nonce_from_pub_key(
            rewind_blinding_public_key.compressed(),
            commitment.as_public_key().compressed(),
        );
        let (confidential_value, proof_message) = rp
            .rewind_single_get_value_only(
                &self.bp_gens,
                &mut pt,
                commitment.as_public_key().compressed(),
                self.range,
                &rewind_nonce_1,
                &rewind_nonce_2,
            )
            .map_err(|e| RangeProofError::ProofConstructionError(e.to_string()))?;
        if &proof_message[..REWIND_CHECK_MESSAGE.len()] != REWIND_CHECK_MESSAGE {
            return Err(RangeProofError::InvalidRewind(
                "Rewind check message length".to_string(),
            ));
        }
        let mut truncated_proof_message: [u8; REWIND_USER_MESSAGE_LENGTH] = [0u8; REWIND_USER_MESSAGE_LENGTH];
        truncated_proof_message.copy_from_slice(&proof_message[REWIND_CHECK_MESSAGE.len()..]);
        Ok(RewindResult::new(confidential_value, truncated_proof_message))
    }

    fn rewind_proof_commitment_data(
        &self,
        proof: &Self::Proof,
        commitment: &PedersenCommitment,
        rewind_key: &RistrettoSecretKey,
        rewind_blinding_key: &RistrettoSecretKey,
    ) -> Result<FullRewindResult<RistrettoSecretKey>, RangeProofError> {
        let rp = DalekProof::from_bytes(proof).map_err(|_| RangeProofError::InvalidProof)?;

        let mut pt = Transcript::new(b"tari");
        let rewind_public_key = RistrettoPublicKey::from_secret_key(rewind_key);
        let rewind_blinding_public_key = RistrettoPublicKey::from_secret_key(rewind_blinding_key);
        let rewind_nonce_1 =
            get_rewind_nonce_from_pub_key(rewind_public_key.compressed(), commitment.as_public_key().compressed());
        let rewind_nonce_2 = get_rewind_nonce_from_pub_key(
            rewind_blinding_public_key.compressed(),
            commitment.as_public_key().compressed(),
        );
        let blinding_nonce_1 = get_secret_nonce_from_pvt_key(&rewind_key.0, commitment.as_public_key().compressed());
        let blinding_nonce_2 =
            get_secret_nonce_from_pvt_key(&rewind_blinding_key.0, commitment.as_public_key().compressed());
        let (confidential_value, blinding_factor, proof_message) = rp
            .rewind_single_get_commitment_data(
                &self.bp_gens,
                &self.pc_gens,
                &mut pt,
                commitment.as_public_key().compressed(),
                self.range,
                &rewind_nonce_1,
                &rewind_nonce_2,
                &blinding_nonce_1,
                &blinding_nonce_2,
            )
            .map_err(|e| RangeProofError::InvalidRewind(e.to_string()))?;

        let mut truncated_proof_message: [u8; REWIND_USER_MESSAGE_LENGTH] = [0u8; REWIND_USER_MESSAGE_LENGTH];
        truncated_proof_message.copy_from_slice(&proof_message[REWIND_CHECK_MESSAGE.len()..]);
        Ok(FullRewindResult::new(
            confidential_value,
            truncated_proof_message,
            RistrettoSecretKey(blinding_factor),
        ))
    }
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use crate::{
        commitment::HomomorphicCommitmentFactory,
        errors::RangeProofError,
        keys::{PublicKey, SecretKey},
        range_proof::RangeProofService,
        rewindable_range_proof::RewindableRangeProofService,
        ristretto::{
            dalek_range_proof::DalekRangeProofService,
            pedersen::commitment_factory::PedersenCommitmentFactory,
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    #[test]
    fn create_and_verify_proof() {
        let base = PedersenCommitmentFactory::default();
        let n: usize = 5;
        let prover = DalekRangeProofService::new(1 << 5, &base).unwrap();
        let mut rng = thread_rng();
        let k = RistrettoSecretKey::random(&mut rng);
        let v = RistrettoSecretKey::from(42);
        let commitment_factory: PedersenCommitmentFactory = PedersenCommitmentFactory::default();
        let c = commitment_factory.commit(&k, &v);
        let proof = prover.construct_proof(&k, 42).unwrap();
        assert_eq!(proof.len(), (2 * n + 9) * 32);
        assert!(prover.verify(&proof, &c));
        // Invalid value
        let v2 = RistrettoSecretKey::from(43);
        let c = commitment_factory.commit(&k, &v2);
        assert!(!prover.verify(&proof, &c));
        // Invalid key
        let k = RistrettoSecretKey::random(&mut rng);
        let c = commitment_factory.commit(&k, &v);
        assert!(!prover.verify(&proof, &c));
        // Both invalid
        let c = commitment_factory.commit(&k, &v2);
        assert!(!prover.verify(&proof, &c));
    }

    #[test]
    fn create_and_rewind_proof() {
        let base = PedersenCommitmentFactory::default();

        let prover = DalekRangeProofService::new(1 << 5, &base).unwrap();
        let mut rng = thread_rng();
        let k = RistrettoSecretKey::random(&mut rng);
        let v = RistrettoSecretKey::from(42);

        let rewind_k = RistrettoSecretKey::random(&mut rng);
        let rewind_blinding_k = RistrettoSecretKey::random(&mut rng);
        let random_k = RistrettoSecretKey::random(&mut rng);

        let public_rewind_k = RistrettoPublicKey::from_secret_key(&rewind_k);
        let public_rewind_blinding_k = RistrettoPublicKey::from_secret_key(&rewind_blinding_k);
        let public_random_k = RistrettoPublicKey::from_secret_key(&random_k);

        let commitment_factory: PedersenCommitmentFactory = PedersenCommitmentFactory::default();
        let c = commitment_factory.commit(&k, &v);
        let message = b"testing12345678910111";
        let proof = prover
            .construct_proof_with_rewind_key(&k, 42, &rewind_k, &rewind_blinding_k, message)
            .unwrap();

        // test Debug impl
        assert!(!format!("{:?}", proof).is_empty());
        assert_eq!(
            prover.rewind_proof_value_only(&proof, &c, &public_random_k, &public_rewind_blinding_k),
            Err(RangeProofError::InvalidRewind(
                "Rewind check message length".to_string()
            ))
        );
        assert_eq!(
            prover.rewind_proof_value_only(&proof, &c, &public_rewind_k, &public_random_k),
            Err(RangeProofError::InvalidRewind(
                "Rewind check message length".to_string()
            ))
        );

        let rewind_result = prover
            .rewind_proof_value_only(&proof, &c, &public_rewind_k, &public_rewind_blinding_k)
            .unwrap();
        assert_eq!(rewind_result.committed_value, 42);
        assert_eq!(&rewind_result.proof_message, message);
        // test Debug impl
        assert!(!format!("{:?}", rewind_result).is_empty());

        assert_eq!(
            prover.rewind_proof_commitment_data(&proof, &c, &random_k, &rewind_blinding_k),
            Err(RangeProofError::InvalidRewind(
                "Rewinding the proof failed, invalid commitment extracted".to_string()
            ))
        );
        assert_eq!(
            prover.rewind_proof_commitment_data(&proof, &c, &rewind_k, &random_k),
            Err(RangeProofError::InvalidRewind(
                "Rewinding the proof failed, invalid commitment extracted".to_string()
            ))
        );

        let full_rewind_result = prover
            .rewind_proof_commitment_data(&proof, &c, &rewind_k, &rewind_blinding_k)
            .unwrap();
        assert_eq!(full_rewind_result.committed_value, 42);
        assert_eq!(&full_rewind_result.proof_message, message);
        assert_eq!(full_rewind_result.blinding_factor, k);
        // test Debug impl
        assert!(!format!("{:?}", full_rewind_result).is_empty());
    }

    #[test]
    fn non_power_of_two_range() {
        let base = PedersenCommitmentFactory::default();
        let _error = RangeProofError::InitializationError("Range not valid".to_string());
        assert!(matches!(DalekRangeProofService::new(10, &base), Err(_error)));
    }

    #[test]
    fn cannot_create_proof_for_out_of_range_value() {
        let base = PedersenCommitmentFactory::default();
        let prover = DalekRangeProofService::new(8, &base).unwrap();
        let in_range = 255;
        let out_of_range = 256;
        let mut rng = thread_rng();
        let k = RistrettoSecretKey::random(&mut rng);
        // Test with value in range
        let v = RistrettoSecretKey::from(in_range);
        let commitment_factory = PedersenCommitmentFactory::default();
        let c = commitment_factory.commit(&k, &v);
        let proof = prover.construct_proof(&k, in_range).unwrap();
        assert!(prover.verify(&proof, &c));
        // Test value out of range
        let proof = prover.construct_proof(&k, out_of_range).unwrap();
        // Test every single value from 0..255 - the proof should fail for every one
        for i in 0..257 {
            let v = RistrettoSecretKey::from(i);
            let c = commitment_factory.commit(&k, &v);
            assert!(!prover.verify(&proof, &c));
        }
    }
}
