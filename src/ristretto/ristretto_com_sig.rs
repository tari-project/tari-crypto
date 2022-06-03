// Copyright 2021 The Tari Project
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
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::CommitmentSignature,
};

/// # A Commitment signature implementation on Ristretto
///
/// `RistrettoComSig` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide Commitment Signature functionality utlizing Schnorr signatures.
///
/// ## Examples
///
/// You can create a `RistrettoComSig` from it's component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let r_pub =
///     HomomorphicCommitment::from_hex("8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19").unwrap();
/// let u = RistrettoSecretKey::from_bytes(b"10000000000000000000000010000000").unwrap();
/// let v = RistrettoSecretKey::from_bytes(b"a00000000000000000000000a0000000").unwrap();
/// let sig = RistrettoComSig::new(r_pub, u, v);
/// ```
///
/// or you can create a signature for a commitment by signing a message with knowledge of the commitment and then
/// verify it by calling the `verify_challenge` method:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::common::*;
/// # use digest::Digest;
/// # use tari_crypto::commitment::HomomorphicCommitmentFactory;
/// # use tari_crypto::ristretto::pedersen::*;
/// use tari_crypto::ristretto::pedersen::commitment_factory::PedersenCommitmentFactory;
/// use tari_utilities::hex::Hex;
///
/// let mut rng = rand::thread_rng();
/// let a_val = RistrettoSecretKey::random(&mut rng);
/// let x_val = RistrettoSecretKey::random(&mut rng);
/// let a_nonce = RistrettoSecretKey::random(&mut rng);
/// let x_nonce = RistrettoSecretKey::random(&mut rng);
/// let e = Blake256::digest(b"Maskerade");
/// let factory = PedersenCommitmentFactory::default();
/// let commitment = factory.commit(&x_val, &a_val);
/// // println!("commitment: {:?}", commitment.to_hex());
/// let sig = RistrettoComSig::sign(&a_val, &x_val, &a_nonce, &x_nonce, &e, &factory).unwrap();
/// // println!("sig: R {:?} u {:?} v {:?}", sig.public_nonce().to_hex(), sig.u().to_hex(), sig.v().to_hex());
/// assert!(sig.verify_challenge(&commitment, &e, &factory));
/// ```
///
/// # Verifying signatures
///
/// Given a signature, (R,u,v), a commitment C and a Challenge, e, you can verify that the signature is valid by
/// calling the `verify_challenge` method:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_crypto::ristretto::pedersen::*;
/// # use tari_crypto::common::*;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
/// use tari_crypto::ristretto::pedersen::commitment_factory::PedersenCommitmentFactory;
///
/// let commitment =
///     HomomorphicCommitment::from_hex("d6cca5cc4cc302c1854a118221d6cf64d100b7da76665dae5199368f3703c665").unwrap();
/// let r_nonce =
///     HomomorphicCommitment::from_hex("9607f72d84d704825864a4455c2325509ecc290eb9419bbce7ff05f1f578284c").unwrap();
/// let u = RistrettoSecretKey::from_hex("0fd60e6479507fec35a46d2ec9da0ae300e9202e613e99b8f2b01d7ef6eccc02").unwrap();
/// let v = RistrettoSecretKey::from_hex("9ae6621dd99ecc252b90a0eb69577c6f3d2e1e8abcdd43bfd0297afadf95fb0b").unwrap();
/// let sig = RistrettoComSig::new(r_nonce, u, v);
/// let e = Blake256::digest(b"Maskerade");
/// let factory = PedersenCommitmentFactory::default();
/// assert!(sig.verify_challenge(&commitment, &e, &factory));
/// ```
pub type RistrettoComSig = CommitmentSignature<RistrettoPublicKey, RistrettoSecretKey>;

#[cfg(test)]
mod test {
    use digest::Digest;
    use tari_utilities::{hex::from_hex, ByteArray};

    use crate::{
        commitment::HomomorphicCommitmentFactory,
        common::Blake256,
        keys::{PublicKey, SecretKey},
        ristretto::{
            pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
            RistrettoComSig,
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    #[test]
    fn default() {
        let sig = RistrettoComSig::default();
        let commitment = PedersenCommitment::default();
        let (_, sig_1, sig_2) = sig.complete_signature_tuple();
        assert_eq!(
            (sig_1, sig_2),
            (&RistrettoSecretKey::default(), &RistrettoSecretKey::default())
        );
        assert_eq!(sig.public_nonce(), &commitment);
    }

    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        let mut rng = rand::thread_rng();
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let factory = PedersenCommitmentFactory::default();
        let commitment = factory.commit(&x_value, &a_value);

        let k_1 = RistrettoSecretKey::random(&mut rng);
        let k_2 = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment = factory.commit(&k_1, &k_2);

        let challenge = Blake256::new()
            .chain(commitment.as_bytes())
            .chain(nonce_commitment.as_bytes())
            .chain(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_bytes(&challenge).unwrap();
        let u_value = &k_1 + e_key.clone() * &x_value;
        let v_value = &k_2 + e_key * &a_value;
        let sig = RistrettoComSig::sign(&a_value, &x_value, &k_2, &k_1, &challenge, &factory).unwrap();
        let R_calc = sig.public_nonce();
        assert_eq!(nonce_commitment, *R_calc);
        let (_, sig_1, sig_2) = sig.complete_signature_tuple();
        assert_eq!((sig_1, sig_2), (&u_value, &v_value));
        assert!(sig.verify_challenge(&commitment, &challenge, &factory));
        // Doesn't work for invalid credentials
        assert!(!sig.verify_challenge(&nonce_commitment, &challenge, &factory));
        // Doesn't work for different challenge
        let wrong_challenge = Blake256::digest(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&commitment, &wrong_challenge, &factory));
    }

    /// This test checks that the linearity of commitment Schnorr signatures hold, i.e. that s = s1 + s2 is validated by
    /// R1 + R2 and C1 + C2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();
        // Alice generate some keys and nonces
        let a_value_alice = RistrettoSecretKey::random(&mut rng);
        let x_value_alice = RistrettoSecretKey::random(&mut rng);
        let commitment_alice = factory.commit(&x_value_alice, &a_value_alice);
        let k_1_alice = RistrettoSecretKey::random(&mut rng);
        let k_2_alice = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment_alice = factory.commit(&k_1_alice, &k_2_alice);
        // Alice generate some keys and nonces
        let a_value_bob = RistrettoSecretKey::random(&mut rng);
        let x_value_bob = RistrettoSecretKey::random(&mut rng);
        let commitment_bob = factory.commit(&x_value_bob, &a_value_bob);
        let k_1_bob = RistrettoSecretKey::random(&mut rng);
        let k_2_bob = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment_bob = factory.commit(&k_1_bob, &k_2_bob);
        // Each of them creates the Challenge committing to both commitments of both parties
        let challenge = Blake256::new()
            .chain(commitment_alice.as_bytes())
            .chain(commitment_bob.as_bytes())
            .chain(nonce_commitment_alice.as_bytes())
            .chain(nonce_commitment_bob.as_bytes())
            .chain(b"Moving Pictures")
            .finalize();
        // Calculate Alice's signature
        let sig_alice = RistrettoComSig::sign(
            &a_value_alice,
            &x_value_alice,
            &k_2_alice,
            &k_1_alice,
            &challenge,
            &factory,
        )
        .unwrap();
        // Calculate Bob's signature
        let sig_bob =
            RistrettoComSig::sign(&a_value_bob, &x_value_bob, &k_2_bob, &k_1_bob, &challenge, &factory).unwrap();
        // Now add the two signatures together
        let s_agg = &sig_alice + &sig_bob;
        // Check that the multi-sig verifies
        let combined_commitment = &commitment_alice + &commitment_bob;
        assert!(s_agg.verify_challenge(&combined_commitment, &challenge, &factory));
    }

    /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    /// signed as a result of applying modulo arithmetic on the challenge value
    #[test]
    fn challenge_from_invalid_scalar() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let message = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        let k_1 = RistrettoSecretKey::random(&mut rng);
        let k_2 = RistrettoSecretKey::random(&mut rng);
        assert!(RistrettoComSig::sign(&a_value, &x_value, &k_2, &k_1, &message, &factory).is_ok());
    }

    #[test]
    fn to_vec() {
        let sig = RistrettoComSig::default();
        let bytes = sig.to_vec();

        assert_eq!(
            bytes.capacity(),
            RistrettoPublicKey::key_length() + RistrettoSecretKey::key_length() * 2
        );
        assert_eq!(bytes.capacity(), bytes.len());
        assert!(bytes.iter().all(|b| *b == 0x00));
    }
}
