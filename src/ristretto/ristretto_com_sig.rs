// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

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
/// You can create a `RistrettoComSig` from its component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let r_pub = HomomorphicCommitment::from_hex(
///     "8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19",
/// )
/// .unwrap();
/// let u = RistrettoSecretKey::from_hex(
///     "a8fb609c5ab7cc07548b076b6c25cc3237c4526fb7a6dcb83b26f457b172c20a",
/// )
/// .unwrap();
/// let v = RistrettoSecretKey::from_hex(
///     "0e689df8ad4ad9d2fd5aaf8cb0a66d85cb0d4b7a380405514d453625813b0b0f",
/// )
/// .unwrap();
/// let sig = RistrettoComSig::new(r_pub, u, v);
/// ```
///
/// or you can create a signature for a commitment by signing a message with knowledge of the commitment and then
/// verify it by calling the `verify_challenge` method:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use digest::Digest;
/// # use tari_crypto::commitment::HomomorphicCommitmentFactory;
/// # use tari_crypto::ristretto::pedersen::*;
/// use blake2::Blake2b;
/// use digest::consts::U64;
/// use tari_crypto::ristretto::pedersen::commitment_factory::PedersenCommitmentFactory;
/// use tari_utilities::hex::Hex;
///
/// let mut rng = rand::rng();
/// let a_val = RistrettoSecretKey::random(&mut rng);
/// let x_val = RistrettoSecretKey::random(&mut rng);
/// let a_nonce = RistrettoSecretKey::random(&mut rng);
/// let x_nonce = RistrettoSecretKey::random(&mut rng);
/// let e = Blake2b::<U64>::digest(b"Maskerade");
/// let factory = PedersenCommitmentFactory::default();
/// let commitment = factory.commit(&x_val, &a_val);
/// let sig = RistrettoComSig::sign(&a_val, &x_val, &a_nonce, &x_nonce, &e, &factory).unwrap();
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
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
/// use blake2::Blake2b;
/// use digest::consts::U64;
/// use tari_crypto::ristretto::pedersen::commitment_factory::PedersenCommitmentFactory;
///
/// let commitment = HomomorphicCommitment::from_hex(
///     "869b83416643258f1e03d028b5d0c652dc5b09decdae4a645fc5a43d87bd0a3e",
/// )
/// .unwrap();
/// let r_nonce = HomomorphicCommitment::from_hex(
///     "665400676bdf8b07679629f703ea86e9cfc7e145f0768d2fdde4bd257009260d",
/// )
/// .unwrap();
/// let u = RistrettoSecretKey::from_hex(
///     "f62fccf7734099d32937f7f767757abcb6eca70f43b3a7fb6500b2cb9ea12b02",
/// )
/// .unwrap();
/// let v = RistrettoSecretKey::from_hex(
///     "cb9e34a7745cabaec0f9b2c3e217bf18fbe7ee8f4c83c1a523cead32ec9b4700",
/// )
/// .unwrap();
/// let sig = RistrettoComSig::new(r_nonce, u, v);
/// let e = Blake2b::<U64>::digest(b"Maskerade");
/// let factory = PedersenCommitmentFactory::default();
/// assert!(sig.verify_challenge(&commitment, &e, &factory));
/// ```
pub type RistrettoComSig = CommitmentSignature<RistrettoPublicKey, RistrettoSecretKey>;

#[cfg(test)]
mod test {
    use blake2::Blake2b;
    use digest::{Digest, consts::U64};
    use rand_core::Rng;
    use tari_utilities::ByteArray;

    use crate::{
        commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
        keys::{PublicKey, SecretKey},
        ristretto::{
            RistrettoComSig,
            RistrettoPublicKey,
            RistrettoSecretKey,
            pedersen::{PedersenCommitment, commitment_factory::PedersenCommitmentFactory},
        },
        signatures::{CommitmentSigChallenge, CommitmentSignatureError},
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
        let mut rng = rand::rng();
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let factory = PedersenCommitmentFactory::default();
        let commitment = factory.commit(&x_value, &a_value);

        let k_1 = RistrettoSecretKey::random(&mut rng);
        let k_2 = RistrettoSecretKey::random(&mut rng);
        let nonce_commitment = factory.commit(&k_1, &k_2);

        let challenge = Blake2b::<U64>::new()
            .chain_update(commitment.as_bytes())
            .chain_update(nonce_commitment.as_bytes())
            .chain_update(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_uniform_bytes(&challenge).unwrap();
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
        let wrong_challenge = Blake2b::<U64>::digest(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&commitment, &wrong_challenge, &factory));
    }

    /// This test checks that the linearity of commitment Schnorr signatures hold, i.e. that s = s1 + s2 is validated by
    /// R1 + R2 and C1 + C2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::rng();
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
        let challenge = Blake2b::<U64>::new()
            .chain_update(commitment_alice.as_bytes())
            .chain_update(commitment_bob.as_bytes())
            .chain_update(nonce_commitment_alice.as_bytes())
            .chain_update(nonce_commitment_bob.as_bytes())
            .chain_update(b"Moving Pictures")
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

    #[test]
    fn zero_commitment() {
        let mut rng = rand::rng();
        let factory = PedersenCommitmentFactory::default();

        // Generate a zero commitment opening
        let secret_a = RistrettoSecretKey::default();
        let secret_x = RistrettoSecretKey::default();
        let commitment = factory.commit(&secret_x, &secret_a);
        assert_eq!(commitment, HomomorphicCommitment::<RistrettoPublicKey>::default());

        // Generate a signature with the zero opening
        let mut challenge = [0u8; RistrettoSecretKey::WIDE_REDUCTION_LEN];
        rng.fill_bytes(&mut challenge);
        let sig = RistrettoComSig::sign(
            &secret_a,
            &secret_x,
            &RistrettoSecretKey::random(&mut rng),
            &RistrettoSecretKey::random(&mut rng),
            &challenge,
            &factory,
        )
        .unwrap();

        // The signature should fail to verify
        assert!(!sig.verify_challenge(&commitment, &challenge, &factory));
    }

    #[test]
    fn zero_challenge_is_rejected() {
        let mut rng = rand::rng();
        let factory = PedersenCommitmentFactory::default();
        let a = RistrettoSecretKey::random(&mut rng);
        let x = RistrettoSecretKey::random(&mut rng);
        let commitment = factory.commit(&x, &a);
        let zero = [0u8; RistrettoSecretKey::WIDE_REDUCTION_LEN];

        let nonce_a = RistrettoSecretKey::random(&mut rng);
        let nonce_x = RistrettoSecretKey::random(&mut rng);
        assert!(RistrettoComSig::sign(&a, &x, &nonce_a, &nonce_x, &zero, &factory).is_err());

        // With e = 0 the equation is commit(u, v) == R, which holds for R = commit(u, v) regardless of C
        let u = RistrettoSecretKey::random(&mut rng);
        let v = RistrettoSecretKey::random(&mut rng);
        let sig = RistrettoComSig::new(factory.commit(&u, &v), u, v);
        assert!(!sig.verify(&commitment, &RistrettoSecretKey::default(), &factory));
        assert!(!sig.verify_challenge(&commitment, &zero, &factory));
    }

    #[test]
    fn sign_and_verify_bound_message() {
        let mut rng = rand::rng();
        let factory = PedersenCommitmentFactory::default();
        let a = RistrettoSecretKey::random(&mut rng);
        let x = RistrettoSecretKey::random(&mut rng);
        let commitment = factory.commit(&x, &a);
        let message = b"Night Watch";

        let sig = RistrettoComSig::sign_message(&a, &x, &commitment, message, &factory, &mut rng).unwrap();
        assert!(sig.verify_message(&commitment, message, &factory));

        // challenge_scalar is the challenge verify_message checks against
        let e = sig.challenge_scalar(&commitment, message).unwrap();
        assert!(sig.verify(&commitment, &e, &factory));

        // Tampering with the message, the commitment or the nonce fails
        assert!(!sig.verify_message(&commitment, b"Day Watch", &factory));
        let other_commitment = factory.commit(&RistrettoSecretKey::random(&mut rng), &a);
        assert!(!sig.verify_message(&other_commitment, message, &factory));
        let (_, u, v) = sig.complete_signature_tuple();
        let tampered = RistrettoComSig::new(factory.commit(u, v), u.clone(), v.clone());
        assert!(!tampered.verify_message(&commitment, message, &factory));

        // Explicit nonces produce the expected public nonce
        let nonce_a = RistrettoSecretKey::random(&mut rng);
        let nonce_x = RistrettoSecretKey::random(&mut rng);
        let sig = RistrettoComSig::sign_message_with_nonces(&a, &x, &nonce_a, &nonce_x, &commitment, message, &factory)
            .unwrap();
        assert_eq!(sig.public_nonce(), &factory.commit(&nonce_x, &nonce_a));
        assert!(sig.verify_message(&commitment, message, &factory));

        // A commitment the secrets do not open is rejected
        assert_eq!(
            RistrettoComSig::sign_message_with_nonces(&a, &x, &nonce_a, &nonce_x, &other_commitment, message, &factory)
                .unwrap_err(),
            CommitmentSignatureError::InvalidOpening
        );
        assert!(RistrettoComSig::sign_message(&a, &x, &other_commitment, message, &factory, &mut rng).is_err());
    }

    /// Signatures over a shared challenge add up to a signature for the sum of the commitments
    #[test]
    fn bound_challenge_addition() {
        let mut rng = rand::rng();
        let factory = PedersenCommitmentFactory::default();
        let (a1, x1, a2, x2) = (
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
        );
        let (na1, nx1, na2, nx2) = (
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
            RistrettoSecretKey::random(&mut rng),
        );
        let combined_commitment = &factory.commit(&x1, &a1) + &factory.commit(&x2, &a2);
        let combined_nonce = &factory.commit(&nx1, &na1) + &factory.commit(&nx2, &na2);
        let challenge = RistrettoComSig::construct_domain_separated_challenge::<_, Blake2b<U64>, CommitmentSigChallenge>(
            &combined_nonce,
            &combined_commitment,
            b"Jingo",
        );

        let sig1 = RistrettoComSig::sign(&a1, &x1, &na1, &nx1, challenge.as_ref(), &factory).unwrap();
        let sig2 = RistrettoComSig::sign(&a2, &x2, &na2, &nx2, challenge.as_ref(), &factory).unwrap();
        let sum = &sig1 + &sig2;
        assert!(sum.verify_message(&combined_commitment, b"Jingo", &factory));
    }
}
