// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::CommitmentAndPublicKeySignature,
};

/// # A commitment and public key (CAPK) signature implementation on Ristretto
///
/// `RistrettoComAndPubSig` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide CAPK signature functionality.
///
/// ## Examples
///
/// You can create a `RistrettoComAndPubSig` from its component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::commitment::HomomorphicCommitment;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let ephemeral_commitment = HomomorphicCommitment::from_hex(
///     "8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19",
/// )
/// .unwrap();
/// let ephemeral_pubkey = RistrettoPublicKey::from_hex(
///     "8063d85e151abee630e643e2b3dc47bfaeb8aa859c9d10d60847985f286aad19",
/// )
/// .unwrap();
/// let u_a = RistrettoSecretKey::from_bytes(b"10000000000000000000000010000000").unwrap();
/// let u_x = RistrettoSecretKey::from_bytes(b"a00000000000000000000000a0000000").unwrap();
/// let u_y = RistrettoSecretKey::from_bytes(b"a00000000000000000000000a0000000").unwrap();
/// let sig = RistrettoComAndPubSig::new(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y);
/// ```
///
/// or you can create a signature for a commitment by signing a message with knowledge of the commitment and then
/// verify it by calling the `verify_challenge` method:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::hash::blake2::Blake256;
/// # use digest::Digest;
/// # use tari_crypto::commitment::HomomorphicCommitmentFactory;
/// # use tari_crypto::ristretto::pedersen::*;
/// use tari_crypto::ristretto::pedersen::commitment_factory::PedersenCommitmentFactory;
/// use tari_utilities::hex::Hex;
///
/// let mut rng = rand::thread_rng();
/// let a_val = RistrettoSecretKey::random(&mut rng);
/// let x_val = RistrettoSecretKey::random(&mut rng);
/// let y_val = RistrettoSecretKey::random(&mut rng);
/// let a_nonce = RistrettoSecretKey::random(&mut rng);
/// let x_nonce = RistrettoSecretKey::random(&mut rng);
/// let y_nonce = RistrettoSecretKey::random(&mut rng);
/// let e = Blake256::digest(b"Maskerade"); // In real life, this should be strong Fiat-Shamir!
/// let factory = PedersenCommitmentFactory::default();
/// let commitment = factory.commit(&x_val, &a_val);
/// let pubkey = RistrettoPublicKey::from_secret_key(&y_val);
/// let sig = RistrettoComAndPubSig::sign(
///     &a_val, &x_val, &y_val, &a_nonce, &x_nonce, &y_nonce, &e, &factory,
/// )
/// .unwrap();
/// assert!(sig.verify_challenge(&commitment, &pubkey, &e, &factory, &mut rng));
/// ```
pub type RistrettoComAndPubSig = CommitmentAndPublicKeySignature<RistrettoPublicKey, RistrettoSecretKey>;

#[cfg(test)]
mod test {
    use digest::Digest;
    use tari_utilities::{hex::from_hex, ByteArray};

    use crate::{
        commitment::HomomorphicCommitmentFactory,
        hash::blake2::Blake256,
        keys::{PublicKey, SecretKey},
        ristretto::{
            pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
            RistrettoComAndPubSig,
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    #[test]
    fn default() {
        let sig = RistrettoComAndPubSig::default();

        // Check all values returned from the tuple
        assert_eq!(
            sig.complete_signature_tuple(),
            (
                &PedersenCommitment::default(),
                &RistrettoPublicKey::default(),
                &RistrettoSecretKey::default(),
                &RistrettoSecretKey::default(),
                &RistrettoSecretKey::default()
            )
        );

        // Check all values returned from the getters
        assert_eq!(sig.ephemeral_commitment(), &PedersenCommitment::default());
        assert_eq!(sig.ephemeral_pubkey(), &RistrettoPublicKey::default());
        assert_eq!(sig.u_a(), &RistrettoSecretKey::default());
        assert_eq!(sig.u_x(), &RistrettoSecretKey::default());
        assert_eq!(sig.u_y(), &RistrettoSecretKey::default());
    }

    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    fn sign_and_verify_message() {
        let mut rng = rand::thread_rng();

        // Witness data
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let y_value = RistrettoSecretKey::random(&mut rng);

        // Statement data
        let factory = PedersenCommitmentFactory::default();
        let commitment = factory.commit(&x_value, &a_value);
        let pubkey = RistrettoPublicKey::from_secret_key(&y_value);

        // Nonce data
        let r_a = RistrettoSecretKey::random(&mut rng);
        let r_x = RistrettoSecretKey::random(&mut rng);
        let r_y = RistrettoSecretKey::random(&mut rng);
        let ephemeral_commitment = factory.commit(&r_x, &r_a);
        let ephemeral_pubkey = RistrettoPublicKey::from_secret_key(&r_y);

        // Challenge; doesn't use proper Fiat-Shamir, so it's for testing only!
        let challenge = Blake256::new()
            .chain(commitment.as_bytes())
            .chain(pubkey.as_bytes())
            .chain(ephemeral_commitment.as_bytes())
            .chain(ephemeral_pubkey.as_bytes())
            .chain(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_bytes(&challenge).unwrap();

        // Responses
        let u_a = &r_a + e_key.clone() * &a_value;
        let u_x = &r_x + e_key.clone() * &x_value;
        let u_y = &r_y + e_key * &y_value;

        let sig =
            RistrettoComAndPubSig::sign(&a_value, &x_value, &y_value, &r_a, &r_x, &r_y, &challenge, &factory).unwrap();

        // Check values from getters
        assert_eq!(*sig.ephemeral_commitment(), ephemeral_commitment);
        assert_eq!(*sig.ephemeral_pubkey(), ephemeral_pubkey);
        assert_eq!(*sig.u_a(), u_a);
        assert_eq!(*sig.u_x(), u_x);
        assert_eq!(*sig.u_y(), u_y);

        // Check values from tuple
        assert_eq!(
            sig.complete_signature_tuple(),
            (&ephemeral_commitment, &ephemeral_pubkey, &u_a, &u_x, &u_y)
        );

        // verify signature
        assert!(sig.verify_challenge(&commitment, &pubkey, &challenge, &factory, &mut rng));

        // A different statement should fail
        let evil_a = RistrettoSecretKey::random(&mut rng);
        let evil_x = RistrettoSecretKey::random(&mut rng);
        let evil_commitment = factory.commit(&evil_x, &evil_a);

        let evil_y = RistrettoSecretKey::random(&mut rng);
        let evil_pubkey = RistrettoPublicKey::from_secret_key(&evil_y);

        assert!(!sig.verify_challenge(&evil_commitment, &pubkey, &challenge, &factory, &mut rng));
        assert!(!sig.verify_challenge(&commitment, &evil_pubkey, &challenge, &factory, &mut rng));

        // A different challenge should fail
        let evil_challenge = Blake256::digest(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&commitment, &pubkey, &evil_challenge, &factory, &mut rng));
    }

    /// Create two partial signatures to the same challenge and computes if the total aggregate signature is valid.
    #[test]
    fn sign_and_verify_message_partial() {
        let mut rng = rand::thread_rng();

        // Witness data
        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let y_value = RistrettoSecretKey::random(&mut rng);

        // Statement data
        let factory = PedersenCommitmentFactory::default();
        let commitment = factory.commit(&x_value, &a_value);
        let pubkey = RistrettoPublicKey::from_secret_key(&y_value);

        // Nonce data
        let r_a = RistrettoSecretKey::random(&mut rng);
        let r_x = RistrettoSecretKey::random(&mut rng);
        let r_y = RistrettoSecretKey::random(&mut rng);
        let ephemeral_commitment = factory.commit(&r_x, &r_a);
        let ephemeral_pubkey = RistrettoPublicKey::from_secret_key(&r_y);

        // Challenge; doesn't use proper Fiat-Shamir, so it's for testing only!
        let challenge = Blake256::new()
            .chain(commitment.as_bytes())
            .chain(pubkey.as_bytes())
            .chain(ephemeral_commitment.as_bytes())
            .chain(ephemeral_pubkey.as_bytes())
            .chain(b"Small Gods")
            .finalize();

        let sig_total =
            RistrettoComAndPubSig::sign(&a_value, &x_value, &y_value, &r_a, &r_x, &r_y, &challenge, &factory).unwrap();

        let default_pk = RistrettoSecretKey::default();

        let sig_p_1 = RistrettoComAndPubSig::sign(
            &a_value,
            &x_value,
            default_pk,
            &r_a,
            &r_x,
            &default_pk,
            &challenge,
            &factory,
        )
        .unwrap();

        let sig_p_2 = RistrettoComAndPubSig::sign(
            &default_pk,
            &default_pk,
            y_value,
            &default_pk,
            &default_pk,
            &r_y,
            &challenge,
            &factory,
        )
        .unwrap();
        assert_eq!(sig_p_total, sig_total);

        // verify signature
        assert!(sig_p_total.verify_challenge(&commitment, &pubkey, &challenge, &factory, &mut rng));
    }

    /// Test that commitment signatures are linear, as in a multisignature construction
    #[test]
    fn test_signature_addition() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();

        // Alice's data
        let a_value_alice = RistrettoSecretKey::random(&mut rng);
        let x_value_alice = RistrettoSecretKey::random(&mut rng);
        let commitment_alice = factory.commit(&x_value_alice, &a_value_alice);

        let y_value_alice = RistrettoSecretKey::random(&mut rng);
        let pubkey_alice = RistrettoPublicKey::from_secret_key(&y_value_alice);

        let r_a_alice = RistrettoSecretKey::random(&mut rng);
        let r_x_alice = RistrettoSecretKey::random(&mut rng);
        let r_y_alice = RistrettoSecretKey::random(&mut rng);

        let ephemeral_commitment_alice = factory.commit(&r_x_alice, &r_a_alice);
        let ephemeral_pubkey_alice = RistrettoPublicKey::from_secret_key(&r_y_alice);

        // Bob's data
        let a_value_bob = RistrettoSecretKey::random(&mut rng);
        let x_value_bob = RistrettoSecretKey::random(&mut rng);
        let commitment_bob = factory.commit(&x_value_bob, &a_value_bob);

        let y_value_bob = RistrettoSecretKey::random(&mut rng);
        let pubkey_bob = RistrettoPublicKey::from_secret_key(&y_value_bob);

        let r_a_bob = RistrettoSecretKey::random(&mut rng);
        let r_x_bob = RistrettoSecretKey::random(&mut rng);
        let r_y_bob = RistrettoSecretKey::random(&mut rng);

        let ephemeral_commitment_bob = factory.commit(&r_x_bob, &r_a_bob);
        let ephemeral_pubkey_bob = RistrettoPublicKey::from_secret_key(&r_y_bob);

        // The challenge is common to Alice and Bob; here we use an arbitrary hash
        let challenge = Blake256::digest(b"Test challenge");

        // Alice's signature
        let sig_alice = RistrettoComAndPubSig::sign(
            &a_value_alice,
            &x_value_alice,
            &y_value_alice,
            &r_a_alice,
            &r_x_alice,
            &r_y_alice,
            &challenge,
            &factory,
        )
        .unwrap();

        // Bob's signature
        let sig_bob = RistrettoComAndPubSig::sign(
            &a_value_bob,
            &x_value_bob,
            &y_value_bob,
            &r_a_bob,
            &r_x_bob,
            &r_y_bob,
            &challenge,
            &factory,
        )
        .unwrap();

        // Add the two signatures
        let sig_sum = &sig_alice + &sig_bob;

        assert_eq!(
            *sig_sum.ephemeral_commitment(),
            &ephemeral_commitment_alice + &ephemeral_commitment_bob
        );
        assert_eq!(
            *sig_sum.ephemeral_pubkey(),
            &ephemeral_pubkey_alice + &ephemeral_pubkey_bob
        );

        // The signature should verify against the sum of statement values
        let commitment_sum = &commitment_alice + &commitment_bob;
        let pubkey_sum = &pubkey_alice + &pubkey_bob;
        assert!(sig_sum.verify_challenge(&commitment_sum, &pubkey_sum, &challenge, &factory, &mut rng))
    }

    /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    /// signed as a result of applying modulo arithmetic on the challenge value
    #[test]
    fn challenge_from_invalid_scalar() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();

        let a_value = RistrettoSecretKey::random(&mut rng);
        let x_value = RistrettoSecretKey::random(&mut rng);
        let y_value = RistrettoSecretKey::random(&mut rng);

        let message = from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();

        let r_a = RistrettoSecretKey::random(&mut rng);
        let r_x = RistrettoSecretKey::random(&mut rng);
        let r_y = RistrettoSecretKey::random(&mut rng);

        assert!(
            RistrettoComAndPubSig::sign(&a_value, &x_value, &y_value, &r_a, &r_x, &r_y, &message, &factory).is_ok()
        );
    }

    #[test]
    fn to_vec() {
        let sig = RistrettoComAndPubSig::default();
        let bytes = sig.to_vec();

        assert_eq!(
            bytes.capacity(),
            2 * RistrettoPublicKey::key_length() + 3 * RistrettoSecretKey::key_length()
        );
        assert_eq!(bytes.capacity(), bytes.len());
        assert!(bytes.iter().all(|b| *b == 0x00));
    }
}
