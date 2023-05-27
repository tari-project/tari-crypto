// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::SchnorrSignature,
};

/// # A domain-separated Schnorr signature implementation on Ristretto
///
/// Find out more about [Schnorr signatures](https://tlu.tarilabs.com/cryptography/digital_signatures/introduction.html).
///
/// `RistrettoSchnorr` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide Schnorr signature functionality.
///
/// You must supply a domain separator to provide context to the signature.
///
/// An easy way to do this is by using the crate's `hash_domain!` macro.
///
/// Different signature contexts should use distinct domain separators to avoid cross-context misuse.
///
/// ## Creating signatures
///
/// Create a signature by signing a message using a secret key:
///
/// ```rust
/// # use tari_crypto::hash_domain;
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
///
/// hash_domain!(ExampleDomain, "com.example");
///
/// fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
///     let mut rng = rand::thread_rng();
///     let k = RistrettoSecretKey::random(&mut rng);
///     let pk = RistrettoPublicKey::from_secret_key(&k);
///     (k, pk)
/// }
///
/// # #[allow(non_snake_case)]
/// let (k, P) = get_keypair();
/// let msg = "Small Gods";
/// let sig = RistrettoSchnorr::<ExampleDomain>::sign_message(&k, &msg).unwrap();
/// ```
///
/// ## Verifying signatures
///
/// Verify a signature against a given public key and message using `verify_message`.
///
/// ```edition2018
/// # use tari_crypto::hash_domain;
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_crypto::hash::blake2::Blake256;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
///
/// hash_domain!(ExampleDomain, "com.example");
///
/// fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
///     let mut rng = rand::thread_rng();
///     let k = RistrettoSecretKey::random(&mut rng);
///     let pk = RistrettoPublicKey::from_secret_key(&k);
///     (k, pk)
/// }
///
/// # #[allow(non_snake_case)]
/// let (k, P) = get_keypair();
/// let msg = "Small Gods";
/// let sig = RistrettoSchnorr::<ExampleDomain>::sign_message(&k, msg).unwrap();
///
/// assert!(sig.verify_message(&P, msg));
/// ```
pub type RistrettoSchnorr<H> = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, H>;

#[cfg(test)]
mod test {
    use digest::Digest;
    use tari_utilities::ByteArray;

    use crate::{
        hash::blake2::Blake256,
        hash_domain,
        keys::PublicKey,
        ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
    };

    hash_domain!(TestDomain, "com.example.test");

    /// Test defaults
    #[test]
    fn default() {
        let sig = RistrettoSchnorr::<TestDomain>::default();
        assert_eq!(sig.get_signature(), &RistrettoSecretKey::default());
        assert_eq!(sig.get_public_nonce(), &RistrettoPublicKey::default());
    }

    /// Test raw signing and verification
    #[test]
    #[allow(non_snake_case)]
    fn raw_sign_and_verify_challenge() {
        // Generate keys and the nonce
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, R) = RistrettoPublicKey::random_keypair(&mut rng);

        // Use raw signing, where we construct a challenge manually (but without domain separation for this example)
        let e = Blake256::new()
            .chain(P.as_bytes())
            .chain(R.as_bytes())
            .chain(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_bytes(&e).unwrap();
        let s = &r + &e_key * &k;
        let sig = RistrettoSchnorr::<TestDomain>::sign_raw(&k, r, &e).unwrap();

        // Examine the signature components
        let R_calc = sig.get_public_nonce();
        assert_eq!(R, *R_calc);
        assert_eq!(sig.get_signature(), &s);

        // Assert the signature verifies against the correct challenge
        assert!(sig.verify_challenge(&P, &e));

        // Verification should fail if we replace the public key with anything else
        assert!(!sig.verify_challenge(&R, &e));

        // Verification should fail against any other challenge
        let wrong_challenge = Blake256::digest(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&P, &wrong_challenge));
    }

    /// Test that signatures are linear on the same key and message
    /// These operations are defined by the API, but we need to check them manually just in case
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        // Generate keys and nonces
        let mut rng = rand::thread_rng();
        let (k1, P1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, P2) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r1, R1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r2, R2) = RistrettoPublicKey::random_keypair(&mut rng);

        // Generate a (non-separated) challenge with sums of components
        let e = Blake256::new()
            .chain((&P1 + &P2).as_bytes())
            .chain((R1 + R2).as_bytes())
            .chain(b"Moving Pictures")
            .finalize();

        // Calculate summand signatures using each component
        let s1 = RistrettoSchnorr::<TestDomain>::sign_raw(&k1, r1, &e).unwrap();
        let s2 = RistrettoSchnorr::<TestDomain>::sign_raw(&k2, r2, &e).unwrap();

        // Confirm linearity holds against the nonce sum
        assert!((&s1 + &s2).verify_challenge(&(P1 + P2), &e));
    }

    /// Test that domain-separated challenge generation isn't obviously broken
    #[test]
    #[allow(non_snake_case)]
    fn domain_separated_challenge() {
        // Generate keys and a nonce
        let mut rng = rand::thread_rng();
        let (_, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (_, R) = RistrettoPublicKey::random_keypair(&mut rng);

        // Generate the challenge
        let msg = "Moving Pictures";
        let hash = RistrettoSchnorr::<TestDomain>::construct_domain_separated_challenge::<_, Blake256>(&R, &P, msg);

        // Construct a non-separated challenge
        let naiive = Blake256::new()
            .chain(R.as_bytes())
            .chain(P.as_bytes())
            .chain(msg)
            .finalize()
            .to_vec();

        // They shouldn't match
        assert_ne!(hash.as_ref(), naiive.as_bytes());
    }

    /// Test message signing and verification
    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        // Generate keys
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (_, evil_P) = RistrettoPublicKey::random_keypair(&mut rng);

        // Generate messages
        let msg = "Queues are things that happen to other people";
        let evil_msg = "Qs are things that happen to other people";

        // Sign a message
        let sig = RistrettoSchnorr::<TestDomain>::sign_message(&k, msg).unwrap();

        // Test successful and failed verification
        assert!(sig.verify_message(&P, msg));
        assert!(!sig.verify_message(&P, evil_msg));
        assert!(!sig.verify_message(&evil_P, msg));
    }
}
