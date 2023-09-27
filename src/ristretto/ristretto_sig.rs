// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    signatures::{SchnorrSigChallenge, SchnorrSignature},
};

/// # A Schnorr signature implementation on Ristretto
///
/// Find out more about [Schnorr signatures](https://tlu.tarilabs.com/cryptography/digital_signatures/introduction.html).
///
/// `RistrettoSchnorr` utilises the [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek1)
/// implementation of `ristretto255` to provide Schnorr signature functionality.
///
/// In short, a Schnorr sig is made up of the pair _(R, s)_, where _R_ is a public key (of a secret nonce) and _s_ is
/// the signature.
///
/// ## Creating signatures
///
/// You can create a `RisrettoSchnorr` from its component parts:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::ByteArray;
/// # use tari_utilities::hex::Hex;
///
/// let public_r = RistrettoPublicKey::from_hex(
///     "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
/// )
/// .unwrap();
/// let s = RistrettoSecretKey::from_hex(
///     "f62fccf7734099d32937f7f767757abcb6eca70f43b3a7fb6500b2cb9ea12b02",
/// )
/// .unwrap();
/// let sig = RistrettoSchnorr::new(public_r, s);
/// ```
///
/// or you can create a signature by signing a message:
///
/// ```rust
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use digest::Digest;
/// # use rand::{Rng, thread_rng};
///
/// fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
///     let mut rng = rand::thread_rng();
///     let k = RistrettoSecretKey::random(&mut rng);
///     let pk = RistrettoPublicKey::from_secret_key(&k);
///     (k, pk)
/// }
///
/// #[allow(non_snake_case)]
/// let (k, P) = get_keypair();
/// let msg = "Small Gods";
/// let mut rng = thread_rng();
/// let sig = RistrettoSchnorr::sign(&k, &msg, &mut rng);
/// ```
///
/// # Verifying signatures
///
/// Given a signature, (R,s) and a Challenge, e, you can verify that the signature is valid by calling the `verify`
/// method:
///
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::hex::*;
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
/// # use rand::{Rng, thread_rng};
///
/// let msg = "Maskerade";
/// let k = RistrettoSecretKey::from_hex(
///     "bd0b253a619310340a4fa2de54cdd212eac7d088ee1dc47e305c3f6cbd020908",
/// )
/// .unwrap();
/// # #[allow(non_snake_case)]
/// let P = RistrettoPublicKey::from_secret_key(&k);
/// let mut rng = thread_rng();
/// let sig: SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey> =
///     SchnorrSignature::sign(&k, msg, &mut rng).unwrap();
/// assert!(sig.verify(&P, msg));
/// ```
pub type RistrettoSchnorr = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, SchnorrSigChallenge>;

/// # A Schnorr signature implementation on Ristretto with a custom domain separation tag
///
/// Usage is identical to [`RistrettoSchnorr`], except that you are able to specify the domain separation tag to use
/// when computing challenges for the signature.
///
/// ## Example
/// ```edition2018
/// # use tari_crypto::ristretto::*;
/// # use tari_crypto::keys::*;
/// # use tari_crypto::hash_domain;
/// # use tari_crypto::signatures::SchnorrSignature;
/// # use tari_utilities::hex::*;
/// # use rand::{Rng, thread_rng};
/// # use tari_utilities::ByteArray;
/// # use digest::Digest;
///
/// hash_domain!(MyCustomDomain, "com.example.custom");
///
/// let msg = "Maskerade";
/// let k = RistrettoSecretKey::from_hex(
///     "bd0b253a619310340a4fa2de54cdd212eac7d088ee1dc47e305c3f6cbd020908",
/// )
/// .unwrap();
/// # #[allow(non_snake_case)]
/// let P = RistrettoPublicKey::from_secret_key(&k);
/// let mut rng = thread_rng();
/// let sig: SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, MyCustomDomain> =
///     SchnorrSignature::sign(&k, msg, &mut rng).unwrap();
/// assert!(sig.verify(&P, msg));
/// ```
pub type RistrettoSchnorrWithDomain<H> = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey, H>;

#[cfg(test)]
mod test {
    use blake2::Blake2b;
    use digest::{consts::U64, Digest};
    use tari_utilities::{
        hex::{to_hex, Hex},
        ByteArray,
    };

    use crate::{
        hash_domain,
        keys::{PublicKey, SecretKey},
        ristretto::{
            ristretto_sig::RistrettoSchnorrWithDomain,
            RistrettoPublicKey,
            RistrettoSchnorr,
            RistrettoSecretKey,
        },
        signatures::{SchnorrSigChallenge, SchnorrSignature},
    };

    #[test]
    fn default() {
        let sig = RistrettoSchnorr::default();
        assert_eq!(sig.get_signature(), &RistrettoSecretKey::default());
        assert_eq!(sig.get_public_nonce(), &RistrettoPublicKey::default());
    }

    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    #[allow(non_snake_case)]
    fn raw_sign_and_verify_challenge() {
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, R) = RistrettoPublicKey::random_keypair(&mut rng);
        // Use sign raw, and bind the nonce and public key manually
        let e = Blake2b::<U64>::new()
            .chain_update(P.as_bytes())
            .chain_update(R.as_bytes())
            .chain_update(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_uniform_bytes(&e).unwrap();
        let s = &r + &e_key * &k;
        let sig = RistrettoSchnorr::sign_raw_uniform(&k, r, &e).unwrap();
        let R_calc = sig.get_public_nonce();
        assert_eq!(R, *R_calc);
        assert_eq!(sig.get_signature(), &s);
        assert!(sig.verify_raw_uniform(&P, &e));
        // Doesn't work for invalid credentials
        assert!(!sig.verify_raw_uniform(&R, &e));
        // Doesn't work for different challenge
        let wrong_challenge = Blake2b::<U64>::digest(b"Guards! Guards!");
        assert!(!sig.verify_raw_uniform(&P, &wrong_challenge));
    }

    /// This test checks that the linearity of Schnorr signatures hold, i.e. that s = s1 + s2 is validated by R1 + R2
    /// and P1 + P2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::thread_rng();
        // Alice and Bob generate some keys and nonces
        let (k1, P1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r1, R1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, P2) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r2, R2) = RistrettoPublicKey::random_keypair(&mut rng);
        // Each of them creates the Challenge = H(R1 || R2 || P1 || P2 || m)
        let e = Blake2b::<U64>::new()
            .chain_update(R1.as_bytes())
            .chain_update(R2.as_bytes())
            .chain_update(P1.as_bytes())
            .chain_update(P2.as_bytes())
            .chain_update(b"Moving Pictures")
            .finalize();
        // Calculate Alice's signature
        let s1 = RistrettoSchnorr::sign_raw_uniform(&k1, r1, &e).unwrap();
        // Calculate Bob's signature
        let s2 = RistrettoSchnorr::sign_raw_uniform(&k2, r2, &e).unwrap();
        // Now add the two signatures together
        let s_agg = &s1 + &s2;
        // Check that the multi-sig verifies
        assert!(s_agg.verify_raw_uniform(&(P1 + P2), &e));
    }

    #[test]
    #[allow(non_snake_case)]
    fn domain_separated_challenge() {
        let P =
            RistrettoPublicKey::from_hex("74896a30c89186b8194e25f8c1382f8d3081c5a182fb8f8a6d34f27fbefbfc70").unwrap();
        let R =
            RistrettoPublicKey::from_hex("fa14cb581ce5717248444721242e6b195a482d503a853dea4acb513074d8d803").unwrap();
        let msg = "Moving Pictures";
        let hash = SchnorrSignature::<_, _, SchnorrSigChallenge>::construct_domain_separated_challenge::<_, Blake2b<U64>>(
            &R, &P, msg,
        );
        let naiive = Blake2b::<U64>::new()
            .chain_update(R.as_bytes())
            .chain_update(P.as_bytes())
            .chain_update(msg)
            .finalize()
            .to_vec();
        assert_ne!(hash.as_ref(), naiive.as_bytes());
        assert_eq!(
            to_hex(hash.as_ref()),
            "2db0656c9dd1482bf61d32f157726b05a88d567c31107bed9a5c60a02119518af35929f360726bffd846439ab12e7c9f4983cf5fab5ea735422e05e0f560ddfd"
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn custom_hash_domain() {
        hash_domain!(TestDomain, "test.signature.com");
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, _) = RistrettoPublicKey::random_keypair(&mut rng);
        let msg = "Moving Pictures";
        // Using default domain
        // NEVER re-use nonces in practice. This is done here explicitly to indicate that the domain separation
        // prevents accidental signature duplication.
        let sig1 = RistrettoSchnorr::sign_with_nonce_and_message(&k, r.clone(), msg).unwrap();
        // Using custom domain
        let sig2 = RistrettoSchnorrWithDomain::<TestDomain>::sign_with_nonce_and_message(&k, r, msg).unwrap();
        // The type system won't even let this compile :)
        // assert_ne!(sig1, sig2);
        // Prove that the nonces were reused. Again, NEVER do this
        assert_eq!(sig1.get_public_nonce(), sig2.get_public_nonce());
        assert!(sig1.verify(&P, msg));
        assert!(sig2.verify(&P, msg));
        // But the signatures are different, for the same message, secret and nonce.
        assert_ne!(sig1.get_signature(), sig2.get_signature());
    }

    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let sig = RistrettoSchnorr::sign(&k, "Queues are things that happen to other people", &mut rng).unwrap();
        assert!(sig.verify(&P, "Queues are things that happen to other people"));
        assert!(!sig.verify(&P, "Qs are things that happen to other people"));
        assert!(!sig.verify(&(&P + &P), "Queues are things that happen to other people"));
    }
}
