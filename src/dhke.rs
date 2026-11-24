// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The robotic innards of a Diffie-Hellman key exchange (DHKE) producing a shared secret.
//! Even though the result of a DHKE is the same type as a public key, it is typically treated as a secret value.
//! To make this work more safely, we ensure that a DHKE result is cleared after use (but beware of subsequent copies or
//! moves). Because a DHKE shared secret is intended to be used in further key derivation, the only visibility into it
//! is as a byte array; it's not possible to directly extract the underlying public key type, and you probably shouldn't
//! clone the byte array without a very good reason. If you need the underlying public key itself, you probably should
//! be using something else.
//!
//! The identity point is rejected as an input and as a result: it is the shared secret for every secret key, so an
//! attacker who supplies it as their public key learns the "secret". The shared secret is a group element, not key
//! material; pass it through a KDF such as [`DerivedKeyDomain`](crate::hashing::DerivedKeyDomain) before use.

use core::ops::Mul;

use snafu::prelude::*;
use subtle::{Choice, ConstantTimeEq};
use tari_utilities::ByteArrayError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::PublicKey;

/// An error when computing or decoding a Diffie-Hellman shared secret
#[derive(Debug, Snafu, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum DiffieHellmanError {
    #[snafu(display("The public key or shared secret is the identity point"))]
    IdentityPoint,
    // `ByteArrayError` comes from `tari_utilities`, which builds on snafu 0.7 and does not implement
    // `core::error::Error`, so it cannot be chained as an error source here.
    #[snafu(display("Invalid shared secret encoding: {source}"))]
    ByteArray {
        #[snafu(source(false))]
        source: ByteArrayError,
    },
}

/// The result of a Diffie-Hellman key exchange
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DiffieHellmanSharedSecret<P>(P)
where P: PublicKey;

impl<P> DiffieHellmanSharedSecret<P>
where
    P: PublicKey,
    for<'a> &'a <P as PublicKey>::K: Mul<&'a P, Output = P>,
{
    /// Perform a Diffie-Hellman key exchange. Returns an error if `pk` or the shared secret (for example with a zero
    /// secret key) is the identity point.
    pub fn new(sk: &P::K, pk: &P) -> Result<Self, DiffieHellmanError> {
        if pk == &P::default() {
            return Err(DiffieHellmanError::IdentityPoint);
        }
        let shared = Self(sk * pk);
        if shared.0 == P::default() {
            return Err(DiffieHellmanError::IdentityPoint);
        }
        Ok(shared)
    }

    /// Constructs a new Diffie-Hellman key exchange from an already created Diffie-Hellman key exchange. The identity
    /// point is rejected.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DiffieHellmanError> {
        let shared = Self(P::from_canonical_bytes(bytes).map_err(|source| DiffieHellmanError::ByteArray { source })?);
        if shared.0 == P::default() {
            return Err(DiffieHellmanError::IdentityPoint);
        }
        Ok(shared)
    }

    /// Get the shared secret as a byte array
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<P> ConstantTimeEq for DiffieHellmanSharedSecret<P>
where P: PublicKey
{
    fn ct_eq(&self, other: &DiffieHellmanSharedSecret<P>) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<P> Eq for DiffieHellmanSharedSecret<P> where P: PublicKey {}

impl<P> PartialEq for DiffieHellmanSharedSecret<P>
where P: PublicKey
{
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

#[cfg(test)]
mod test {
    use rand::rng;

    use super::{DiffieHellmanError, DiffieHellmanSharedSecret};
    use crate::{
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    };

    #[test]
    fn test_dhke() {
        // Generate two key pairs
        let mut rng = rng();

        let sk1 = RistrettoSecretKey::random(&mut rng);
        let pk1 = RistrettoPublicKey::from_secret_key(&sk1);

        let sk2 = RistrettoSecretKey::random(&mut rng);
        let pk2 = RistrettoPublicKey::from_secret_key(&sk2);

        // Assert that both sides of a key exchange match
        let left = DiffieHellmanSharedSecret::<RistrettoPublicKey>::new(&sk1, &pk2).unwrap();
        let right = DiffieHellmanSharedSecret::<RistrettoPublicKey>::new(&sk2, &pk1).unwrap();

        assert_eq!(left.as_bytes(), right.as_bytes());

        let left_bytes = left.as_bytes();
        let new_left = DiffieHellmanSharedSecret::<RistrettoPublicKey>::from_canonical_bytes(left_bytes).unwrap();
        assert_eq!(left.as_bytes(), new_left.as_bytes());
    }

    #[test]
    fn identity_is_rejected() {
        let mut rng = rng();
        let (sk, pk) = RistrettoPublicKey::random_keypair(&mut rng);

        assert_eq!(
            DiffieHellmanSharedSecret::<RistrettoPublicKey>::new(&sk, &RistrettoPublicKey::default()).err(),
            Some(DiffieHellmanError::IdentityPoint)
        );
        assert_eq!(
            DiffieHellmanSharedSecret::<RistrettoPublicKey>::new(&RistrettoSecretKey::default(), &pk).err(),
            Some(DiffieHellmanError::IdentityPoint)
        );
        assert_eq!(
            DiffieHellmanSharedSecret::<RistrettoPublicKey>::from_canonical_bytes(&[0u8; 32]).err(),
            Some(DiffieHellmanError::IdentityPoint)
        );
        assert!(matches!(
            DiffieHellmanSharedSecret::<RistrettoPublicKey>::from_canonical_bytes(&[0u8; 31]),
            Err(DiffieHellmanError::ByteArray { .. })
        ));
    }
}
