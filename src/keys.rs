// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! General definition of public-private key pairs for use in Tari. The traits and structs
//! defined here are used in the Tari domain logic layer exclusively (as opposed to any specific
//! implementation of ECC curve). The idea being that we can swap out the underlying
//! implementation without worrying too much about the impact on upstream code.

use core::ops::Add;

use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "serde")]
use serde::{de::DeserializeOwned, ser::Serialize};
use tari_utilities::ByteArray;
use zeroize::Zeroize;

/// A trait specifying common behaviour for representing `SecretKey`s. Specific elliptic curve
/// implementations need to implement this trait for them to be used in Tari.
///
/// ## Example
///
/// Assuming there is a Ristretto implementation,
/// ```edition2018
/// # use tari_crypto::ristretto::{ RistrettoSecretKey, RistrettoPublicKey };
/// # use tari_crypto::keys::{ SecretKey, PublicKey };
/// # use rand;
/// let mut rng = rand::thread_rng();
/// let k = RistrettoSecretKey::random(&mut rng);
/// let p = RistrettoPublicKey::from_secret_key(&k);
/// ```
pub trait SecretKey: ByteArray + Clone + PartialEq + Eq + Add<Output = Self> + Default + Zeroize {
    /// The length of the key, in bytes
    fn key_length() -> usize;
    /// Generates a random secret key
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self;
}

//----------------------------------------   Public Keys  ----------------------------------------//

/// A trait specifying common behaviour for representing `PublicKey`s. Specific elliptic curve
/// implementations need to implement this trait for them to be used in Tari.
///
/// See [SecretKey](trait.SecretKey.html) for an example.
#[cfg(feature = "serde")]
pub trait PublicKey:
    ByteArray + Add<Output = Self> + Clone + PartialOrd + Ord + Default + Serialize + DeserializeOwned + Zeroize
{
    /// The output size len of Public Key
    const KEY_LEN: usize;

    /// The related [SecretKey](trait.SecretKey.html) type
    type K: SecretKey;

    /// Calculate the public key associated with the given secret key. This should not fail; if a
    /// failure does occur (implementation error?), the function will panic.
    fn from_secret_key(k: &Self::K) -> Self;

    /// The length of the public key when converted to bytes
    fn key_length() -> usize {
        Self::KEY_LEN
    }

    /// Multiplies each of the items in `scalars` by their respective item in `points` and then adds
    /// the results to produce a single public key
    fn batch_mul(scalars: &[Self::K], points: &[Self]) -> Self;

    /// Generate a random public and secret key
    fn random_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::K, Self) {
        let k = Self::K::random(rng);
        let pk = Self::from_secret_key(&k);
        (k, pk)
    }
}
#[cfg(not(feature = "serde"))]
pub trait PublicKey: ByteArray + Add<Output = Self> + Clone + PartialOrd + Ord + Default + Zeroize {
    /// The output size len of Public Key
    const KEY_LEN: usize;

    /// The related [SecretKey](trait.SecretKey.html) type
    type K: SecretKey;

    /// Calculate the public key associated with the given secret key. This should not fail; if a
    /// failure does occur (implementation error?), the function will panic.
    fn from_secret_key(k: &Self::K) -> Self;

    /// The length of the public key when converted to bytes
    fn key_length() -> usize {
        Self::KEY_LEN
    }

    /// Multiplies each of the items in `scalars` by their respective item in `points` and then adds
    /// the results to produce a single public key
    fn batch_mul(scalars: &[Self::K], points: &[Self]) -> Self;

    /// Generate a random public and secret key
    fn random_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (Self::K, Self) {
        let k = Self::K::random(rng);
        let pk = Self::from_secret_key(&k);
        (k, pk)
    }
}
