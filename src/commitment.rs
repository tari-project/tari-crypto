// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A commitment is like a sealed envelope. You put some information inside the envelope, and then seal (commit) it.
//! You can't change what you've said, but also, no-one knows what you've said until you're ready to open (open) the
//! envelope and reveal its contents. Also it's a special envelope that can only be opened by a special opener that
//! you keep safe in your drawer.

use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::{Add, Mul, Sub},
};

use serde::{Deserialize, Serialize};
use tari_utilities::{ByteArray, ByteArrayError};

use crate::keys::{PublicKey, SecretKey};

/// There are also different types of commitments that vary in their security guarantees, but all of them are
/// represented by binary data; so [HomomorphicCommitment](trait.HomomorphicCommitment.html) implements
/// [ByteArray](trait.ByteArray.html).
///
/// The Homomorphic part means, more or less, that commitments follow some of the standard rules of
/// arithmetic. Adding two commitments is the same as committing to the sum of their parts:
/// $$ \begin{aligned}
///   C_1 &= v_1.G + k_1.H \\\\
///   C_2 &= v_2.G + k_2.H \\\\
///   \therefore C_1 + C_2 &= (v_1 + v_2)G + (k_1 + k_2)H
/// \end{aligned} $$
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomomorphicCommitment<P>(pub(crate) P);

impl<P> HomomorphicCommitment<P>
where P: PublicKey
{
    /// Get this commitment as a public key point
    pub fn as_public_key(&self) -> &P {
        &self.0
    }

    /// Converts a public key into a commitment
    pub fn from_public_key(p: &P) -> HomomorphicCommitment<P> {
        HomomorphicCommitment(p.clone())
    }
}

impl<P> ByteArray for HomomorphicCommitment<P>
where P: PublicKey
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, ByteArrayError> {
        let p = P::from_bytes(bytes)?;
        Ok(Self(p))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<P> PartialOrd for HomomorphicCommitment<P>
where P: PublicKey
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<P> Ord for HomomorphicCommitment<P>
where P: PublicKey
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

/// Add two commitments together. Note! There is no check that the bases are equal.
impl<'b, P> Add for &'b HomomorphicCommitment<P>
where
    P: PublicKey,
    &'b P: Add<&'b P, Output = P>,
{
    type Output = HomomorphicCommitment<P>;

    fn add(self, rhs: &'b HomomorphicCommitment<P>) -> Self::Output {
        HomomorphicCommitment(&self.0 + &rhs.0)
    }
}

/// Add a public key to a commitment. Note! There is no check that the bases are equal.
impl<'a, 'b, P> Add<&'b P> for &'b HomomorphicCommitment<P>
where
    P: PublicKey,
    &'b P: Add<&'b P, Output = P>,
{
    type Output = HomomorphicCommitment<P>;

    fn add(self, rhs: &'b P) -> Self::Output {
        HomomorphicCommitment(&self.0 + rhs)
    }
}

/// Subtracts the left commitment from the right commitment. Note! There is no check that the bases are equal.
impl<'b, P> Sub for &'b HomomorphicCommitment<P>
where
    P: PublicKey,
    &'b P: Sub<&'b P, Output = P>,
{
    type Output = HomomorphicCommitment<P>;

    fn sub(self, rhs: &'b HomomorphicCommitment<P>) -> Self::Output {
        HomomorphicCommitment(&self.0 - &rhs.0)
    }
}

/// Multiply the commitment with a private key
impl<'a, 'b, P, K> Mul<&'b K> for &'a HomomorphicCommitment<P>
where
    P: PublicKey<K = K>,
    K: SecretKey,
    &'b K: Mul<&'a P, Output = P>,
{
    type Output = HomomorphicCommitment<P>;

    fn mul(self, rhs: &'b K) -> HomomorphicCommitment<P> {
        let p = rhs * &self.0;
        HomomorphicCommitment::<P>::from_public_key(&p)
    }
}

impl<P: PublicKey> Hash for HomomorphicCommitment<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes())
    }
}

impl<P: PublicKey> PartialEq for HomomorphicCommitment<P> {
    fn eq(&self, other: &Self) -> bool {
        self.as_public_key().eq(other.as_public_key())
    }
}

impl<P: PublicKey> Eq for HomomorphicCommitment<P> {}

/// A trait for creating commitments
pub trait HomomorphicCommitmentFactory {
    /// The type of public key that the underlying commitment will be based on
    type P: PublicKey;

    /// Create a new commitment with the blinding factor k and value v provided. The implementing type will provide the
    /// base values
    fn commit(&self, k: &<Self::P as PublicKey>::K, v: &<Self::P as PublicKey>::K) -> HomomorphicCommitment<Self::P>;
    /// return an identity point for addition using the specified base point. This is a commitment to zero with a zero
    /// blinding factor on the base point
    fn zero(&self) -> HomomorphicCommitment<Self::P>;
    /// Test whether the given blinding factor k and value v open the given commitment
    fn open(
        &self,
        k: &<Self::P as PublicKey>::K,
        v: &<Self::P as PublicKey>::K,
        commitment: &HomomorphicCommitment<Self::P>,
    ) -> bool;
    /// Create a commitment from a blinding factor k and a integer value
    fn commit_value(&self, k: &<Self::P as PublicKey>::K, value: u64) -> HomomorphicCommitment<Self::P>;
    /// Test whether the given private key and value open the given commitment
    fn open_value(&self, k: &<Self::P as PublicKey>::K, v: u64, commitment: &HomomorphicCommitment<Self::P>) -> bool;
}
