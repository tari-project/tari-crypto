// Copyright 2019 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A commitment is like a sealed envelope. You put some information inside the envelope, and then seal (commit) it.
//! You can't change what you've said, but also, no-one knows what you've said until you're ready to open (open) the
//! envelope and reveal its contents. Also it's a special envelope that can only be opened by a special opener that
//! you keep safe in your drawer.

use std::{
    cmp::Ordering,
    convert::TryFrom,
    hash::{Hash, Hasher},
    ops::{Add, Mul, Sub},
};

use serde::{Deserialize, Serialize};
use tari_utilities::{ByteArray, ByteArrayError};

use crate::{
    errors::CommitmentError,
    keys::{PublicKey, SecretKey},
};

/// There are also different types of commitments that vary in their security guarantees, but all of them are
/// represented by binary data; so [HomomorphicCommitment](trait.HomomorphicCommitment.html) implements
/// [ByteArray](trait.ByteArray.html).
///
/// The Homomorphic part means, more or less, that commitments follow some of the standard rules of
/// arithmetic. Adding two commitments is the same as committing to the sum of their parts:
/// $$ \begin{aligned}
///   C_1 &= v_1.H + k_1.G \\\\
///   C_2 &= v_2.H + k_2.G \\\\
///   \therefore C_1 + C_2 &= (v_1 + v_2)H + (k_1 + k_2)G
/// \end{aligned} $$
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HomomorphicCommitment<P>(pub(crate) P);

#[cfg(feature = "borsh")]
impl<P: borsh::BorshDeserialize> borsh::BorshDeserialize for HomomorphicCommitment<P> {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        Ok(Self(P::deserialize(buf)?))
    }
}

#[cfg(feature = "borsh")]
impl<P: borsh::BorshSerialize> borsh::BorshSerialize for HomomorphicCommitment<P> {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        self.0.serialize(writer)
    }
}

impl<P> HomomorphicCommitment<P>
where
    P: PublicKey,
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
where
    P: PublicKey,
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
where
    P: PublicKey,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.0.cmp(&other.0))
    }
}

impl<P> Ord for HomomorphicCommitment<P>
where
    P: PublicKey,
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
impl<'b, P> Add<&'b P> for &'b HomomorphicCommitment<P>
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

    /// Create a new commitment with the blinding factor _k_ and value _v_ provided. The implementing type will provide
    /// the base values
    fn commit(&self, k: &<Self::P as PublicKey>::K, v: &<Self::P as PublicKey>::K) -> HomomorphicCommitment<Self::P>;
    /// Return an identity point for addition using the specified base point. This is a commitment to zero with a zero
    /// blinding factor on the base point
    fn zero(&self) -> HomomorphicCommitment<Self::P>;
    /// Test whether the given blinding factor _k_ and value _v_ open the given commitment
    fn open(
        &self,
        k: &<Self::P as PublicKey>::K,
        v: &<Self::P as PublicKey>::K,
        commitment: &HomomorphicCommitment<Self::P>,
    ) -> bool;
    /// Create a commitment from a blinding factor _k_ and an integer value
    fn commit_value(&self, k: &<Self::P as PublicKey>::K, value: u64) -> HomomorphicCommitment<Self::P>;
    /// Test whether the given private key and value open the given commitment
    fn open_value(&self, k: &<Self::P as PublicKey>::K, v: u64, commitment: &HomomorphicCommitment<Self::P>) -> bool;
}

/// A trait for creating extended commitments that are based on a public key
pub trait ExtendedHomomorphicCommitmentFactory {
    /// The type of public key that the underlying commitment will be based on
    type P: PublicKey;

    /// Create a new commitment with the blinding factor vector **k** and value _v_ provided. The implementing type will
    /// provide the base values
    fn commit_extended(
        &self,
        k_vec: &[<Self::P as PublicKey>::K],
        v: &<Self::P as PublicKey>::K,
    ) -> Result<HomomorphicCommitment<Self::P>, CommitmentError>;
    /// Return an identity point for addition using the specified base points. This is a commitment to zero with a zero
    /// blinding factor vector on the base points
    fn zero_extended(&self) -> HomomorphicCommitment<Self::P>;
    /// Test whether the given blinding factor vector **k** and value _v_ open the given commitment
    fn open_extended(
        &self,
        k_vec: &[<Self::P as PublicKey>::K],
        v: &<Self::P as PublicKey>::K,
        commitment: &HomomorphicCommitment<Self::P>,
    ) -> Result<bool, CommitmentError>;
    /// Create a commitment from a blinding factor vector **k** and an integer value
    fn commit_value_extended(
        &self,
        k_vec: &[<Self::P as PublicKey>::K],
        value: u64,
    ) -> Result<HomomorphicCommitment<Self::P>, CommitmentError>;
    /// Test whether the given private keys and value open the given commitment
    fn open_value_extended(
        &self,
        k_vec: &[<Self::P as PublicKey>::K],
        v: u64,
        commitment: &HomomorphicCommitment<Self::P>,
    ) -> Result<bool, CommitmentError>;
}

/// The extension degree for extended Pedersen commitments. Currently this is limited to adding 5 base points to the
/// default Pedersen commitment, but in theory it could be arbitrarily long, although practically, very few if any
/// test cases will need to add more than 2 base points.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExtensionDegree {
    /// Default Pedersen commitment (`C = v.H + sum(k_i.G_i)|i=1`)
    DefaultPedersen = 1,
    /// Pedersen commitment extended with one degree (`C = v.H + sum(k_i.G_i)|i=1..2`)
    AddOneBasePoint = 2,
    /// Pedersen commitment extended with two degrees (`C = v.H + sum(k_i.G_i)|i=1..3`)
    AddTwoBasePoints = 3,
    /// Pedersen commitment extended with three degrees (`C = v.H + sum(k_i.G_i)|i=1..4`)
    AddThreeBasePoints = 4,
    /// Pedersen commitment extended with four degrees (`C = v.H + sum(k_i.G_i)|i=1..5`)
    AddFourBasePoints = 5,
    /// Pedersen commitment extended with five degrees (`C = v.H + sum(k_i.G_i)|i=1..6`)
    AddFiveBasePoints = 6,
}

impl ExtensionDegree {
    /// Helper function to convert a size into an extension degree
    pub fn try_from_size(size: usize) -> Result<ExtensionDegree, CommitmentError> {
        match size {
            1 => Ok(ExtensionDegree::DefaultPedersen),
            2 => Ok(ExtensionDegree::AddOneBasePoint),
            3 => Ok(ExtensionDegree::AddTwoBasePoints),
            4 => Ok(ExtensionDegree::AddThreeBasePoints),
            5 => Ok(ExtensionDegree::AddFourBasePoints),
            6 => Ok(ExtensionDegree::AddFiveBasePoints),
            _ => Err(CommitmentError::ExtensionDegree(
                "Extension degree not valid".to_string(),
            )),
        }
    }
}

impl TryFrom<usize> for ExtensionDegree {
    type Error = CommitmentError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from_size(value)
    }
}
