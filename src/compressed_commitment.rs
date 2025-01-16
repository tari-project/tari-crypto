// Copyright 2025 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A commitment is like a sealed envelope. You put some information inside the envelope, and then seal (commit) it.
//! You can't change what you've said, but also, no-one knows what you've said until you're ready to open (open) the
//! envelope and reveal its contents. Also it's a special envelope that can only be opened by a special opener that
//! you keep safe in your drawer.

use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use tari_utilities::{ByteArray, ByteArrayError};

use crate::{commitment::HomomorphicCommitment, compressed_key::CompressedKey, keys::PublicKey};

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
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedCommitment<P>(pub(crate) CompressedKey<P>);

impl<P: Default + ByteArray> Default for CompressedCommitment<P> {
    fn default() -> Self {
        Self(CompressedKey::default())
    }
}

#[cfg(feature = "borsh")]
impl<P: borsh::BorshDeserialize> borsh::BorshDeserialize for CompressedCommitment<P> {
    fn deserialize_reader<R>(reader: &mut R) -> Result<Self, borsh::io::Error>
    where R: borsh::io::Read {
        Ok(Self(CompressedKey::deserialize_reader(reader)?))
    }
}

#[cfg(feature = "borsh")]
impl<P: borsh::BorshSerialize> borsh::BorshSerialize for CompressedCommitment<P> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        self.0.serialize(writer)
    }
}

#[allow(dead_code)]
impl<P> CompressedCommitment<P>
where P: PublicKey
{
    /// Get this commitment as a public key point
    pub fn to_public_key(&self) -> Result<P, ByteArrayError> {
        self.0.to_public_key()
    }

    pub fn to_commitment(&self) -> Result<HomomorphicCommitment<P>, ByteArrayError> {
        Ok(HomomorphicCommitment(self.to_public_key()?))
    }

    /// Converts a public key into a commitment
    pub fn from_public_key(p: &P) -> CompressedCommitment<P> {
        let compressed_key = CompressedKey::new_from_pk(p);
        CompressedCommitment(compressed_key)
    }
}

impl<P> ByteArray for CompressedCommitment<P>
where P: PublicKey
{
    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ByteArrayError> {
        let key = CompressedKey::from_canonical_bytes(bytes)?;
        Ok(Self(key))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<P> PartialOrd for CompressedCommitment<P>
where P: PublicKey
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P> Ord for CompressedCommitment<P>
where P: PublicKey
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<P: PublicKey> Hash for CompressedCommitment<P> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes())
    }
}

impl<P: PublicKey> PartialEq for CompressedCommitment<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P: PublicKey> Eq for CompressedCommitment<P> {}
