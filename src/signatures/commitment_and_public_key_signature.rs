// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::{Add, Mul},
};

use rand_core::{CryptoRng, RngCore};
use snafu::prelude::*;
use tari_utilities::ByteArray;

use crate::{
    alloc::borrow::ToOwned,
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    keys::{PublicKey, SecretKey},
};

/// An error when creating a commitment signature
#[derive(Clone, Debug, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub enum CommitmentAndPublicKeySignatureError {
    #[snafu(display("An invalid challenge was provided"))]
    InvalidChallenge,
}

/// # Commitment and public key (CAPK) signatures
///
/// Given a commitment `commitment = a*H + x*G` and group element `pubkey = y*G`, a CAPK signature is based on
/// a representation proof of both openings: `(a, x)` and `y`. It additionally binds to arbitrary message data `m`
/// via the challenge to produce a signature construction.
///
/// It is used in Tari protocols as part of transaction authorization.
///
/// The construction works as follows:
/// - Sample scalar nonces `r_a, r_x, r_y` uniformly at random.
/// - Compute ephemeral values `ephemeral_commitment = r_a*H + r_x*G` and `ephemeral_pubkey = r_y*G`.
/// - Use strong Fiat-Shamir to produce a challenge `e`. If `e == 0` (this is unlikely), abort and start over.
/// - Compute the responses `u_a = r_a + e*a` and `u_x = r_x + e*x` and `u_y = r_y + e*y`.
///
/// The signature is the tuple `(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y)`.
///
/// To verify:
/// - The verifier computes the challenge `e` and rejects the signature if `e == 0` (this is unlikely).
/// - Verification succeeds if and only if the following equations hold: `u_a*H + u*x*G == ephemeral_commitment +
///   e*commitment` `u_y*G == ephemeral_pubkey + e*pubkey`
///
/// We note that it is possible to make verification slightly more efficient. To do so, the verifier selects a nonzero
/// scalar weight `w` uniformly at random (not through Fiat-Shamir!) and accepts the signature if and only if the
/// following equation holds:
///     `u_a*H + (u_x + w*u_y)*G - ephemeral_commitment - w*ephemeral_pubkey - e*commitment - (w*e)*pubkey == 0`
/// The use of efficient multiscalar multiplication algorithms may also be useful for efficiency.
/// The use of precomputation tables for `G` and `H` may also be useful for efficiency.

#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommitmentAndPublicKeySignature<P, K> {
    ephemeral_commitment: HomomorphicCommitment<P>,
    ephemeral_pubkey: P,
    u_a: K,
    u_x: K,
    u_y: K,
}

impl<P, K> CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    /// Creates a new [CommitmentSignature]
    pub fn new(ephemeral_commitment: HomomorphicCommitment<P>, ephemeral_pubkey: P, u_a: K, u_x: K, u_y: K) -> Self {
        CommitmentAndPublicKeySignature {
            ephemeral_commitment,
            ephemeral_pubkey,
            u_a,
            u_x,
            u_y,
        }
    }

    /// Complete a signature using the given challenge. The challenge is provided by the caller to support the
    /// multiparty use case. It is _very important_ that it be computed using strong Fiat-Shamir! Further, the
    /// values `r_a, r_x, r_y` are nonces, must be sampled uniformly at random, and must never be reused.
    #[allow(clippy::too_many_arguments)]
    pub fn sign<C>(
        a: &K,
        x: &K,
        y: &K,
        r_a: &K,
        r_x: &K,
        r_y: &K,
        challenge: &[u8],
        factory: &C,
    ) -> Result<Self, CommitmentAndPublicKeySignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        // The challenge is computed by wide reduction
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(CommitmentAndPublicKeySignatureError::InvalidChallenge),
        };

        // The challenge cannot be zero
        if e == K::default() {
            return Err(CommitmentAndPublicKeySignatureError::InvalidChallenge);
        }

        // Compute the response values
        let ea = &e * a;
        let ex = &e * x;
        let ey = &e * y;

        let u_a = r_a + &ea;
        let u_x = r_x + &ex;
        let u_y = r_y + &ey;

        // Compute the initial values
        let ephemeral_commitment = factory.commit(r_x, r_a);
        let ephemeral_pubkey = P::from_secret_key(r_y);

        Ok(Self::new(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y))
    }

    /// Verify a signature on a commitment and group element statement using a given challenge (as a byte array)
    pub fn verify_challenge<'a, C, R>(
        &self,
        commitment: &'a HomomorphicCommitment<P>,
        pubkey: &'a P,
        challenge: &[u8],
        factory: &C,
        rng: &mut R,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b P: Mul<&'b K, Output = P>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        for<'b> &'b P: Add<&'b P, Output = P>,
        for<'b> &'b K: Mul<&'b K, Output = K>,
        for<'b> &'b K: Add<&'b K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
        R: RngCore + CryptoRng,
    {
        // The challenge is computed by wide reduction
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };

        self.verify(commitment, pubkey, &e, factory, rng)
    }

    /// Verify a signature on a commitment and group element statement using a given challenge (as a scalar)
    pub fn verify<'a, C, R>(
        &self,
        commitment: &'a HomomorphicCommitment<P>,
        pubkey: &'a P,
        challenge: &K,
        factory: &C,
        rng: &mut R,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b P: Mul<&'b K, Output = P>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        for<'b> &'b P: Add<&'b P, Output = P>,
        for<'b> &'b K: Mul<&'b K, Output = K>,
        for<'b> &'b K: Add<&'b K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
        R: RngCore + CryptoRng,
    {
        // The challenge cannot be zero
        if *challenge == K::default() {
            return false;
        }

        // Use a single weighted equation for verification to avoid unnecessary group operations
        // For now, we use naive multiscalar multiplication, but offload the commitment computation
        // This allows for the use of precomputation within the commitment itself, which is more efficient
        let w = K::random(rng); // must be random and not Fiat-Shamir!

        // u_a*H + (u_x + w*u_y)*G == ephemeral_commitment + w*ephemeral_pubkey + e*commitment + (w*e)*pubkey
        let verifier_lhs = factory
            .commit(&(&self.u_x + &(&w * &self.u_y)), &self.u_a)
            .as_public_key()
            .to_owned();
        let verifier_rhs_unweighted =
            self.ephemeral_commitment.as_public_key() + (commitment * challenge).as_public_key();
        let verifier_rhs_weighted = &self.ephemeral_pubkey * &w + pubkey * &(&w * challenge);

        verifier_lhs == verifier_rhs_unweighted + verifier_rhs_weighted
    }

    /// Get the signature tuple `(ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y)`
    pub fn complete_signature_tuple(&self) -> (&HomomorphicCommitment<P>, &P, &K, &K, &K) {
        (
            &self.ephemeral_commitment,
            &self.ephemeral_pubkey,
            &self.u_a,
            &self.u_x,
            &self.u_y,
        )
    }

    /// Get the response value `u_a`
    pub fn u_a(&self) -> &K {
        &self.u_a
    }

    /// Get the response value `u_x`
    pub fn u_x(&self) -> &K {
        &self.u_x
    }

    /// Get the response value `u_y`
    pub fn u_y(&self) -> &K {
        &self.u_y
    }

    /// Get the ephemeral commitment `ephemeral_commitment`
    pub fn ephemeral_commitment(&self) -> &HomomorphicCommitment<P> {
        &self.ephemeral_commitment
    }

    /// Get the ephemeral public key `ephemeral_pubkey`
    pub fn ephemeral_pubkey(&self) -> &P {
        &self.ephemeral_pubkey
    }

    /// Produce a canonical byte representation of the commitment signature
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 * P::key_length() + 3 * K::key_length());
        buf.extend_from_slice(self.ephemeral_commitment().as_bytes());
        buf.extend_from_slice(self.ephemeral_pubkey().as_bytes());
        buf.extend_from_slice(self.u_a().as_bytes());
        buf.extend_from_slice(self.u_x().as_bytes());
        buf.extend_from_slice(self.u_y().as_bytes());
        buf
    }
}

impl<'a, 'b, P, K> Add<&'b CommitmentAndPublicKeySignature<P, K>> for &'a CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
{
    type Output = CommitmentAndPublicKeySignature<P, K>;

    fn add(self, rhs: &'b CommitmentAndPublicKeySignature<P, K>) -> CommitmentAndPublicKeySignature<P, K> {
        let ephemeral_commitment_sum = self.ephemeral_commitment() + rhs.ephemeral_commitment();
        let ephemeral_pubkey_sum_sum = self.ephemeral_pubkey() + rhs.ephemeral_pubkey();
        let u_a_sum = self.u_a() + rhs.u_a();
        let u_x_sum = self.u_x() + rhs.u_x();
        let u_y_sum = self.u_y() + rhs.u_y();

        CommitmentAndPublicKeySignature::new(
            ephemeral_commitment_sum,
            ephemeral_pubkey_sum_sum,
            u_a_sum,
            u_x_sum,
            u_y_sum,
        )
    }
}

impl<'a, P, K> Add<CommitmentAndPublicKeySignature<P, K>> for &'a CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    for<'b> &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    for<'b> &'a P: Add<&'b P, Output = P>,
    K: SecretKey,
    for<'b> &'a K: Add<&'b K, Output = K>,
{
    type Output = CommitmentAndPublicKeySignature<P, K>;

    fn add(self, rhs: CommitmentAndPublicKeySignature<P, K>) -> CommitmentAndPublicKeySignature<P, K> {
        let ephemeral_commitment_sum = self.ephemeral_commitment() + rhs.ephemeral_commitment();
        let ephemeral_pubkey_sum_sum = self.ephemeral_pubkey() + rhs.ephemeral_pubkey();
        let u_a_sum = self.u_a() + rhs.u_a();
        let u_x_sum = self.u_x() + rhs.u_x();
        let u_y_sum = self.u_y() + rhs.u_y();

        CommitmentAndPublicKeySignature::new(
            ephemeral_commitment_sum,
            ephemeral_pubkey_sum_sum,
            u_a_sum,
            u_x_sum,
            u_y_sum,
        )
    }
}

impl<P, K> Default for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn default() -> Self {
        CommitmentAndPublicKeySignature::new(
            HomomorphicCommitment::<P>::default(),
            P::default(),
            K::default(),
            K::default(),
            K::default(),
        )
    }
}

/// Provide a canonical ordering for commitment signatures. We use byte representations of all values in this order:
/// `ephemeral_commitment, ephemeral_pubkey, u_a, u_x, u_y`
impl<P, K> Ord for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn cmp(&self, other: &Self) -> Ordering {
        let mut compare = self.ephemeral_commitment().cmp(other.ephemeral_commitment());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.ephemeral_pubkey().cmp(other.ephemeral_pubkey());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.u_a().as_bytes().cmp(other.u_a().as_bytes());
        if compare != Ordering::Equal {
            return compare;
        }

        compare = self.u_x().as_bytes().cmp(other.u_x().as_bytes());
        if compare != Ordering::Equal {
            return compare;
        }

        self.u_y().as_bytes().cmp(other.u_y().as_bytes())
    }
}

impl<P, K> PartialOrd for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K> PartialEq for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.ephemeral_commitment().eq(other.ephemeral_commitment()) &&
            self.ephemeral_pubkey().eq(other.ephemeral_pubkey()) &&
            self.u_a().eq(other.u_a()) &&
            self.u_x().eq(other.u_x()) &&
            self.u_y().eq(other.u_y())
    }
}

impl<P, K> Eq for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
}

impl<P, K> Hash for CommitmentAndPublicKeySignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.to_vec())
    }
}
