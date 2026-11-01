// Copyright 2021. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::{Add, Mul},
};

use blake2::Blake2b;
use digest::{Digest, consts::U64};
use rand_core::{CryptoRng, Rng};
use snafu::prelude::*;
use tari_utilities::{ByteArray, ByteArrayError};

use crate::{
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    hash_domain,
    hashing::{DomainSeparatedHash, DomainSeparatedHasher, DomainSeparation},
    keys::{PublicKey, SecretKey},
};

hash_domain!(ComSigChallenge, "com.tari.commitment_signature", 1);

/// An error when creating a commitment signature
#[derive(Clone, Debug, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(missing_docs)]
pub enum CommitmentSignatureError {
    #[snafu(display("An invalid challenge was provided"))]
    InvalidChallenge,
}

/// # Commitment Signatures
///
/// Find out more about Commitment signatures [here](https://eprint.iacr.org/2020/061.pdf) and
/// [here](https://documents.uow.edu.au/~wsusilo/ZCMS_IJNS08.pdf).
///
/// In short, a Commitment Signature is made up of the tuple _(R, u, v)_, where _R_ is a random Pedersen commitment (of
/// two secret nonces) and _u_ and _v_ are the two publicly known private signature keys. It demonstrates ownership of
/// a specific commitment.
///
/// The Commitment Signature signes a challenge with the value commitment's value and blinding factor. The two nonces
/// should be completely random and never reused - that responsibility lies with the calling function.
///   C = a*H + x*G          ... (Pedersen commitment to the value 'a' using blinding factor 'x')
///   R = k_2*H + k_1*G      ... (a public (Pedersen) commitment nonce created with the two random nonces)
///   u = k_1 + e.x          ... (the first publicly known private key of the signature signing with 'x')
///   v = k_2 + e.a          ... (the second publicly known private key of the signature signing with 'a')
///   signature = (R, u, v)  ... (the final signature tuple)
///
/// Verification of the Commitment Signature (R, u, v) entails the following:
///   S = v*H + u*G          ... (Pedersen commitment of the publicly known private signature keys)
///   S =? R + e.C           ... (final verification)
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshDeserialize, borsh::BorshSerialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CommitmentSignature<P, K> {
    pub(crate) public_nonce: HomomorphicCommitment<P>,
    pub(crate) u: K,
    pub(crate) v: K,
}

impl<P, K> CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    /// Creates a new [CommitmentSignature]
    pub fn new(public_nonce: HomomorphicCommitment<P>, u: K, v: K) -> Self {
        CommitmentSignature { public_nonce, u, v }
    }

    /// This is the left-hand side of the signature verification equation
    pub fn calc_signature_verifier<C>(&self, factory: &C) -> HomomorphicCommitment<P>
    where C: HomomorphicCommitmentFactory<P = P> {
        // v*H + u*G
        factory.commit(&self.u, &self.v)
    }

    /// Sign a message using the commitment's value `secret_a` and blinding factor `secret_x`, sampling fresh random
    /// nonces and binding `(public_nonce, public_commitment, message)` in a domain-separated Blake2b-512 transcript.
    pub fn sign_message<C, B, R>(
        secret_a: &K,
        secret_x: &K,
        message: B,
        factory: &C,
        rng: &mut R,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
        B: AsRef<[u8]>,
        R: Rng + CryptoRng,
    {
        let nonce_a = K::random(rng);
        let nonce_x = K::random(rng);
        Self::sign_with_nonces_and_message(secret_a, secret_x, &nonce_a, &nonce_x, message, factory)
    }

    /// Sign a message using the commitment's value `secret_a`, blinding factor `secret_x`, and caller-supplied nonces,
    /// binding `(public_nonce, public_commitment, message)` in a domain-separated Blake2b-512 transcript.
    ///
    /// WARNING: Both nonces _must_ be sampled uniformly at random and never reused with the same commitment and a
    /// different message.
    pub fn sign_with_nonces_and_message<C, B>(
        secret_a: &K,
        secret_x: &K,
        nonce_a: &K,
        nonce_x: &K,
        message: B,
        factory: &C,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
        B: AsRef<[u8]>,
    {
        let public_nonce = factory.commit(nonce_x, nonce_a);
        let public_commitment = factory.commit(secret_x, secret_a);
        let challenge = Self::construct_domain_separated_challenge::<_, Blake2b<U64>, ComSigChallenge>(
            &public_nonce,
            &public_commitment,
            message,
        );
        Self::sign_raw_uniform(secret_a, secret_x, nonce_a, nonce_x, challenge.as_ref(), factory)
    }

    /// Construct a domain-separated challenge hash committing to `(public_nonce, public_commitment, message)`.
    pub fn construct_domain_separated_challenge<B, D, H>(
        public_nonce: &HomomorphicCommitment<P>,
        public_commitment: &HomomorphicCommitment<P>,
        message: B,
    ) -> DomainSeparatedHash<D>
    where
        B: AsRef<[u8]>,
        D: Digest,
        H: DomainSeparation,
    {
        DomainSeparatedHasher::<D, H>::new_with_label("challenge")
            .chain(public_nonce.as_bytes())
            .chain(public_commitment.as_bytes())
            .chain(message.as_ref())
            .finalize()
    }

    /// Generate a commitment signature from a wide-reduced raw challenge byte slice.
    ///
    /// WARNING: The caller _must_ ensure that the public nonce commitment `R = nonce_a*H + nonce_x*G` and the target
    /// commitment `C = secret_a*H + secret_x*G` are committed in the challenge transcript, and that nonces are sampled
    /// uniformly at random and never reused. Prefer [`Self::sign_message`] when a custom transcript is not required.
    pub fn sign_raw_uniform<C>(
        secret_a: &K,
        secret_x: &K,
        nonce_a: &K,
        nonce_x: &K,
        challenge: &[u8],
        factory: &C,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(CommitmentSignatureError::InvalidChallenge),
        };
        if e == K::default() {
            return Err(CommitmentSignatureError::InvalidChallenge);
        }
        let ea = &e * secret_a;
        let ex = &e * secret_x;

        let v = nonce_a + &ea;
        let u = nonce_x + &ex;

        let public_commitment_nonce = factory.commit(nonce_x, nonce_a);

        Ok(Self::new(public_commitment_nonce, u, v))
    }

    /// Generate a commitment signature from a canonical scalar challenge byte slice.
    ///
    /// WARNING: The caller _must_ ensure that the public nonce commitment `R = nonce_a*H + nonce_x*G` and the target
    /// commitment `C = secret_a*H + secret_x*G` are committed in the challenge transcript, and that nonces are sampled
    /// uniformly at random and never reused. Prefer [`Self::sign_message`] when a custom transcript is not required.
    pub fn sign_raw_canonical<C>(
        secret_a: &K,
        secret_x: &K,
        nonce_a: &K,
        nonce_x: &K,
        challenge: &[u8],
        factory: &C,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        let e = match K::from_canonical_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(CommitmentSignatureError::InvalidChallenge),
        };
        if e == K::default() {
            return Err(CommitmentSignatureError::InvalidChallenge);
        }
        let ea = &e * secret_a;
        let ex = &e * secret_x;

        let v = nonce_a + &ea;
        let u = nonce_x + &ex;

        let public_commitment_nonce = factory.commit(nonce_x, nonce_a);

        Ok(Self::new(public_commitment_nonce, u, v))
    }

    /// Sign the provided challenge with the value commitment's value and blinding factor. The two nonces should be
    /// completely random and never reused - that responsibility lies with the calling function.
    ///
    /// WARNING: The provided secret keys and nonces are NOT bound to the challenge by this function. Callers MUST
    /// commit both the public nonce commitment `R` and the public commitment `C` in the challenge transcript, or use
    /// [`Self::sign_message`] / [`Self::sign_raw_uniform`].
    pub fn sign<C>(
        secret_a: &K,
        secret_x: &K,
        nonce_a: &K,
        nonce_x: &K,
        challenge: &[u8],
        factory: &C,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        Self::sign_raw_uniform(secret_a, secret_x, nonce_a, nonce_x, challenge, factory)
    }

    /// Verify a signature created by [`Self::sign_message`] or [`Self::sign_with_nonces_and_message`].
    #[must_use = "a `false` result means verification FAILED; it must be checked"]
    pub fn verify_message<'a, C, B>(
        &self,
        public_commitment: &'a HomomorphicCommitment<P>,
        message: B,
        factory: &C,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
        B: AsRef<[u8]>,
    {
        let challenge = Self::construct_domain_separated_challenge::<_, Blake2b<U64>, ComSigChallenge>(
            &self.public_nonce,
            public_commitment,
            message,
        );
        self.verify_raw_uniform(public_commitment, challenge.as_ref(), factory)
    }

    /// Verify a commitment signature against a wide-reduced raw challenge byte slice.
    #[must_use = "a `false` result means verification FAILED; it must be checked"]
    pub fn verify_raw_uniform<'a, C>(
        &self,
        public_commitment: &'a HomomorphicCommitment<P>,
        challenge: &[u8],
        factory: &C,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        let e = match K::from_uniform_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };

        self.verify(public_commitment, &e, factory)
    }

    /// Verify a commitment signature against a canonical scalar challenge byte slice.
    #[must_use = "a `false` result means verification FAILED; it must be checked"]
    pub fn verify_raw_canonical<'a, C>(
        &self,
        public_commitment: &'a HomomorphicCommitment<P>,
        challenge: &[u8],
        factory: &C,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        let e = match K::from_canonical_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };

        self.verify(public_commitment, &e, factory)
    }

    /// Verify if the commitment signature signed the commitment using the specified challenge (as bytes). If the
    /// provided challenge n bytes cannot be converted to a secret key, this function also returns false.
    #[must_use = "a `false` result means verification FAILED; it must be checked"]
    pub fn verify_challenge<'a, C>(
        &self,
        public_commitment: &'a HomomorphicCommitment<P>,
        challenge: &[u8],
        factory: &C,
    ) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        self.verify_raw_uniform(public_commitment, challenge, factory)
    }

    /// Verify if the commitment signature signed the commitment using the specified challenge (as secret key).
    ///  v*H + u*G = R + e.C
    #[must_use = "a `false` result means verification FAILED; it must be checked"]
    pub fn verify<'a, C>(&self, public_commitment: &'a HomomorphicCommitment<P>, challenge: &K, factory: &C) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        // Reject a zero commitment or zero challenge scalar
        if public_commitment.as_public_key() == &P::default() || *challenge == K::default() {
            return false;
        }

        // v*H + u*G
        let lhs = self.calc_signature_verifier(factory);
        // R + e.C
        let rhs = &self.public_nonce + &(public_commitment * challenge);
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    /// This function returns the complete signature tuple (R, u, v)
    pub fn complete_signature_tuple(&self) -> (&HomomorphicCommitment<P>, &K, &K) {
        (&self.public_nonce, &self.u, &self.v)
    }

    /// This function returns the first publicly known private key of the signature tuple (u)
    pub fn u(&self) -> &K {
        &self.u
    }

    /// This function returns the second publicly known private key of the signature tuple (v)
    pub fn v(&self) -> &K {
        &self.v
    }

    /// This function returns the public commitment public_nonce of the signature tuple (R)
    pub fn public_nonce(&self) -> &HomomorphicCommitment<P> {
        &self.public_nonce
    }

    /// Returns a canonical byte representation of the commitment signature
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(P::key_length() + K::key_length() + K::key_length());
        buf.extend_from_slice(self.public_nonce().as_bytes());
        buf.extend_from_slice(self.u().as_bytes());
        buf.extend_from_slice(self.v().as_bytes());
        buf
    }

    /// From a canonical byte representation, retrieves a commitment signature
    pub fn from_bytes(buf: &[u8]) -> Result<Self, ByteArrayError> {
        if buf.len() != P::KEY_LEN + 2 * K::key_length() {
            return Err(ByteArrayError::IncorrectLength {});
        }
        let public_nonce = HomomorphicCommitment::from_public_key(&P::from_canonical_bytes(&buf[0..P::KEY_LEN])?);
        let u = K::from_canonical_bytes(&buf[P::KEY_LEN..P::KEY_LEN + K::key_length()])?;
        let v = K::from_canonical_bytes(&buf[P::KEY_LEN + K::key_length()..P::KEY_LEN + 2 * K::key_length()])?;

        Ok(Self { public_nonce, u, v })
    }
}

impl<'a, 'b, P, K> Add<&'b CommitmentSignature<P, K>> for &'a CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    K: SecretKey,
    &'a K: Add<&'b K, Output = K>,
{
    type Output = CommitmentSignature<P, K>;

    fn add(self, rhs: &'b CommitmentSignature<P, K>) -> CommitmentSignature<P, K> {
        let r_sum = self.public_nonce() + rhs.public_nonce();
        let s_u_sum = self.u() + rhs.u();
        let s_v_sum = self.v() + rhs.v();
        CommitmentSignature::new(r_sum, s_u_sum, s_v_sum)
    }
}

impl<'a, P, K> Add<CommitmentSignature<P, K>> for &'a CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    for<'b> &'a HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
    K: SecretKey,
    for<'b> &'a K: Add<&'b K, Output = K>,
{
    type Output = CommitmentSignature<P, K>;

    fn add(self, rhs: CommitmentSignature<P, K>) -> CommitmentSignature<P, K> {
        let r_sum = self.public_nonce() + rhs.public_nonce();
        let s_u_sum = self.u() + rhs.u();
        let s_v_sum = self.v() + rhs.v();
        CommitmentSignature::new(r_sum, s_u_sum, s_v_sum)
    }
}

impl<P, K> Default for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn default() -> Self {
        CommitmentSignature::new(HomomorphicCommitment::<P>::default(), K::default(), K::default())
    }
}

/// Provide an efficient ordering algorithm for Commitment signatures. It's probably not a good idea to implement `Ord`
/// for secret keys, but in this instance, the signature is publicly known and is simply a scalar, so we use the bytes
/// representation of the scalar as the canonical ordering metric. This conversion is done if and only if the public
/// nonces are already equal, otherwise the public nonce ordering determines the CommitmentSignature order.
impl<P, K> Ord for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.public_nonce().cmp(other.public_nonce()) {
            Ordering::Equal => {
                let this_u = self.u().as_bytes();
                let that_u = other.u().as_bytes();
                match this_u.cmp(that_u) {
                    Ordering::Equal => {
                        let this = self.v().as_bytes();
                        let that = other.v().as_bytes();
                        this.cmp(that)
                    },
                    v => v,
                }
            },
            v => v,
        }
    }
}

impl<P, K> PartialOrd for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<P, K> PartialEq for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn eq(&self, other: &Self) -> bool {
        self.public_nonce().eq(other.public_nonce()) && self.u().eq(other.u()) && self.v().eq(other.v())
    }
}

impl<P, K> Eq for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
}

impl<P, K> Hash for CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.to_vec())
    }
}
