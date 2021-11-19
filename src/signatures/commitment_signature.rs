// Copyright 2021 The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Digital Signature module
//! This module defines generic traits for handling the digital signature operations, agnostic
//! of the underlying elliptic curve implementation

use crate::{
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    keys::{CompressedPublicKey, PublicKey, SecretKey},
    tari_utilities::ByteArrayError,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    ops::{Add, Mul},
};
use tari_utilities::ByteArray;
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq, Deserialize, Serialize)]
pub enum CommitmentSignatureError {
    #[error("An invalid challenge was provided")]
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
pub struct CommitmentSignature<P, K> {
    public_nonce: HomomorphicCommitment<P>,
    u: K,
    v: K,
}

impl<P, K> CommitmentSignature<P, K>
where
    P: PublicKey<K = K>,
    K: SecretKey,
{
    pub fn new(public_nonce: HomomorphicCommitment<P>, u: K, v: K) -> Self {
        CommitmentSignature { public_nonce, u, v }
    }

    /// This is the left-hand side of the signature verification equation
    pub fn calc_signature_verifier<C>(&self, factory: &C) -> HomomorphicCommitment<P>
    where C: HomomorphicCommitmentFactory<P = P> {
        // v*H + u*G
        factory.commit(&self.u, &self.v)
    }

    /// Sign the provided challenge with the value commitment's value and blinding factor. The two nonces should be
    /// completely random and never reused - that responsibility lies with the calling function.
    pub fn sign<C>(
        secret_a: K,
        secret_x: K,
        nonce_a: K,
        nonce_x: K,
        challenge: &[u8],
        factory: &C,
    ) -> Result<Self, CommitmentSignatureError>
    where
        K: Mul<P, Output = P>,
        for<'a> &'a K: Add<&'a K, Output = K>,
        for<'a> &'a K: Mul<&'a K, Output = K>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        let e = match K::from_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return Err(CommitmentSignatureError::InvalidChallenge),
        };
        let ea = &e * &secret_a;
        let ex = &e * &secret_x;

        let v = &nonce_a + &ea;
        let u = &nonce_x + &ex;

        let public_commitment_nonce = factory.commit(&nonce_x, &nonce_a);

        Ok(Self::new(public_commitment_nonce, u, v))
    }

    /// Verify if the commitment signature signed the commitment using the specified challenge (as bytes). If the
    /// provided challenge n bytes cannot be converted to a secret key, this function also returns false.
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
        let e = match K::from_bytes(challenge) {
            Ok(e) => e,
            Err(_) => return false,
        };

        self.verify(public_commitment, &e, factory)
    }

    /// Verify if the commitment signature signed the commitment using the specified challenge (as secret key).
    ///   v*H + u*G = R + e.C
    pub fn verify<'a, C>(&self, public_commitment: &'a HomomorphicCommitment<P>, challenge: &K, factory: &C) -> bool
    where
        for<'b> &'a HomomorphicCommitment<P>: Mul<&'b K, Output = HomomorphicCommitment<P>>,
        for<'b> &'b HomomorphicCommitment<P>: Add<&'b HomomorphicCommitment<P>, Output = HomomorphicCommitment<P>>,
        C: HomomorphicCommitmentFactory<P = P>,
    {
        // v*H + u*G
        let lhs = self.calc_signature_verifier(factory);
        // R + e.C
        let rhs = &self.public_nonce + &(public_commitment * challenge);
        // Implementors should make this a constant time comparison
        lhs == rhs
    }

    /// This function returns the complete signature tuple (R, u, v)
    #[inline]
    pub fn complete_signature_tuple(&self) -> (&HomomorphicCommitment<P>, &K, &K) {
        (&self.public_nonce, &self.u, &self.v)
    }

    /// This function returns the first publicly known private key of the signature tuple (u)
    #[inline]
    pub fn u(&self) -> &K {
        &self.u
    }

    /// This function returns the second publicly known private key of the signature tuple (v)
    #[inline]
    pub fn v(&self) -> &K {
        &self.v
    }

    /// This function returns the public commitment public_nonce of the signature tuple (R)
    #[inline]
    pub fn public_nonce(&self) -> &HomomorphicCommitment<P> {
        &self.public_nonce
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompressedCommitmentSignature<CPK, PK, K>
where
    CPK: CompressedPublicKey<PK>,
    PK: PublicKey<K = K>,
    K: SecretKey,
{
    public_nonce: CPK,
    u: K,
    v: K,
    // Double the memory, but as_bytes() requires a reference
    raw_bytes: Vec<u8>,
    // Remove if possible
    phantom: PhantomData<PK>,
}

impl<CPK, PK, K> CompressedCommitmentSignature<CPK, PK, K>
where
    CPK: CompressedPublicKey<PK>,
    PK: PublicKey<K = K>,
    K: SecretKey,
{
    pub fn new(public_nonce: CPK, u: K, v: K) -> Self {
        let mut raw_bytes = Vec::from(public_nonce.as_bytes());
        raw_bytes.extend(u.as_bytes());
        raw_bytes.extend(v.as_bytes());
        Self {
            public_nonce,
            u,
            v,
            raw_bytes,
            phantom: Default::default(),
        }
    }

    pub fn public_nonce(&self) -> &CPK {
        &self.public_nonce
    }

    pub fn u(&self) -> &K {
        &self.u
    }

    pub fn v(&self) -> &K {
        &self.v
    }
}

impl<CPK, PK, K> ByteArray for CompressedCommitmentSignature<CPK, PK, K>
where
    CPK: CompressedPublicKey<PK>,
    PK: PublicKey<K = K>,
    K: SecretKey,
{
    fn from_bytes(bytes: &[u8]) -> Result<Self, ByteArrayError> {
        if bytes.is_empty() {
            return Ok(Default::default());
        }
        let mut end = CPK::key_length();
        let public_nonce = CPK::from_bytes(&bytes[0..end])?;
        let mut start = end;
        end += K::key_length();
        let u = K::from_bytes(&bytes[start..end])?;
        start = end;
        end += K::key_length();
        let v = K::from_bytes(&bytes[start..end])?;
        Ok(Self {
            public_nonce,
            u,
            v,
            raw_bytes: Vec::from(bytes),
            phantom: PhantomData::default(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        self.raw_bytes.as_slice()
    }
}
