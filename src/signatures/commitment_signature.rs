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
    keys::{PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let e = match K::from_bytes(&challenge) {
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
        match self.public_nonce().cmp(&other.public_nonce()) {
            Ordering::Equal => {
                let this_u = self.u().as_bytes();
                let that_u = other.u().as_bytes();
                match this_u.cmp(&that_u) {
                    Ordering::Equal => {
                        let this = self.v().as_bytes();
                        let that = other.v().as_bytes();
                        this.cmp(&that)
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
        state.write(&[self.public_nonce().as_bytes(), self.u().as_bytes(), self.v().as_bytes()].concat())
    }
}
