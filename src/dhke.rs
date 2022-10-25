// Copyright 2022 The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The robotic innards of a Diffie-Hellman key exchange (DHKE) producing a shared secret.
//! Even though the result of a DHKE is the same type as a public key, it is typically treated as a secret value.
//! To make this work more safely, we ensure that a DHKE result is cleared after use (but beware of subsequent copies or
//! moves). Because a DHKE shared secret is intended to be used in further key derivation, the only visibility into it
//! is as a byte array; it's not possible to directly extract the underlying public key type, and you probably shouldn't
//! clone the byte array without a very good reason. If you need the underlying public key itself, you probably should
//! be using something else.

use std::ops::Mul;

use zeroize::Zeroize;

use crate::keys::PublicKey;

/// A type to hold a DH secret key.
pub struct DiffieHellmanSharedSecret<P>(P)
where P: Zeroize;

impl<P> DiffieHellmanSharedSecret<P>
where
    P: PublicKey + Zeroize,
    for<'a> &'a <P as PublicKey>::K: Mul<&'a P, Output = P>,
{
    /// Perform a Diffie-Hellman key exchange
    pub fn new(sk: &P::K, pk: &P) -> Self {
        Self(sk * pk)
    }

    /// Get the shared secret as a byte array
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<P> Zeroize for DiffieHellmanSharedSecret<P>
where P: Zeroize
{
    /// Zeroize the shared secret's underlying public key
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<P> Drop for DiffieHellmanSharedSecret<P>
where P: Zeroize
{
    /// Zeroize the shared secret when out of scope or otherwise dropped
    fn drop(&mut self) {
        self.zeroize();
    }
}
