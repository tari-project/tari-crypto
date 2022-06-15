// Copyright 2019 The Tari Project
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

use std::{borrow::Borrow, iter::Sum};

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT},
    ristretto::{CompressedRistretto, RistrettoPoint},
};

use crate::{
    commitment::HomomorphicCommitment,
    ristretto::{
        constants::{RISTRETTO_NUMS_POINTS, RISTRETTO_NUMS_POINTS_COMPRESSED},
        RistrettoPublicKey,
    },
};

pub mod commitment_factory;
pub mod extended_commitment_factory;

pub const RISTRETTO_PEDERSEN_G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub const RISTRETTO_PEDERSEN_G_COMPRESSED: CompressedRistretto = RISTRETTO_BASEPOINT_COMPRESSED;
lazy_static! {
    pub static ref RISTRETTO_PEDERSEN_H: RistrettoPoint = RISTRETTO_NUMS_POINTS[0];
    pub static ref RISTRETTO_PEDERSEN_H_COMPRESSED: CompressedRistretto = RISTRETTO_NUMS_POINTS_COMPRESSED[0];
}

pub type PedersenCommitment = HomomorphicCommitment<RistrettoPublicKey>;

impl<T> Sum<T> for PedersenCommitment
where T: Borrow<PedersenCommitment>
{
    fn sum<I>(iter: I) -> Self
    where I: Iterator<Item = T> {
        let mut total = RistrettoPoint::default();
        for c in iter {
            let commitment = c.borrow();
            total += RistrettoPoint::from(&commitment.0);
        }
        let sum = RistrettoPublicKey::new_from_pk(total);
        HomomorphicCommitment(sum)
    }
}

#[cfg(test)]
mod test {
    use tari_utilities::ByteArray;

    use crate::{
        commitment::{ExtendedHomomorphicCommitmentFactory, ExtensionDegree, HomomorphicCommitmentFactory},
        keys::{PublicKey, SecretKey},
        ristretto::{
            pedersen::{
                commitment_factory::PedersenCommitmentFactory,
                extended_commitment_factory::ExtendedPedersenCommitmentFactory,
                PedersenCommitment,
                RISTRETTO_PEDERSEN_G,
                RISTRETTO_PEDERSEN_H,
            },
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    #[test]
    fn pubkey_roundtrip() {
        let mut rng = rand::thread_rng();
        let (_, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let c = PedersenCommitment::from_public_key(&p);
        assert_eq!(c.as_public_key(), &p);
        let c2 = PedersenCommitment::from_bytes(c.as_bytes()).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn commitment_sub() {
        let mut rng = rand::thread_rng();
        let (_, a) = RistrettoPublicKey::random_keypair(&mut rng);
        let (_, b) = RistrettoPublicKey::random_keypair(&mut rng);
        let c = &a + &b;
        let a = PedersenCommitment::from_public_key(&a);
        let b = PedersenCommitment::from_public_key(&b);
        let c = PedersenCommitment::from_public_key(&c);
        assert_eq!(b, &c - &a);
    }

    #[test]
    fn check_g_ne_h() {
        assert_ne!(RISTRETTO_PEDERSEN_G, *RISTRETTO_PEDERSEN_H);
    }

    #[test]
    fn default_value() {
        let c = PedersenCommitment::default();
        assert_eq!(c, PedersenCommitment::from_public_key(&RistrettoPublicKey::default()));
    }

    /// Default bases for PedersenCommitmentFactory and ExtendedPedersenCommitmentFactory must be equal
    #[test]
    fn check_default_bases_between_factories() {
        let factory_singular = PedersenCommitmentFactory::default();
        let factory_extended = ExtendedPedersenCommitmentFactory::default();
        assert_eq!(factory_extended.extension_degree, ExtensionDegree::DefaultPedersen);
        assert_eq!(factory_singular.G, factory_extended.g_base_vec[0]);
        assert_eq!(factory_singular.H, factory_extended.h_base);
    }

    /// A PedersenCommitmentFactory commitment and ExtendedPedersenCommitmentFactory commitment of degree zero must be
    /// equal
    #[test]
    fn check_commitments_between_factories() {
        let factory_singular = PedersenCommitmentFactory::default();
        let factory_extended = ExtendedPedersenCommitmentFactory::default();
        let mut rng = rand::thread_rng();
        let v = RistrettoSecretKey::random(&mut rng);
        let k = RistrettoSecretKey::random(&mut rng);
        let c_singular = factory_singular.commit(&k, &v);
        let c_extended = factory_extended.commit_extended(&[k], &v).unwrap();
        assert_eq!(c_singular, c_extended);
    }
}
