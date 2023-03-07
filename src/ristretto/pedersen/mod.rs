// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Pederson commitments utilities

use core::{borrow::Borrow, iter::Sum};

use curve25519_dalek::{
    constants::{RISTRETTO_BASEPOINT_COMPRESSED, RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};

use crate::{
    commitment::HomomorphicCommitment,
    ristretto::{
        constants::{RISTRETTO_NUMS_POINTS, RISTRETTO_NUMS_POINTS_COMPRESSED, RISTRETTO_NUMS_TABLE_0},
        RistrettoPublicKey,
    },
};

pub mod commitment_factory;
pub mod extended_commitment_factory;

/// The default generator on a Pedersen commitment used for the blinding factor
pub const RISTRETTO_PEDERSEN_G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
/// The default generator on a Pedersen commitment used for the blinding factor in a compressed form
pub const RISTRETTO_PEDERSEN_G_COMPRESSED: CompressedRistretto = RISTRETTO_BASEPOINT_COMPRESSED;
lazy_static! {
    /// The default generator on a Pedersen commitment used for the value
    pub static ref RISTRETTO_PEDERSEN_H: RistrettoPoint = RISTRETTO_NUMS_POINTS[0];
    /// The default generator on a Pedersen commitment used for the value in a compressed form
    pub static ref RISTRETTO_PEDERSEN_H_COMPRESSED: CompressedRistretto = RISTRETTO_NUMS_POINTS_COMPRESSED[0];
}

/// The Pedersen commitment
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

pub(crate) fn scalar_mul_with_pre_computation_tables(k: &Scalar, v: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_TABLE * k + &*RISTRETTO_NUMS_TABLE_0 * v
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
