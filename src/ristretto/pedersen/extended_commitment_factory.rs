// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Extended commitments are commitments that have more than one blinding factor.

use alloc::vec::Vec;
use core::{borrow::Borrow, iter::once};

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul},
};
use zeroize::Zeroize;

#[cfg(feature = "precomputed_tables")]
use crate::ristretto::pedersen::scalar_mul_with_pre_computation_tables;
use crate::{
    alloc::string::ToString,
    commitment::{
        ExtendedHomomorphicCommitmentFactory,
        ExtensionDegree,
        HomomorphicCommitment,
        HomomorphicCommitmentFactory,
    },
    errors::CommitmentError,
    ristretto::{
        constants::{ristretto_nums_points, RISTRETTO_NUMS_POINTS_COMPRESSED},
        pedersen::{
            ristretto_pedersen_h,
            ristretto_pedersen_h_compressed,
            PedersenCommitment,
            RISTRETTO_PEDERSEN_G,
            RISTRETTO_PEDERSEN_G_COMPRESSED,
        },
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

/// Generates extended Pederson commitments `sum(k_i.G_i) + v.H` using the provided base
/// [RistrettoPoints](curve25519_dalek::ristretto::RistrettoPoints).
/// Notes:
///  - Homomorphism with public key only holds for extended commitments with `ExtensionDegree::DefaultPedersen`
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ExtendedPedersenCommitmentFactory {
    /// Base for the committed value
    pub(crate) h_base: RistrettoPoint,
    /// Compressed base for the committed value
    pub(crate) h_base_compressed: CompressedRistretto,
    /// Base for the blinding factor vector
    pub(crate) g_base_vec: Vec<RistrettoPoint>,
    /// Compressed base for the blinding factor vector
    pub(crate) g_base_compressed_vec: Vec<CompressedRistretto>,
    /// Blinding factor extension degree
    pub(crate) extension_degree: ExtensionDegree,
}

impl ExtendedPedersenCommitmentFactory {
    /// Create a new Extended Pedersen Ristretto Commitment factory for the required extension degree using
    /// pre-calculated compressed constants - we only hold references to the static generator points.
    pub fn new_with_extension_degree(extension_degree: ExtensionDegree) -> Result<Self, CommitmentError> {
        if extension_degree as usize > ristretto_nums_points().len() ||
            extension_degree as usize > RISTRETTO_NUMS_POINTS_COMPRESSED.len()
        {
            return Err(CommitmentError::CommitmentExtensionDegree {
                reason: "Not enough Ristretto NUMS points to construct the extended commitment factory".to_string(),
            });
        }
        let g_base_vec = once(&RISTRETTO_PEDERSEN_G)
            .chain(ristretto_nums_points()[1..extension_degree as usize].iter())
            .copied()
            .collect();
        let g_base_compressed_vec = once(&RISTRETTO_PEDERSEN_G_COMPRESSED)
            .chain(RISTRETTO_NUMS_POINTS_COMPRESSED[1..extension_degree as usize].iter())
            .copied()
            .collect();
        Ok(Self {
            h_base: *ristretto_pedersen_h(),
            h_base_compressed: *ristretto_pedersen_h_compressed(),
            g_base_vec,
            g_base_compressed_vec,
            extension_degree,
        })
    }

    /// Creates a Pedersen commitment using the value scalar and a blinding factor vector
    fn commit_scalars(
        &self,
        value: &Scalar,
        blinding_factors: &[Scalar],
    ) -> Result<RistrettoPoint, CommitmentError>
    where
        for<'a> &'a Scalar: Borrow<Scalar>,
    {
        if blinding_factors.is_empty() || blinding_factors.len() > self.extension_degree as usize {
            Err(CommitmentError::CommitmentExtensionDegree {
                reason: "blinding vector".to_string(),
            })
        } else if blinding_factors.len() == 1 &&
            (self.g_base_vec[0], self.h_base) == (RISTRETTO_PEDERSEN_G, *ristretto_pedersen_h())
        {
            #[cfg(feature = "precomputed_tables")]
            {
                Ok(scalar_mul_with_pre_computation_tables(&blinding_factors[0], value))
            }
            #[cfg(not(feature = "precomputed_tables"))]
            {
                let scalars = once(value).chain(blinding_factors);
                let g_base_head = self.g_base_vec.iter().take(blinding_factors.len());
                let points = once(&self.h_base).chain(g_base_head);
                Ok(RistrettoPoint::multiscalar_mul(scalars, points))
            }
        } else {
            let scalars = once(value).chain(blinding_factors);
            let g_base_head = self.g_base_vec.iter().take(blinding_factors.len());
            let points = once(&self.h_base).chain(g_base_head);
            Ok(RistrettoPoint::multiscalar_mul(scalars, points))
        }
    }
}

impl Default for ExtendedPedersenCommitmentFactory {
    /// The default Extended Pedersen Ristretto Commitment factory is of extension degree Zero; this corresponds to
    /// the default non extended Pedersen Ristretto Commitment factory.
    fn default() -> Self {
        Self::new_with_extension_degree(ExtensionDegree::DefaultPedersen)
            .expect("Ristretto default base points not defined!")
    }
}

impl HomomorphicCommitmentFactory for ExtendedPedersenCommitmentFactory {
    type P = RistrettoPublicKey;

    fn commit(&self, k: &RistrettoSecretKey, v: &RistrettoSecretKey) -> PedersenCommitment {
        let c = self
            .commit_scalars(&v.0, &[k.0])
            .expect("Default commitments will never fail");
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c))
    }

    fn zero(&self) -> PedersenCommitment {
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(RistrettoPoint::identity()))
    }

    fn open(&self, k: &RistrettoSecretKey, v: &RistrettoSecretKey, commitment: &PedersenCommitment) -> bool {
        let c_test = self.commit(k, v);
        commitment == &c_test
    }

    fn commit_value(&self, k: &RistrettoSecretKey, value: u64) -> PedersenCommitment {
        let v = RistrettoSecretKey::from(value);
        self.commit(k, &v)
    }

    fn open_value(&self, k: &RistrettoSecretKey, v: u64, commitment: &PedersenCommitment) -> bool {
        let kv = RistrettoSecretKey::from(v);
        self.open(k, &kv, commitment)
    }
}

impl ExtendedHomomorphicCommitmentFactory for ExtendedPedersenCommitmentFactory {
    type P = RistrettoPublicKey;

    fn commit_extended(
        &self,
        k_vec: &[RistrettoSecretKey],
        v: &RistrettoSecretKey,
    ) -> Result<PedersenCommitment, CommitmentError> {
        let mut blinding_factors: Vec<Scalar> = k_vec.iter().map(|k| k.0).collect();
        let c = self.commit_scalars(&v.0, &blinding_factors)?;
        blinding_factors.zeroize();
        Ok(HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c)))
    }

    fn zero_extended(&self) -> PedersenCommitment {
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(RistrettoPoint::identity()))
    }

    fn open_extended(
        &self,
        k_vec: &[RistrettoSecretKey],
        v: &RistrettoSecretKey,
        commitment: &PedersenCommitment,
    ) -> Result<bool, CommitmentError> {
        let c_test = self
            .commit_extended(k_vec, v)
            .map_err(|e| CommitmentError::CommitmentExtensionDegree { reason: e.to_string() })?;
        Ok(commitment == &c_test)
    }

    fn commit_value_extended(
        &self,
        k_vec: &[RistrettoSecretKey],
        value: u64,
    ) -> Result<PedersenCommitment, CommitmentError> {
        let v = RistrettoSecretKey::from(value);
        self.commit_extended(k_vec, &v)
    }

    fn open_value_extended(
        &self,
        k_vec: &[RistrettoSecretKey],
        v: u64,
        commitment: &PedersenCommitment,
    ) -> Result<bool, CommitmentError> {
        let kv = RistrettoSecretKey::from(v);
        self.open_extended(k_vec, &kv, commitment)
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};
    use rand::rngs::ThreadRng;

    use crate::{
        commitment::{
            ExtendedHomomorphicCommitmentFactory,
            ExtensionDegree,
            HomomorphicCommitment,
            HomomorphicCommitmentFactory,
        },
        keys::{PublicKey, SecretKey},
        ristretto::{
            constants::ristretto_nums_points,
            pedersen::{
                commitment_factory::PedersenCommitmentFactory,
                extended_commitment_factory::ExtendedPedersenCommitmentFactory,
                ristretto_pedersen_h,
                RISTRETTO_PEDERSEN_G,
            },
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    static EXTENSION_DEGREE: [ExtensionDegree; 6] = [
        ExtensionDegree::DefaultPedersen,
        ExtensionDegree::AddOneBasePoint,
        ExtensionDegree::AddTwoBasePoints,
        ExtensionDegree::AddThreeBasePoints,
        ExtensionDegree::AddFourBasePoints,
        ExtensionDegree::AddFiveBasePoints,
    ];

    #[test]
    fn check_default_base() {
        let factory = ExtendedPedersenCommitmentFactory::default();
        assert_eq!(factory.g_base_vec[0], RISTRETTO_PEDERSEN_G);
        assert_eq!(factory.h_base, *ristretto_pedersen_h());
        assert_eq!(
            factory,
            ExtendedPedersenCommitmentFactory::new_with_extension_degree(ExtensionDegree::DefaultPedersen).unwrap()
        );
    }

    /// Default bases for PedersenCommitmentFactory and all extension degrees of ExtendedPedersenCommitmentFactory must
    /// be equal
    #[test]
    fn check_extended_bases_between_factories() {
        let factory_singular = PedersenCommitmentFactory::default();
        for extension_degree in EXTENSION_DEGREE {
            let factory_extended =
                ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            assert_eq!(factory_extended.extension_degree, extension_degree);
            assert_eq!(factory_singular.G, factory_extended.g_base_vec[0]);
            assert_eq!(factory_singular.H, factory_extended.h_base);
        }
    }

    #[test]
    /// Verify that the identity point is equal to a commitment to zero with a zero blinding factor vector on the base
    /// points
    fn check_zero_both_traits() {
        for extension_degree in EXTENSION_DEGREE {
            let zero_values = vec![Scalar::ZERO; extension_degree as usize + 1];
            let mut points = Vec::with_capacity(extension_degree as usize + 1);
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            points.push(factory.h_base);
            points.append(&mut factory.g_base_vec.clone());
            let c = RistrettoPoint::multiscalar_mul(&zero_values, &points);

            // HomomorphicCommitmentFactory
            assert_eq!(
                HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c)),
                ExtendedPedersenCommitmentFactory::zero(&factory)
            );

            // ExtendedHomomorphicCommitmentFactory
            assert_eq!(
                HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c)),
                ExtendedPedersenCommitmentFactory::zero_extended(&factory)
            );
        }
    }

    /// Simple test for open for each extension degree:
    /// - Generate random sets of scalars and calculate the Pedersen commitment for them.
    /// - Check that the commitment = sum(k_i.G_i) + v.H, and that `open` returns `true` for `open(k_i, v)`
    #[test]
    #[allow(non_snake_case)]
    fn check_open_both_traits() {
        let H = *ristretto_pedersen_h();
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            for _ in 0..25 {
                let v = RistrettoSecretKey::random(&mut rng);
                let k_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let c_extended = factory.commit_extended(&k_vec, &v).unwrap();
                let mut c_calc: RistrettoPoint = v.0 * H + k_vec[0].0 * RISTRETTO_PEDERSEN_G;
                #[allow(clippy::needless_range_loop)]
                for i in 1..(extension_degree as usize) {
                    c_calc += k_vec[i].0 * ristretto_nums_points()[i];
                }
                assert_eq!(RistrettoPoint::from(c_extended.as_public_key()), c_calc);

                // ExtendedHomomorphicCommitmentFactory
                // - Default open
                assert!(factory.open_extended(&k_vec, &v, &c_extended).unwrap());
                // - A different value doesn't open the commitment
                assert!(!factory.open_extended(&k_vec, &(&v + &v), &c_extended).unwrap());
                // - A different blinding factor doesn't open the commitment
                let mut not_k = k_vec.clone();
                not_k[0] = &not_k[0] + v.clone();
                assert!(!factory.open_extended(&not_k, &v, &c_extended).unwrap());

                // HomomorphicCommitmentFactory vs. ExtendedHomomorphicCommitmentFactory
                if extension_degree == ExtensionDegree::DefaultPedersen {
                    let c = factory.commit(&k_vec[0], &v);
                    assert_eq!(c, c_extended);
                    // - Default open
                    assert!(factory.open(&k_vec[0], &v, &c));
                    // - A different value doesn't open the commitment
                    assert!(!factory.open(&k_vec[0], &(&v + &v), &c));
                    // - A different blinding factor doesn't open the commitment
                    assert!(!factory.open(&not_k[0], &v, &c));
                }
            }
        }
    }

    /// Test for random sets of scalars that the homomorphic property holds. i.e.
    /// $$
    ///   C = C1 + C2 = sum((k1_i+k2_i).G_i) + (v1+v2).H
    /// $$
    /// and
    /// `open(k1_i+k2_i, v1+v2)` is true for _C_
    #[test]
    fn check_homomorphism_both_traits() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            for _ in 0..25 {
                let v1 = RistrettoSecretKey::random(&mut rng);
                let v2 = RistrettoSecretKey::random(&mut rng);
                let v_sum = &v1 + &v2;
                let k1_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let k2_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let mut k_sum_i = Vec::with_capacity(extension_degree as usize);
                for i in 0..extension_degree as usize {
                    k_sum_i.push(&k1_vec[i] + &k2_vec[i]);
                }
                let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();

                // ExtendedHomomorphicCommitmentFactory
                let c1_extended = factory.commit_extended(&k1_vec, &v1).unwrap();
                let c2_extended = factory.commit_extended(&k2_vec, &v2).unwrap();
                let c_sum_extended = &c1_extended + &c2_extended;
                let c_sum2_extended = factory.commit_extended(&k_sum_i, &v_sum).unwrap();
                assert!(factory.open_extended(&k1_vec, &v1, &c1_extended).unwrap());
                assert!(factory.open_extended(&k2_vec, &v2, &c2_extended).unwrap());
                assert_eq!(c_sum_extended, c_sum2_extended);
                assert!(factory.open_extended(&k_sum_i, &v_sum, &c_sum_extended).unwrap());

                // HomomorphicCommitmentFactory vs. ExtendedHomomorphicCommitmentFactory
                if extension_degree == ExtensionDegree::DefaultPedersen {
                    let c1 = factory.commit(&k1_vec[0], &v1);
                    assert_eq!(c1, c1_extended);
                    let c2 = factory.commit(&k2_vec[0], &v2);
                    assert_eq!(c2, c2_extended);
                    let c_sum = &c1 + &c2;
                    assert_eq!(c_sum, c_sum_extended);
                    let c_sum2 = factory.commit(&k_sum_i[0], &v_sum);
                    assert_eq!(c_sum2, c_sum2_extended);
                    assert!(factory.open(&k1_vec[0], &v1, &c1));
                    assert!(factory.open(&k2_vec[0], &v2, &c2));
                    assert_eq!(c_sum, c_sum2);
                    assert!(factory.open(&k_sum_i[0], &v_sum, &c_sum));
                }
            }
        }
    }

    /// Test addition of a public key to a homomorphic commitment.
    /// $$
    ///   C = C_1 + P = (v_1.H + k_1.G) + k_2.G = v_1.H + (k_1 + k_2).G
    /// $$
    /// and
    /// `open(k1+k2, v1)` is true for _C_
    #[test]
    fn check_homomorphism_with_public_key_singular() {
        let mut rng = rand::thread_rng();
        // Left-hand side
        let v1 = RistrettoSecretKey::random(&mut rng);
        let k1 = RistrettoSecretKey::random(&mut rng);
        let factory = ExtendedPedersenCommitmentFactory::default();
        let c1 = factory.commit(&k1, &v1);
        let (k2, k2_pub) = RistrettoPublicKey::random_keypair(&mut rng);
        let c_sum = &c1 + &k2_pub;
        // Right-hand side
        let c2 = factory.commit(&(&k1 + &k2), &v1);
        // Test
        assert_eq!(c_sum, c2);
        assert!(factory.open(&(&k1 + &k2), &v1, &c2));
    }

    fn scalar_random_not_zero(rng: &mut ThreadRng) -> Scalar {
        loop {
            let value = Scalar::random(rng);
            if value != Scalar::ZERO {
                return value;
            }
        }
    }

    // Try to create an extended 'RistrettoPublicKey'
    fn random_keypair_extended(
        factory: &ExtendedPedersenCommitmentFactory,
        extension_degree: ExtensionDegree,
        rng: &mut ThreadRng,
    ) -> (RistrettoSecretKey, RistrettoPublicKey) {
        let mut k_vec = vec![scalar_random_not_zero(rng)];
        if extension_degree != ExtensionDegree::DefaultPedersen {
            k_vec.append(&mut vec![Scalar::default(); extension_degree as usize - 1]);
        }
        (
            RistrettoSecretKey(k_vec[0]),
            RistrettoPublicKey::new_from_pk(RistrettoPoint::multiscalar_mul(k_vec, &factory.g_base_vec)),
        )
    }

    /// Test addition of a public key to a homomorphic commitment for extended commitments
    /// with`ExtensionDegree::DefaultPedersen`. $$
    ///   C = C_1 + P = (v1.H + sum(k1_i.G_i)) + k2.G_0 = v1.H + (k2 + sum(k1_i))).G
    /// $$
    /// and
    /// `open(k1+k2, v1)` is true for _C_
    /// Note: Homomorphism with public key only holds for extended commitments with`ExtensionDegree::DefaultPedersen`
    #[test]
    fn check_homomorphism_with_public_key_extended() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            // Left-hand side
            let v1 = RistrettoSecretKey::random(&mut rng);
            let k1_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let c1 = factory.commit_extended(&k1_vec, &v1).unwrap();
            let mut k2_vec = Vec::with_capacity(extension_degree as usize);
            let mut k2_pub_vec = Vec::with_capacity(extension_degree as usize);
            for _i in 0..extension_degree as usize {
                let (k2, k2_pub) = random_keypair_extended(&factory, extension_degree, &mut rng);
                k2_vec.push(k2);
                k2_pub_vec.push(k2_pub);
            }
            let mut c_sum = c1.0;
            for k2_pub in &k2_pub_vec {
                c_sum = c_sum + k2_pub.clone();
            }
            // Right-hand side
            let mut k_sum_vec = Vec::with_capacity(extension_degree as usize);
            for i in 0..extension_degree as usize {
                k_sum_vec.push(&k1_vec[i] + &k2_vec[i]);
            }
            let c2 = factory.commit_extended(&k_sum_vec, &v1).unwrap();
            // Test
            assert!(factory.open_extended(&k_sum_vec, &v1, &c2).unwrap());
            match extension_degree {
                ExtensionDegree::DefaultPedersen => {
                    assert_eq!(c_sum, c2.0);
                },
                _ => {
                    assert_ne!(c_sum, c2.0);
                },
            }
        }
    }

    /// Test addition of individual homomorphic commitments to be equal to a single vector homomorphic commitment.
    /// $$
    ///   sum(C_j) = sum((v.H + k.G)_j) = sum(v_j).H + sum(k_j).G
    /// $$
    /// and
    /// `open(sum(k_j), sum(v_j))` is true for `sum(C_j)`
    #[test]
    fn sum_commitment_vector_singular() {
        let mut rng = rand::thread_rng();
        let mut v_sum = RistrettoSecretKey::default();
        let mut k_sum = RistrettoSecretKey::default();
        let zero = RistrettoSecretKey::default();
        let commitment_factory = ExtendedPedersenCommitmentFactory::default();
        let mut c_sum = commitment_factory.commit(&zero, &zero);
        let mut commitments = Vec::with_capacity(100);
        for _ in 0..100 {
            let v = RistrettoSecretKey::random(&mut rng);
            v_sum = &v_sum + &v;
            let k = RistrettoSecretKey::random(&mut rng);
            k_sum = &k_sum + &k;
            let c = commitment_factory.commit(&k, &v);
            c_sum = &c_sum + &c;
            commitments.push(c);
        }
        assert!(commitment_factory.open(&k_sum, &v_sum, &c_sum));
        assert_eq!(c_sum, commitments.iter().sum());
    }

    /// Test addition of individual homomorphic commitments to be equal to a single vector homomorphic commitment for
    /// extended commitments.
    /// $$
    ///   sum(C_j) = sum((v.H + sum(k_i.G_i))_j) = sum(v_j).H + sum(sum(k_i.G_i)_j)
    /// $$
    /// and
    /// `open(sum(sum(k_i)_j), sum(v_j))` is true for `sum(C_j)`
    #[test]
    fn sum_commitment_vector_extended() {
        let mut rng = rand::thread_rng();
        let v_zero = RistrettoSecretKey::default();
        let k_zero = vec![RistrettoSecretKey::default(); ExtensionDegree::AddFiveBasePoints as usize];
        for extension_degree in EXTENSION_DEGREE {
            let mut v_sum = RistrettoSecretKey::default();
            let mut k_sum_vec = vec![RistrettoSecretKey::default(); extension_degree as usize];
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let mut c_sum = factory
                .commit_extended(&k_zero[0..extension_degree as usize], &v_zero)
                .unwrap();
            let mut commitments = Vec::with_capacity(25);
            for _ in 0..25 {
                let v = RistrettoSecretKey::random(&mut rng);
                v_sum = &v_sum + &v;
                let k_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                for i in 0..extension_degree as usize {
                    k_sum_vec[i] = &k_sum_vec[i] + &k_vec[i];
                }
                let c = factory.commit_extended(&k_vec, &v).unwrap();
                c_sum = &c_sum + &c;
                commitments.push(c);
            }
            assert!(factory.open_extended(&k_sum_vec, &v_sum, &c_sum).unwrap());
            assert_eq!(c_sum, commitments.iter().sum());
        }
    }

    #[cfg(feature = "serde")]
    mod test_serialize {
        use tari_utilities::message_format::MessageFormat;

        use super::*;
        use crate::ristretto::pedersen::PedersenCommitment;
        #[test]
        fn serialize_deserialize_singular() {
            let mut rng = rand::thread_rng();
            let factory = ExtendedPedersenCommitmentFactory::default();
            let k = RistrettoSecretKey::random(&mut rng);
            let c = factory.commit_value(&k, 420);
            // Base64
            let ser_c = c.to_base64().unwrap();
            let c2 = PedersenCommitment::from_base64(&ser_c).unwrap();
            assert!(factory.open_value(&k, 420, &c2));
            // MessagePack
            let ser_c = c.to_binary().unwrap();
            let c2 = PedersenCommitment::from_binary(&ser_c).unwrap();
            assert!(factory.open_value(&k, 420, &c2));
            // Invalid Base64
            assert!(PedersenCommitment::from_base64("bad@ser$").is_err());
        }

        #[test]
        fn serialize_deserialize_extended() {
            let mut rng = rand::thread_rng();
            for extension_degree in EXTENSION_DEGREE {
                let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
                let k_vec = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let c = factory.commit_value_extended(&k_vec, 420).unwrap();
                // Base64
                let ser_c = c.to_base64().unwrap();
                let c2 = PedersenCommitment::from_base64(&ser_c).unwrap();
                assert!(factory.open_value_extended(&k_vec, 420, &c2).unwrap());
                // MessagePack
                let ser_c = c.to_binary().unwrap();
                let c2 = PedersenCommitment::from_binary(&ser_c).unwrap();
                assert!(factory.open_value_extended(&k_vec, 420, &c2).unwrap());
                // Invalid Base64
                assert!(PedersenCommitment::from_base64("bad@ser$").is_err());
            }
        }
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn derived_methods_singular() {
        let factory = ExtendedPedersenCommitmentFactory::default();
        let k = RistrettoSecretKey::from(1024);
        let value = 2048;
        let c1 = factory.commit_value(&k, value);

        // Test 'Debug' implementation
        assert_eq!(
            format!("{c1:?}"),
            "HomomorphicCommitment(601cdc5c97e94bb16ae56f75430f8ab3ef4703c7d89ca9592e8acadc81629f0e)"
        );
        // Test 'Clone' implementation
        let c2 = c1.clone();
        assert_eq!(c1, c2);

        // Test hash implementation
        let mut hasher = DefaultHasher::new();
        c1.hash(&mut hasher);
        let result = format!("{:x}", hasher.finish());
        assert_eq!(&result, "699d38210741194e");

        // Test 'Ord' and 'PartialOrd' implementations
        let mut values = (value - 100..value).collect::<Vec<_>>();
        values.extend((value + 1..value + 101).collect::<Vec<_>>());
        let (mut tested_less_than, mut tested_greater_than) = (false, false);
        for val in values {
            let c3 = factory.commit_value(&k, val);
            assert_ne!(c2, c3);
            assert_ne!(c2.cmp(&c3), c3.cmp(&c2));
            if c2 > c3 {
                assert!(c3 < c2);
                assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Greater));
                assert!(matches!(c3.cmp(&c2), std::cmp::Ordering::Less));
                tested_less_than = true;
            }
            if c2 < c3 {
                assert!(c3 > c2);
                assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Less));
                assert!(matches!(c3.cmp(&c2), std::cmp::Ordering::Greater));
                tested_greater_than = true;
            }
            if tested_less_than && tested_greater_than {
                break;
            }
        }
        assert!(
            tested_less_than && tested_greater_than,
            "Try extending the range of values to compare"
        );
    }

    #[test]
    fn derived_methods_extended() {
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let k_vec = vec![RistrettoSecretKey::from(1024); extension_degree as usize];
            let value = 2048;
            let c1 = factory.commit_value_extended(&k_vec, value).unwrap();

            // Test 'Clone` implementation
            let c2 = c1.clone();
            assert_eq!(c1, c2);

            // Test 'Debug' and hashing implementations
            let mut hasher = DefaultHasher::new();
            c1.hash(&mut hasher);
            match extension_degree {
                ExtensionDegree::DefaultPedersen => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(601cdc5c97e94bb16ae56f75430f8ab3ef4703c7d89ca9592e8acadc81629f0e)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "699d38210741194e");
                },
                ExtensionDegree::AddOneBasePoint => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(f0019440ae20b39ba55a88f27ebd7ca56857251beca1047a3b195dc93642d829)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "fb68d75431b3a0b0");
                },
                ExtensionDegree::AddTwoBasePoints => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(b09789e597115f592491009f18ef4ec13ba7018a77e9df1729f1e2611b237a06)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "61dd716dc29a5fc5");
                },
                ExtensionDegree::AddThreeBasePoints => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(f8356cbea349191683f84818ab5203e48b04fef42f812ddf7d9b92df966c8473)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "49e988f621628ebc");
                },
                ExtensionDegree::AddFourBasePoints => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(1e113af7e33ac15b328e298239f3796e5061a0863d1a69e297ee8d81ee6e1f22)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "aff1b9967c7bffe7");
                },
                ExtensionDegree::AddFiveBasePoints => {
                    assert_eq!(
                        format!("{c1:?}"),
                        "HomomorphicCommitment(126844ee6889dd065ccc0c47e16ea23697f72e6ecce70f5e3fef320d843c332e)"
                    );
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "e27df20b2dd195ee");
                },
            }

            // Test 'Ord' and 'PartialOrd' implementations
            let mut values = (value - 100..value).collect::<Vec<_>>();
            values.extend((value + 1..value + 101).collect::<Vec<_>>());
            let (mut tested_less_than, mut tested_greater_than) = (false, false);
            for val in values {
                let c3 = factory.commit_value_extended(&k_vec, val).unwrap();
                assert_ne!(c2, c3);
                assert_ne!(c2.cmp(&c3), c3.cmp(&c2));
                if c2 > c3 {
                    assert!(c3 < c2);
                    assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Greater));
                    assert!(matches!(c3.cmp(&c2), std::cmp::Ordering::Less));
                    tested_less_than = true;
                }
                if c2 < c3 {
                    assert!(c3 > c2);
                    assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Less));
                    assert!(matches!(c3.cmp(&c2), std::cmp::Ordering::Greater));
                    tested_greater_than = true;
                }
                if tested_less_than && tested_greater_than {
                    break;
                }
            }
            assert!(
                tested_less_than && tested_greater_than,
                "Try extending the range of values to compare"
            );
        }
    }
}
