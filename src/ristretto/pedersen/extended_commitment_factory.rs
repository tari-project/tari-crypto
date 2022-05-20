use bulletproofs_plus::{generators::pedersen_gens::ExtensionDegree, PedersenGens};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

use crate::{
    commitment::{ExtendedHomomorphicCommitmentFactory, HomomorphicCommitment},
    errors::RangeProofError,
    ristretto::{
        constants::{RISTRETTO_NUMS_POINTS, RISTRETTO_NUMS_POINTS_COMPRESSED},
        pedersen::{
            PedersenCommitment,
            RISTRETTO_PEDERSEN_G,
            RISTRETTO_PEDERSEN_G_COMPRESSED,
            RISTRETTO_PEDERSEN_H,
            RISTRETTO_PEDERSEN_H_COMPRESSED,
        },
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

/// Generates extended Pederson commitments `sum(k_i.G_i) + v.H` using the provided base
/// [RistrettoPoints](curve25519_dalek::ristretto::RistrettoPoints).
/// Notes:
///  - Homomorphism with public key only holds for extended commitments with `ExtensionDegree::Zero`
///  - 'Ord' and 'PartialOrd' are undefined for extended commitments other than `ExtensionDegree::Zero`
#[derive(Debug, PartialEq, Clone)]
pub struct ExtendedPedersenCommitmentFactory(pub(crate) PedersenGens<RistrettoPoint>);

impl ExtendedPedersenCommitmentFactory {
    /// Create a new Extended Pedersen Ristretto Commitment factory for the required extension degree using
    /// pre-calculated compressed constants - we only hold references to the static generator points.
    pub fn new_with_extension_degree(extension_degree: ExtensionDegree) -> Result<Self, RangeProofError> {
        if extension_degree as usize > RISTRETTO_NUMS_POINTS.len() ||
            extension_degree as usize > RISTRETTO_NUMS_POINTS_COMPRESSED.len()
        {
            return Err(RangeProofError::ExtensionDegree(
                "Not enough Ristretto NUMS points to construct the extended commitment factory".to_string(),
            ));
        }
        let mut g_base_vec = Vec::with_capacity(extension_degree as usize);
        g_base_vec.push(RISTRETTO_PEDERSEN_G);
        let mut g_base_compressed_vec = Vec::with_capacity(extension_degree as usize);
        g_base_compressed_vec.push(RISTRETTO_PEDERSEN_G_COMPRESSED);
        for i in 1..extension_degree as usize {
            g_base_vec.push(RISTRETTO_NUMS_POINTS[i]);
            g_base_compressed_vec.push(RISTRETTO_NUMS_POINTS_COMPRESSED[i]);
        }
        Ok(Self(PedersenGens {
            h_base: *RISTRETTO_PEDERSEN_H,
            h_base_compressed: *RISTRETTO_PEDERSEN_H_COMPRESSED,
            g_base_vec,
            g_base_compressed_vec,
            extension_degree,
        }))
    }
}

impl Default for ExtendedPedersenCommitmentFactory {
    /// The default Extended Pedersen Ristretto Commitment factory is of extension degree Zero; this corresponds to
    /// the default non extended Pedersen Ristretto Commitment factory.
    fn default() -> Self {
        Self::new_with_extension_degree(ExtensionDegree::Zero).expect("Ristretto default base points not defined!")
    }
}

impl ExtendedHomomorphicCommitmentFactory for ExtendedPedersenCommitmentFactory {
    type P = RistrettoPublicKey;

    fn commit(
        &self,
        k_i: &[RistrettoSecretKey],
        v: &RistrettoSecretKey,
    ) -> Result<PedersenCommitment, RangeProofError> {
        let k_i: Vec<Scalar> = k_i.to_vec().iter().map(|k| k.0).collect();
        let c = self
            .0
            .commit(v.0, &k_i)
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))?;
        Ok(HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c)))
    }

    fn zero(&self) -> PedersenCommitment {
        let extension_degree = self.0.extension_degree as usize;
        let zero = vec![Scalar::zero(); extension_degree + 1];
        let mut points = Vec::with_capacity(extension_degree + 1);
        points.push(self.0.h_base);
        points.append(&mut self.0.g_base_vec.clone());
        let c = RistrettoPoint::multiscalar_mul(&zero, &self.0.g_base_vec);
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c))
    }

    fn open(
        &self,
        k_i: &[RistrettoSecretKey],
        v: &RistrettoSecretKey,
        commitment: &PedersenCommitment,
    ) -> Result<bool, RangeProofError> {
        let c_test = self
            .commit(k_i, v)
            .map_err(|e| RangeProofError::ExtensionDegree(e.to_string()))?;
        Ok(commitment == &c_test)
    }

    fn commit_value(&self, k_i: &[RistrettoSecretKey], value: u64) -> Result<PedersenCommitment, RangeProofError> {
        let v = RistrettoSecretKey::from(value);
        self.commit(k_i, &v)
    }

    fn open_value(
        &self,
        k_i: &[RistrettoSecretKey],
        v: u64,
        commitment: &PedersenCommitment,
    ) -> Result<bool, RangeProofError> {
        let kv = RistrettoSecretKey::from(v);
        self.open(k_i, &kv, commitment)
    }
}

#[cfg(test)]
mod test {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use bulletproofs_plus::generators::pedersen_gens::ExtensionDegree;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use tari_utilities::message_format::MessageFormat;

    use crate::{
        commitment::ExtendedHomomorphicCommitmentFactory,
        keys::{PublicKey, SecretKey},
        ristretto::{
            constants::RISTRETTO_NUMS_POINTS,
            pedersen::{
                extended_commitment_factory::ExtendedPedersenCommitmentFactory,
                PedersenCommitment,
                RISTRETTO_PEDERSEN_G,
                RISTRETTO_PEDERSEN_H,
            },
            RistrettoPublicKey,
            RistrettoSecretKey,
        },
    };

    static EXTENSION_DEGREE: [ExtensionDegree; 6] = [
        ExtensionDegree::Zero,
        ExtensionDegree::One,
        ExtensionDegree::Two,
        ExtensionDegree::Three,
        ExtensionDegree::Four,
        ExtensionDegree::Five,
    ];

    #[test]
    fn check_default_base() {
        let factory = ExtendedPedersenCommitmentFactory::default();
        assert_eq!(factory.0.g_base_vec[0], RISTRETTO_PEDERSEN_G);
        assert_eq!(factory.0.h_base, *RISTRETTO_PEDERSEN_H);
        assert_eq!(
            factory,
            ExtendedPedersenCommitmentFactory::new_with_extension_degree(ExtensionDegree::Zero).unwrap()
        );
    }

    /// Simple test for open for each extension degree:
    /// - Generate 100 random sets of scalars and calculate the Pedersen commitment for them.
    /// - Check that the commitment = sum(k_i.G_i) + v.H, and that `open` returns `true` for `open(k_i, v)`
    #[test]
    #[allow(non_snake_case)]
    fn check_open() {
        let H = *RISTRETTO_PEDERSEN_H;
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            for _ in 0..25 {
                let v = RistrettoSecretKey::random(&mut rng);
                let k_i = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let c = factory.commit(&k_i, &v).unwrap();
                let mut c_calc: RistrettoPoint = v.0 * H + k_i[0].0 * RISTRETTO_PEDERSEN_G;
                for i in 1..(extension_degree as usize) {
                    c_calc += k_i[i].0 * RISTRETTO_NUMS_POINTS[i];
                }
                assert_eq!(RistrettoPoint::from(c.as_public_key()), c_calc);
                assert!(factory.open(&k_i, &v, &c).unwrap());
                // A different value doesn't open the commitment
                assert!(!factory.open(&k_i, &(&v + &v), &c).unwrap());
                // A different blinding factor doesn't open the commitment
                let mut not_k = k_i;
                not_k[0] = &not_k[0] + v.clone();
                assert!(!factory.open(&not_k, &v, &c).unwrap());
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
    fn check_homomorphism() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            for _ in 0..25 {
                let v1 = RistrettoSecretKey::random(&mut rng);
                let v2 = RistrettoSecretKey::random(&mut rng);
                let v_sum = &v1 + &v2;
                let k1_i = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let k2_i = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                let mut k_sum_i = Vec::with_capacity(extension_degree as usize);
                for i in 0..extension_degree as usize {
                    k_sum_i.push(&k1_i[i] + &k2_i[i]);
                }
                let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
                let c1 = factory.commit(&k1_i, &v1).unwrap();
                let c2 = factory.commit(&k2_i, &v2).unwrap();
                let c_sum = &c1 + &c2;
                let c_sum2 = factory.commit(&k_sum_i, &v_sum).unwrap();
                assert!(factory.open(&k1_i, &v1, &c1).unwrap());
                assert!(factory.open(&k2_i, &v2, &c2).unwrap());
                assert_eq!(c_sum, c_sum2);
                assert!(factory.open(&k_sum_i, &v_sum, &c_sum).unwrap());
            }
        }
    }

    /// Test addition of a public key to a homomorphic commitment for extended commitments with`ExtensionDegree::Zero`.
    /// $$
    ///   C = C_1 + P = (v1.H + sum(k1_i.G_i)) + sum(k2_i.G_i)) = v1.H + (k1 + sum(k1_i))).G
    /// $$
    /// and
    /// `open(k1+k2, v1)` is true for _C_
    /// Note: Homomorphism with public key only holds for extended commitments with`ExtensionDegree::Zero`
    #[test]
    fn check_homomorphism_with_public_key() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            // Left-hand side
            let v1 = RistrettoSecretKey::random(&mut rng);
            let k1_i = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let c1 = factory.commit(&k1_i, &v1).unwrap();
            let mut k2_i = Vec::with_capacity(extension_degree as usize);
            let mut k2_pub_i = Vec::with_capacity(extension_degree as usize);
            for _i in 0..extension_degree as usize {
                let (k2, k2_pub) = RistrettoPublicKey::random_keypair(&mut rng);
                k2_i.push(k2);
                k2_pub_i.push(k2_pub);
            }
            let mut c_sum = c1.0;
            for k2_pub in &k2_pub_i {
                c_sum = c_sum + k2_pub.clone();
            }
            // Right-hand side
            let mut k_sum_i = Vec::with_capacity(extension_degree as usize);
            for i in 0..extension_degree as usize {
                k_sum_i.push(&k1_i[i] + &k2_i[i]);
            }
            let c2 = factory.commit(&k_sum_i, &v1).unwrap();
            // Test
            assert!(factory.open(&k_sum_i, &v1, &c2).unwrap());
            match extension_degree {
                ExtensionDegree::Zero => {
                    assert_eq!(c_sum, c2.0);
                },
                _ => {
                    assert_ne!(c_sum, c2.0);
                },
            }
        }
    }

    /// Test addition of individual homomorphic commitments to be equal to a single vector homomorphic commitment for
    /// extended commitments.
    /// $$
    ///   sum(C_j) = sum((v.H + sum(k_i.G_i))_j) = sum(v_j).H + sum(sum(k_i.G_i)_j)
    /// $$
    /// and
    /// `open(sum(sum(k_i)_j), sum(v_j))` is true for `sum(C_j)`
    /// Note: Homomorphism with public key only holds for extended commitments with`ExtensionDegree::Zero`
    #[test]
    fn sum_commitment_vector() {
        let mut rng = rand::thread_rng();
        let v_zero = RistrettoSecretKey::default();
        let k_zero = vec![RistrettoSecretKey::default(); *EXTENSION_DEGREE.iter().max().unwrap() as usize];
        for extension_degree in EXTENSION_DEGREE {
            let mut v_sum = RistrettoSecretKey::default();
            let mut k_sum = vec![RistrettoSecretKey::default(); extension_degree as usize];
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let mut c_sum = factory.commit(&k_zero[0..extension_degree as usize], &v_zero).unwrap();
            let mut commitments = Vec::with_capacity(25);
            for _ in 0..25 {
                let v = RistrettoSecretKey::random(&mut rng);
                v_sum = &v_sum + &v;
                let k_i = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
                for i in 0..extension_degree as usize {
                    k_sum[i] = &k_sum[i] + &k_i[i];
                }
                let c = factory.commit(&k_i, &v).unwrap();
                c_sum = &c_sum + &c;
                commitments.push(c);
            }
            assert!(factory.open(&k_sum, &v_sum, &c_sum).unwrap());
            assert_eq!(c_sum, commitments.iter().sum());
        }
    }

    #[test]
    fn serialize_deserialize() {
        let mut rng = rand::thread_rng();
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let k = vec![RistrettoSecretKey::random(&mut rng); extension_degree as usize];
            let c = factory.commit_value(&k, 420).unwrap();
            // Base64
            let ser_c = c.to_base64().unwrap();
            let c2 = PedersenCommitment::from_base64(&ser_c).unwrap();
            assert!(factory.open_value(&k, 420, &c2).unwrap());
            // MessagePack
            let ser_c = c.to_binary().unwrap();
            let c2 = PedersenCommitment::from_binary(&ser_c).unwrap();
            assert!(factory.open_value(&k, 420, &c2).unwrap());
            // Invalid Base64
            assert!(PedersenCommitment::from_base64("bad@ser$").is_err());
        }
    }

    #[test]
    fn derived_methods() {
        for extension_degree in EXTENSION_DEGREE {
            let factory = ExtendedPedersenCommitmentFactory::new_with_extension_degree(extension_degree).unwrap();
            let k = vec![RistrettoSecretKey::from(1024); extension_degree as usize];
            let c1 = factory.commit_value(&k, 2048).unwrap();
            let mut hasher = DefaultHasher::new();
            c1.hash(&mut hasher);
            let c2 = c1.clone();
            let c3 = factory.commit_value(&k, 2049).unwrap();

            // Test 'clone`
            assert_eq!(c1, c2);
            assert_ne!(c2, c3);

            // Note! 'Ord' and 'PartialOrd' are undefined for extended commitments with extension degree other than Zero
            match extension_degree {
                ExtensionDegree::Zero => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(9801c7785217e0c973e9b85508c6eebcb74b257a6f825630e17282b81b7fcd78)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "1ef11e8d243c886e");
                    // test 'Ord' and 'PartialOrd'
                    assert!(c2 > c3);
                    assert!(c3 < c2);
                    assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Greater));
                },
                ExtensionDegree::One => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(42a14804076ba9515be21a519eb1914d3ae1dc3c0237f387bad267a1596c0900)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "77144935b6bfdef2");
                },
                ExtensionDegree::Two => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(3232b10a480df84addc7fd9c89ba0225dc586ab907b1ea48e36395dbc1f8013a)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "7d135652dedbd469");
                },
                ExtensionDegree::Three => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(128ae4d7b6ee6d441d6ca156e8a0847edd116a5528e65afd0ad7428d2704147d)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "a5015615878d2095");
                },
                ExtensionDegree::Four => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(a0f3593cb6a5261e025da8cee5ccd6e102fe365cf544998fd55bb2ec0222f707)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "ea1eb5e67730ac49");
                },
                ExtensionDegree::Five => {
                    // Test 'Debug'
                    assert_eq!(
                        format!("{:?}", c1),
                        "HomomorphicCommitment(7cec35074259cad0b5d3022b29f6e9d5526ed3923d802faffaa64d1829bce67f)"
                    );
                    // Test hashing
                    let result = format!("{:x}", hasher.finish());
                    assert_eq!(&result, "1a90510f34ef25ed");
                },
            }
        }
    }
}
