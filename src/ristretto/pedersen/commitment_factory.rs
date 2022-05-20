use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

use crate::{
    commitment::{HomomorphicCommitment, HomomorphicCommitmentFactory},
    ristretto::{
        pedersen::{PedersenCommitment, RISTRETTO_PEDERSEN_G, RISTRETTO_PEDERSEN_H},
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
};

/// Generates Pederson commitments `k.G + v.H` using the provided base
/// [RistrettoPoints](curve25519_dalek::ristretto::RistrettoPoints).
#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(non_snake_case)]
pub struct PedersenCommitmentFactory {
    pub(crate) G: RistrettoPoint,
    pub(crate) H: RistrettoPoint,
}

impl PedersenCommitmentFactory {
    /// Create a new Ristretto Commitment factory with the given points as the bases. It's very cheap to create
    /// factories, since we only hold references to the static generator points.
    #[allow(non_snake_case)]
    pub fn new(G: RistrettoPoint, H: RistrettoPoint) -> PedersenCommitmentFactory {
        PedersenCommitmentFactory { G, H }
    }
}

impl Default for PedersenCommitmentFactory {
    /// The default Ristretto Commitment factory uses the Base point for x25519 and its first Blake256 hash.
    fn default() -> Self {
        PedersenCommitmentFactory::new(RISTRETTO_PEDERSEN_G, *RISTRETTO_PEDERSEN_H)
    }
}

impl HomomorphicCommitmentFactory for PedersenCommitmentFactory {
    type P = RistrettoPublicKey;

    fn commit(&self, k: &RistrettoSecretKey, v: &RistrettoSecretKey) -> PedersenCommitment {
        let c = RistrettoPoint::multiscalar_mul(&[v.0, k.0], &[self.H, self.G]);
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c))
    }

    fn zero(&self) -> PedersenCommitment {
        let zero = Scalar::zero();
        let c = RistrettoPoint::multiscalar_mul(&[zero, zero], &[self.H, self.G]);
        HomomorphicCommitment(RistrettoPublicKey::new_from_pk(c))
    }

    fn open(&self, k: &RistrettoSecretKey, v: &RistrettoSecretKey, commitment: &PedersenCommitment) -> bool {
        let c_test = self.commit(k, v);
        commitment.0 == c_test.0
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

#[cfg(test)]
mod test {
    use std::{
        collections::hash_map::DefaultHasher,
        convert::From,
        hash::{Hash, Hasher},
    };

    use tari_utilities::message_format::MessageFormat;

    use super::*;
    use crate::{
        commitment::HomomorphicCommitmentFactory,
        keys::{PublicKey, SecretKey},
        ristretto::{pedersen::commitment_factory::PedersenCommitmentFactory, RistrettoSecretKey},
    };

    #[test]
    fn check_default_base() {
        let base = PedersenCommitmentFactory::default();
        assert_eq!(base.G, RISTRETTO_PEDERSEN_G);
        assert_eq!(base.H, *RISTRETTO_PEDERSEN_H)
    }

    /// Simple test for open: Generate 100 random sets of scalars and calculate the Pedersen commitment for them.
    /// Then check that the commitment = k.G + v.H, and that `open` returns `true` for `open(&k, &v)`
    #[test]
    #[allow(non_snake_case)]
    fn check_open() {
        let factory = PedersenCommitmentFactory::default();
        let H = *RISTRETTO_PEDERSEN_H;
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let v = RistrettoSecretKey::random(&mut rng);
            let k = RistrettoSecretKey::random(&mut rng);
            let c = factory.commit(&k, &v);
            let c_calc: RistrettoPoint = v.0 * H + k.0 * RISTRETTO_PEDERSEN_G;
            assert_eq!(RistrettoPoint::from(c.as_public_key()), c_calc);
            assert!(factory.open(&k, &v, &c));
            // A different value doesn't open the commitment
            assert!(!factory.open(&k, &(&v + &v), &c));
            // A different blinding factor doesn't open the commitment
            assert!(!factory.open(&(&k + &v), &v, &c));
        }
    }

    /// Test, for 100 random sets of scalars that the homomorphic property holds. i.e.
    /// $$
    ///   C = C_1 + C_2 = (k_1+k_2).G + (v_1+v_2).H
    /// $$
    /// and
    /// `open(k1+k2, v1+v2)` is true for _C_
    #[test]
    fn check_homomorphism() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let v1 = RistrettoSecretKey::random(&mut rng);
            let v2 = RistrettoSecretKey::random(&mut rng);
            let v_sum = &v1 + &v2;
            let k1 = RistrettoSecretKey::random(&mut rng);
            let k2 = RistrettoSecretKey::random(&mut rng);
            let k_sum = &k1 + &k2;
            let factory = PedersenCommitmentFactory::default();
            let c1 = factory.commit(&k1, &v1);
            let c2 = factory.commit(&k2, &v2);
            let c_sum = &c1 + &c2;
            let c_sum2 = factory.commit(&k_sum, &v_sum);
            assert!(factory.open(&k1, &v1, &c1));
            assert!(factory.open(&k2, &v2, &c2));
            assert_eq!(c_sum, c_sum2);
            assert!(factory.open(&k_sum, &v_sum, &c_sum));
        }
    }

    /// Test addition of a public key to a homomorphic commitment.
    /// $$
    ///   C = C_1 + P = (v_1.H + k_1.G) + k_2.G = v_1.H + (k_1 + k_2).G
    /// $$
    /// and
    /// `open(k1+k2, v1)` is true for _C_
    #[test]
    fn check_homomorphism_with_public_key() {
        let mut rng = rand::thread_rng();
        // Left-hand side
        let v1 = RistrettoSecretKey::random(&mut rng);
        let k1 = RistrettoSecretKey::random(&mut rng);
        let factory = PedersenCommitmentFactory::default();
        let c1 = factory.commit(&k1, &v1);
        let (k2, k2_pub) = RistrettoPublicKey::random_keypair(&mut rng);
        let c_sum = &c1 + &k2_pub;
        // Right-hand side
        let c2 = factory.commit(&(&k1 + &k2), &v1);
        // Test
        assert_eq!(c_sum, c2);
        assert!(factory.open(&(&k1 + &k2), &v1, &c2));
    }

    /// Test addition of individual homomorphic commitments to be equal to a single vector homomorphic commitment.
    /// $$
    ///   sum(C_j) = sum((v.H + k.G)_j) = sum(v_j).H + sum(k_j).G
    /// $$
    /// and
    /// `open(sum(k_j), sum(v_j))` is true for `sum(C_j)`
    #[test]
    fn sum_commitment_vector() {
        let mut rng = rand::thread_rng();
        let mut v_sum = RistrettoSecretKey::default();
        let mut k_sum = RistrettoSecretKey::default();
        let zero = RistrettoSecretKey::default();
        let commitment_factory = PedersenCommitmentFactory::default();
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

    #[test]
    fn serialize_deserialize() {
        let mut rng = rand::thread_rng();
        let factory = PedersenCommitmentFactory::default();
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
    fn derived_methods() {
        let factory = PedersenCommitmentFactory::default();
        let k = RistrettoSecretKey::from(1024);
        let c1 = factory.commit_value(&k, 2048);
        // Test Debug impl
        assert_eq!(
            format!("{:?}", c1),
            "HomomorphicCommitment(9801c7785217e0c973e9b85508c6eebcb74b257a6f825630e17282b81b7fcd78)"
        );
        // test Clone impl
        let c2 = c1.clone();
        assert_eq!(c1, c2);
        // test hash impl
        let mut hasher = DefaultHasher::new();
        c1.hash(&mut hasher);
        let result = format!("{:x}", hasher.finish());
        assert_eq!(&result, "1ef11e8d243c886e");
        // test Ord and PartialOrd impl
        let c3 = factory.commit_value(&k, 2049);
        assert!(c2 > c3);
        assert!(c2 != c3);
        assert!(c3 < c2);
        assert!(matches!(c2.cmp(&c3), std::cmp::Ordering::Greater));
    }
}
