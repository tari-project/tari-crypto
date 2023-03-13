// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! The Tari-compatible implementation of Ristretto based on the curve25519-dalek implementation
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::{Add, Mul, Sub},
};
use alloc::string::ToString;
#[cfg(feature = "borsh")]
use std::{io, io::Write};
use alloc::vec::Vec;

use blake2::Blake2b;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use digest::{consts::U64, Digest};
use once_cell::unsync::OnceCell;
use rand_core::{CryptoRng, RngCore};
use tari_utilities::{hex::Hex, ByteArray, ByteArrayError, Hashable};
#[cfg(feature = "zero")]
use zeroize::Zeroize;

use crate::{
    errors::HashingError,
    hashing::{DerivedKeyDomain, DomainSeparatedHasher, DomainSeparation},
    keys::{PublicKey, SecretKey},
};

/// The [SecretKey](trait.SecretKey.html) implementation for [Ristretto](https://ristretto.group) is a thin wrapper
/// around the Dalek [Scalar](struct.Scalar.html) type, representing a 256-bit integer (mod the group order).
///
/// ## Creating secret keys
/// [ByteArray](trait.ByteArray.html) and [SecretKeyFactory](trait.SecretKeyFactory.html) are implemented for
/// [SecretKey](struct .SecretKey.html), so any of the following work (note that hex strings and byte array are
/// little-endian):
///
/// ```edition2018
/// use rand;
/// use tari_crypto::{keys::SecretKey, ristretto::RistrettoSecretKey};
/// use tari_utilities::{hex::Hex, ByteArray};
///
/// let mut rng = rand::thread_rng();
/// let _k1 = RistrettoSecretKey::from_bytes(&[
///     1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     0, 0,
/// ]);
/// let _k2 = RistrettoSecretKey::from_hex(&"100000002000000030000000040000000");
/// let _k3 = RistrettoSecretKey::random(&mut rng);
/// ```
#[derive(Eq, Clone, Default)]
#[cfg_attr(feature = "zero", derive(Zeroize))]
// #[cfg_attr(feature = "zero", Zeroize(drop))]
pub struct RistrettoSecretKey(pub(crate) Scalar);

#[cfg(feature = "borsh")]
impl borsh::BorshSerialize for RistrettoSecretKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        borsh::BorshSerialize::serialize(&self.as_bytes(), writer)
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for RistrettoSecretKey {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        let bytes: Vec<u8> = borsh::BorshDeserialize::deserialize(buf)?;
        Self::from_bytes(bytes.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }
}

const SCALAR_LENGTH: usize = 32;
const PUBLIC_KEY_LENGTH: usize = 32;

//-----------------------------------------   Ristretto Secret Key    ------------------------------------------------//
impl SecretKey for RistrettoSecretKey {
    fn key_length() -> usize {
        SCALAR_LENGTH
    }

    /// Return a random secret key on the `ristretto255` curve using the supplied CSPRNG.
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        RistrettoSecretKey(Scalar::random(rng))
    }
}

//-------------------------------------  Ristretto Secret Key ByteArray  ---------------------------------------------//

impl ByteArray for RistrettoSecretKey {
    /// Create a secret key on the Ristretto255 curve using the given little-endian byte array. If the byte array is
    /// not exactly 32 bytes long, `from_bytes` returns an error. This function is guaranteed to return a valid key
    /// in the group since it performs a mod _l_ on the input.
    fn from_bytes(bytes: &[u8]) -> Result<RistrettoSecretKey, ByteArrayError>
    where Self: Sized {
        if bytes.len() != 32 {
            return Err(ByteArrayError::IncorrectLength {});
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(bytes);
        let k = Scalar::from_bytes_mod_order(a);
        Ok(RistrettoSecretKey(k))
    }

    /// Return the byte array for the secret key in little-endian order
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Hash for RistrettoSecretKey {
    /// Require the implementation of the Hash trait for Hashmaps
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialEq for RistrettoSecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

//----------------------------------   RistrettoSecretKey Debug --------------------------------------------//
impl fmt::Debug for RistrettoSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RistrettoSecretKey(***)")
    }
}

/// A secret key that can be printed with `Debug` or `Display`.
pub struct RevealedSecretKey<'a> {
    secret: &'a RistrettoSecretKey,
}

impl RistrettoSecretKey {
    /// Make a secret key printable.
    pub fn reveal(&self) -> RevealedSecretKey<'_> {
        RevealedSecretKey { secret: self }
    }
}

impl<'a> fmt::Display for RevealedSecretKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.secret.to_hex())
    }
}

impl<'a> fmt::Debug for RevealedSecretKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RistrettoSecretKey")
            .field(&self.secret.to_hex())
            .finish()
    }
}

//----------------------------------   RistrettoSecretKey Mul / Add / Sub --------------------------------------------//

impl<'a, 'b> Mul<&'b RistrettoPublicKey> for &'a RistrettoSecretKey {
    type Output = RistrettoPublicKey;

    fn mul(self, rhs: &'b RistrettoPublicKey) -> RistrettoPublicKey {
        let p = self.0 * rhs.point;
        RistrettoPublicKey::new_from_pk(p)
    }
}

impl<'a, 'b> Add<&'b RistrettoSecretKey> for &'a RistrettoSecretKey {
    type Output = RistrettoSecretKey;

    fn add(self, rhs: &'b RistrettoSecretKey) -> RistrettoSecretKey {
        let k = self.0 + rhs.0;
        RistrettoSecretKey(k)
    }
}

impl<'a, 'b> Sub<&'b RistrettoSecretKey> for &'a RistrettoSecretKey {
    type Output = RistrettoSecretKey;

    fn sub(self, rhs: &'b RistrettoSecretKey) -> RistrettoSecretKey {
        RistrettoSecretKey(self.0 - rhs.0)
    }
}

define_add_variants!(
    LHS = RistrettoSecretKey,
    RHS = RistrettoSecretKey,
    Output = RistrettoSecretKey
);
define_sub_variants!(
    LHS = RistrettoSecretKey,
    RHS = RistrettoSecretKey,
    Output = RistrettoSecretKey
);
define_mul_variants!(
    LHS = RistrettoSecretKey,
    RHS = RistrettoPublicKey,
    Output = RistrettoPublicKey
);

//---------------------------------------------      Conversions     -------------------------------------------------//

impl From<u64> for RistrettoSecretKey {
    fn from(v: u64) -> Self {
        let s = Scalar::from(v);
        RistrettoSecretKey(s)
    }
}

impl From<Scalar> for RistrettoSecretKey {
    fn from(s: Scalar) -> Self {
        RistrettoSecretKey(s)
    }
}

//---------------------------------------------      Borrow impl     -------------------------------------------------//

impl<'a> Borrow<Scalar> for &'a RistrettoSecretKey {
    fn borrow(&self) -> &Scalar {
        &self.0
    }
}

//--------------------------------------------- Ristretto Public Key -------------------------------------------------//

/// The [PublicKey](trait.PublicKey.html) implementation for `ristretto255` is a thin wrapper around the dalek
/// library's [RistrettoPoint](struct.RistrettoPoint.html).
///
/// ## Creating public keys
/// Both [PublicKey](trait.PublicKey.html) and [ByteArray](trait.ByteArray.html) are implemented on
/// `RistrettoPublicKey` so all of the following will work:
/// ```edition2018
/// use rand;
/// use tari_crypto::{
///     keys::{PublicKey, SecretKey},
///     ristretto::{RistrettoPublicKey, RistrettoSecretKey},
/// };
/// use tari_utilities::{hex::Hex, ByteArray};
///
/// let mut rng = rand::thread_rng();
/// let _p1 = RistrettoPublicKey::from_bytes(&[
///     224, 196, 24, 247, 200, 217, 196, 205, 215, 57, 91, 147, 234, 18, 79, 58, 217, 144, 33,
///     187, 104, 29, 252, 51, 2, 169, 217, 154, 46, 83, 230, 78,
/// ]);
/// let _p2 = RistrettoPublicKey::from_hex(
///     &"e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
/// );
/// let sk = RistrettoSecretKey::random(&mut rng);
/// let _p3 = RistrettoPublicKey::from_secret_key(&sk);
/// ```
#[derive(Clone)]
pub struct RistrettoPublicKey {
    point: RistrettoPoint,
    compressed: OnceCell<CompressedRistretto>,
}

#[cfg(feature = "borsh")]
impl borsh::BorshSerialize for RistrettoPublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        borsh::BorshSerialize::serialize(&self.as_bytes(), writer)
    }
}

#[cfg(feature = "borsh")]
impl borsh::BorshDeserialize for RistrettoPublicKey {
    fn deserialize(buf: &mut &[u8]) -> io::Result<Self> {
        let bytes: Vec<u8> = borsh::BorshDeserialize::deserialize(buf)?;
        Self::from_bytes(bytes.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    }
}

impl RistrettoPublicKey {
    // Private constructor
    pub(super) fn new_from_pk(pk: RistrettoPoint) -> Self {
        Self {
            point: pk,
            compressed: OnceCell::new(),
        }
    }

    fn new_from_compressed(compressed: CompressedRistretto) -> Option<Self> {
        compressed.decompress().map(|point| Self {
            compressed: compressed.into(),
            point,
        })
    }

    /// A verifiable group generator using a domain separated hasher
    pub fn new_generator(label: &'static str) -> Result<RistrettoPublicKey, HashingError> {
        // This function requires 512 bytes of data, so let's be opinionated here and use blake2b
        let hash = DomainSeparatedHasher::<Blake2b<U64>, RistrettoGeneratorPoint>::new_with_label(label).finalize();
        if hash.as_ref().len() < 64 {
            return Err(HashingError::DigestTooShort { bytes: 64 });
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(hash.as_ref());
        let point = RistrettoPoint::from_uniform_bytes(&bytes);
        Ok(RistrettoPublicKey::new_from_pk(point))
    }

    /// Return the embedded RistrettoPoint representation
    pub fn point(&self) -> RistrettoPoint {
        self.point
    }

    pub(super) fn compressed(&self) -> &CompressedRistretto {
        self.compressed.get_or_init(|| self.point.compress())
    }
}
#[cfg(feature = "zero")]
impl Zeroize for RistrettoPublicKey {
    /// Zeroizes both the point and (if it exists) the compressed point
    fn zeroize(&mut self) {
        self.point.zeroize();

        // Need to empty the cell
        if let Some(mut compressed) = self.compressed.take() {
            compressed.zeroize();
        }
    }
}

//---------------------------------------   Ristretto Hashing Applications  ------------------------------------------//

/// The Domain Separation Tag type for the KDF algorithm, version 1
pub struct RistrettoKdf;
impl DerivedKeyDomain for RistrettoKdf {
    type DerivedKeyType = RistrettoSecretKey;
}

impl DomainSeparation for RistrettoKdf {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.kdf.ristretto"
    }
}

/// A generator point on the Ristretto curve
pub struct RistrettoGeneratorPoint;

impl DomainSeparation for RistrettoGeneratorPoint {
    fn version() -> u8 {
        1
    }

    fn domain() -> &'static str {
        "com.tari.groups.ristretto"
    }
}

impl PublicKey for RistrettoPublicKey {
    type K = RistrettoSecretKey;

    const KEY_LEN: usize = PUBLIC_KEY_LENGTH;

    /// Generates a new Public key from the given secret key
    fn from_secret_key(k: &Self::K) -> RistrettoPublicKey {
        let pk = &k.0 * RISTRETTO_BASEPOINT_TABLE;
        RistrettoPublicKey::new_from_pk(pk)
    }

    fn batch_mul(scalars: &[Self::K], points: &[Self]) -> Self {
        let p = points.iter().map(|p| &p.point);
        let s = scalars.iter().map(|k| &k.0);
        let p = RistrettoPoint::multiscalar_mul(s, p);
        RistrettoPublicKey::new_from_pk(p)
    }
}

// Requires custom Hashable implementation for RistrettoPublicKey as CompressedRistretto doesnt implement this trait
impl Hashable for RistrettoPublicKey {
    fn hash(&self) -> Vec<u8> {
        Blake2b::<U64>::digest(self.as_bytes()).to_vec()
    }
}

impl Hash for RistrettoPublicKey {
    /// Require the implementation of the Hash trait for Hashmaps
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

//----------------------------------    Ristretto Public Key Default   -----------------------------------------------//

impl Default for RistrettoPublicKey {
    fn default() -> Self {
        RistrettoPublicKey::new_from_pk(RistrettoPoint::default())
    }
}

//------------------------------------ PublicKey Display impl ---------------------------------------------//

impl fmt::Display for RistrettoPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, false)
    }
}

impl RistrettoPublicKey {
    // Formats a 64 char hex string to a given width.
    // If w >= 64, we pad the result.
    // If 7 <= w < 64, we replace the middle of the string with "..."
    // If w <= 6, we return the first w chars of the string
    fn fmt_case(&self, f: &mut fmt::Formatter, uppercase: bool) -> fmt::Result {
        let mut hex = self.to_hex();
        if uppercase {
            hex = hex.to_uppercase();
        }
        if f.alternate() {
            hex = format!("0x{hex}");
        }
        match f.width() {
            None => f.write_str(hex.as_str()),
            Some(w @ 1..=6) => f.write_str(&hex[..w]),
            Some(w @ 7..=63) => {
                let left = (w - 3) / 2;
                let right = hex.len() - (w - left - 3);
                f.write_str(format!("{}...{}", &hex[..left], &hex[right..]).as_str())
            },
            _ => core::fmt::Display::fmt(&hex, f),
        }
    }
}

impl fmt::LowerHex for RistrettoPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, false)
    }
}

impl fmt::UpperHex for RistrettoPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, true)
    }
}

impl fmt::Debug for RistrettoPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

//------------------------------------ PublicKey PartialEq, Eq, Ord impl ---------------------------------------------//

impl PartialEq for RistrettoPublicKey {
    fn eq(&self, other: &RistrettoPublicKey) -> bool {
        // Although this is slower than `self.compressed == other.compressed`, expanded point comparison is an equal
        // time comparison
        self.point == other.point
    }
}

impl Eq for RistrettoPublicKey {}

impl PartialOrd for RistrettoPublicKey {
    fn partial_cmp(&self, other: &RistrettoPublicKey) -> Option<Ordering> {
        self.compressed().as_bytes().partial_cmp(other.compressed().as_bytes())
    }
}

impl Ord for RistrettoPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compressed().as_bytes().cmp(other.compressed().as_bytes())
    }
}

//---------------------------------- PublicKey ByteArray implementation  ---------------------------------------------//

impl ByteArray for RistrettoPublicKey {
    /// Create a new `RistrettoPublicKey` instance form the given byte array. The constructor returns errors under
    /// the following circumstances:
    /// * The byte array is not exactly 32 bytes
    /// * The byte array does not represent a valid (compressed) point on the ristretto255 curve
    fn from_bytes(bytes: &[u8]) -> Result<RistrettoPublicKey, ByteArrayError>
    where Self: Sized {
        // Check the length here, because The Ristretto constructor panics rather than returning an error
        if bytes.len() != 32 {
            return Err(ByteArrayError::IncorrectLength {});
        }
        let compressed = CompressedRistretto::from_slice(bytes).map_err(|_| ByteArrayError::ConversionError {
            reason: "Invalid Public key".to_string(),
        })?;
        match RistrettoPublicKey::new_from_compressed(compressed) {
            Some(p) => Ok(p),
            None => Err(ByteArrayError::ConversionError {
                reason: "Invalid compressed Ristretto point".to_string(),
            }),
        }
    }

    /// Return the little-endian byte array representation of the compressed public key
    fn as_bytes(&self) -> &[u8] {
        self.compressed().as_bytes()
    }
}

//----------------------------------         PublicKey Add / Sub / Mul   ---------------------------------------------//

impl<'a, 'b> Add<&'b RistrettoPublicKey> for &'a RistrettoPublicKey {
    type Output = RistrettoPublicKey;

    fn add(self, rhs: &'b RistrettoPublicKey) -> RistrettoPublicKey {
        let p_sum = self.point + rhs.point;
        RistrettoPublicKey::new_from_pk(p_sum)
    }
}

impl<'a, 'b> Sub<&'b RistrettoPublicKey> for &'a RistrettoPublicKey {
    type Output = RistrettoPublicKey;

    fn sub(self, rhs: &RistrettoPublicKey) -> RistrettoPublicKey {
        let p_sum = self.point - rhs.point;
        RistrettoPublicKey::new_from_pk(p_sum)
    }
}

impl<'a, 'b> Mul<&'b RistrettoSecretKey> for &'a RistrettoPublicKey {
    type Output = RistrettoPublicKey;

    fn mul(self, rhs: &'b RistrettoSecretKey) -> RistrettoPublicKey {
        let p = rhs.0 * self.point;
        RistrettoPublicKey::new_from_pk(p)
    }
}

impl<'a, 'b> Mul<&'b RistrettoSecretKey> for &'a RistrettoSecretKey {
    type Output = RistrettoSecretKey;

    fn mul(self, rhs: &'b RistrettoSecretKey) -> RistrettoSecretKey {
        let p = &rhs.0 * &self.0;
        RistrettoSecretKey(p)
    }
}

define_add_variants!(
    LHS = RistrettoPublicKey,
    RHS = RistrettoPublicKey,
    Output = RistrettoPublicKey
);
define_sub_variants!(
    LHS = RistrettoPublicKey,
    RHS = RistrettoPublicKey,
    Output = RistrettoPublicKey
);
define_mul_variants!(
    LHS = RistrettoPublicKey,
    RHS = RistrettoSecretKey,
    Output = RistrettoPublicKey
);
define_mul_variants!(
    LHS = RistrettoSecretKey,
    RHS = RistrettoSecretKey,
    Output = RistrettoSecretKey
);

//----------------------------------         PublicKey From implementations      -------------------------------------//

impl From<RistrettoSecretKey> for Scalar {
    fn from(k: RistrettoSecretKey) -> Self {
        k.0
    }
}

impl From<RistrettoPublicKey> for RistrettoPoint {
    fn from(pk: RistrettoPublicKey) -> Self {
        pk.point
    }
}

impl From<&RistrettoPublicKey> for RistrettoPoint {
    fn from(pk: &RistrettoPublicKey) -> Self {
        pk.point
    }
}

impl From<RistrettoPublicKey> for CompressedRistretto {
    fn from(pk: RistrettoPublicKey) -> Self {
        *pk.compressed()
    }
}

//--------------------------------------------------------------------------------------------------------------------//
//                                                     Tests                                                          //
//--------------------------------------------------------------------------------------------------------------------//

#[cfg(test)]
mod test {
    use tari_utilities::{message_format::MessageFormat, ByteArray};

    use super::*;
    use crate::{hash::blake2::Blake256, keys::PublicKey, ristretto::test_common::get_keypair};

    fn assert_completely_equal(k1: &RistrettoPublicKey, k2: &RistrettoPublicKey) {
        assert_eq!(k1, k2);
        assert_eq!(k1.point, k2.point);
        assert_eq!(k1.compressed, k2.compressed);
    }

    #[test]
    fn test_generation() {
        let mut rng = rand::thread_rng();
        let k1 = RistrettoSecretKey::random(&mut rng);
        let k2 = RistrettoSecretKey::random(&mut rng);
        assert_ne!(k1, k2);
    }

    #[test]
    fn invalid_secret_key_bytes() {
        RistrettoSecretKey::from_bytes(&[1, 2, 3]).expect_err("Secret keys should be 32 bytes");
    }

    #[test]
    fn create_public_key() {
        let encodings_of_small_multiples = [
            // This is the identity point
            "0000000000000000000000000000000000000000000000000000000000000000",
            // This is the basepoint
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
            // These are small multiples of the basepoint
            "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
            "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259",
            "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57",
            "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e",
            "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403",
            "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d",
            "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c",
            "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031",
            "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f",
            "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42",
            "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460",
            "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f",
            "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e",
            "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e",
        ];
        let mut bytes = [0u8; 32];
        for i in 0u8..16 {
            let pk = RistrettoPublicKey::from_hex(encodings_of_small_multiples[i as usize]).unwrap();
            bytes[0] = i;
            let sk = RistrettoSecretKey::from_bytes(&bytes).unwrap();
            let pk2 = RistrettoPublicKey::from_secret_key(&sk);
            assert_eq!(pk, pk2);
        }
    }

    #[test]
    fn secret_to_hex() {
        let mut rng = rand::thread_rng();
        let sk = RistrettoSecretKey::random(&mut rng);
        let hex = sk.to_hex();
        let sk2 = RistrettoSecretKey::from_hex(&hex).unwrap();
        assert_eq!(sk, sk2);
    }

    #[test]
    fn pubkey_to_hex() {
        let mut rng = rand::thread_rng();
        let sk = RistrettoSecretKey::random(&mut rng);
        let pk = RistrettoPublicKey::from_secret_key(&sk);
        let hex = pk.to_hex();
        let pk2 = RistrettoPublicKey::from_hex(&hex).unwrap();
        assert_completely_equal(&pk, &pk2);
    }

    #[test]
    fn secret_to_vec() {
        let mut rng = rand::thread_rng();
        let sk = RistrettoSecretKey::random(&mut rng);
        let vec = sk.to_vec();
        let sk2 = RistrettoSecretKey::from_vec(&vec).unwrap();
        assert_eq!(sk, sk2);
    }

    #[test]
    fn public_to_vec() {
        let mut rng = rand::thread_rng();
        let sk = RistrettoSecretKey::random(&mut rng);
        let pk = RistrettoPublicKey::from_secret_key(&sk);
        let vec = pk.to_vec();
        let pk2 = RistrettoPublicKey::from_vec(&vec).unwrap();
        assert_completely_equal(&pk, &pk2);
    }

    #[test]
    fn zero_plus_k_is_k() {
        let zero = RistrettoSecretKey::default();
        let mut rng = rand::thread_rng();
        let k = RistrettoSecretKey::random(&mut rng);
        assert_eq!(&k + &zero, k);
        assert_eq!(&k + zero.clone(), k);
        assert_eq!(k.clone() + &zero, k);
        assert_eq!(k.clone() + zero, k);
    }

    #[test]
    fn k_minus_zero_is_k() {
        let zero = RistrettoSecretKey::default();
        let mut rng = rand::thread_rng();
        let k = RistrettoSecretKey::random(&mut rng);
        assert_eq!(&k - &zero, k);
        assert_eq!(&k - zero.clone(), k);
        assert_eq!(k.clone() - &zero, k);
        assert_eq!(k.clone() - zero, k);
    }

    /// These test vectors are from https://ristretto.group/test_vectors/ristretto255.html
    #[test]
    fn bad_keys() {
        let bad_encodings = [
            // These are all bad because they're non-canonical field encodings.
            "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "f3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            // These are all bad because they're negative field elements.
            "0100000000000000000000000000000000000000000000000000000000000000",
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "ed57ffd8c914fb201471d1c3d245ce3c746fcbe63a3679d51b6a516ebebe0e20",
            "c34c4e1826e5d403b78e246e88aa051c36ccf0aafebffe137d148a2bf9104562",
            "c940e5a4404157cfb1628b108db051a8d439e1a421394ec4ebccb9ec92a8ac78",
            "47cfc5497c53dc8e61c91d17fd626ffb1c49e2bca94eed052281b510b1117a24",
            "f1c6165d33367351b0da8f6e4511010c68174a03b6581212c71c0e1d026c3c72",
            "87260f7a2f12495118360f02c26a470f450dadf34a413d21042b43b9d93e1309",
            // These are all bad because they give a nonsquare x^2.
            "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371",
            "4eac077a713c57b4f4397629a4145982c661f48044dd3f96427d40b147d9742f",
            "de6a7b00deadc788eb6b6c8d20c0ae96c2f2019078fa604fee5b87d6e989ad7b",
            "bcab477be20861e01e4a0e295284146a510150d9817763caf1a6f4b422d67042",
            "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
            "f4a9e534fc0d216c44b218fa0c42d99635a0127ee2e53c712f70609649fdff22",
            "8268436f8c4126196cf64b3c7ddbda90746a378625f9813dd9b8457077256731",
            "2810e5cbc2cc4d4eece54f61c6f69758e289aa7ab440b3cbeaa21995c2f4232b",
            // These are all bad because they give a negative xy value.
            "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e",
            "a45fdc55c76448c049a1ab33f17023edfb2be3581e9c7aade8a6125215e04220",
            "d483fe813c6ba647ebbfd3ec41adca1c6130c2beeee9d9bf065c8d151c5f396e",
            "8a2e1d30050198c65a54483123960ccc38aef6848e1ec8f5f780e8523769ba32",
            "32888462f8b486c68ad7dd9610be5192bbeaf3b443951ac1a8118419d9fa097b",
            "227142501b9d4355ccba290404bde41575b037693cef1f438c47f8fbf35d1165",
            "5c37cc491da847cfeb9281d407efc41e15144c876e0170b499a96a22ed31e01e",
            "445425117cb8c90edcbc7c1cc0e74f747f2c1efa5630a967c64f287792a48a4b",
            // This is s = -1, which causes y = 0.
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        // Test that all of the bad encodings are rejected
        for bad_encoding in &bad_encodings {
            RistrettoPublicKey::from_hex(bad_encoding).expect_err(&format!("Encoding {bad_encoding} should fail"));
        }
    }

    #[test]
    fn mul() {
        let (k, p) = get_keypair();
        let prod = &k * &p;
        assert_eq!(k.clone() * &p, prod);
        assert_eq!(&k * p.clone(), prod);
        assert_eq!(k * p, prod);
    }

    #[test]
    fn batch_mul() {
        let (k1, p1) = get_keypair();
        let (k2, p2) = get_keypair();
        let p_slow = &(&k1 * &p1) + &(&k2 * &p2);
        let b_batch = RistrettoPublicKey::batch_mul(&[k1, k2], &[p1, p2]);
        assert_completely_equal(&p_slow, &b_batch);
    }

    #[test]
    fn create_keypair() {
        let mut rng = rand::thread_rng();
        let (k, pk) = RistrettoPublicKey::random_keypair(&mut rng);
        assert_completely_equal(&pk, &RistrettoPublicKey::from_secret_key(&k));
    }

    #[cfg(feature = "zero")]
    #[test]
    fn secret_keys_are_cleared_after_drop() {
        let zero = &vec![0u8; 32][..];
        let mut rng = rand::thread_rng();
        let ptr;
        {
            let k = RistrettoSecretKey::random(&mut rng);
            ptr = (k.0).as_bytes().as_ptr();
        }
        // In release mode, the memory can already be reclaimed by this stage due to optimisations, and so this test
        // can fail in release mode, even though the values were effectively scrubbed.
        if cfg!(debug_assertions) {
            unsafe {
                use core::slice;
                assert_eq!(slice::from_raw_parts(ptr, 32), zero);
            }
        }
    }

    #[test]
    fn convert_from_u64() {
        let k = RistrettoSecretKey::from(42u64);
        assert_eq!(
            k.to_hex(),
            "2a00000000000000000000000000000000000000000000000000000000000000"
        );
        let k = RistrettoSecretKey::from(256u64);
        assert_eq!(
            k.to_hex(),
            "0001000000000000000000000000000000000000000000000000000000000000"
        );
        let k = RistrettoSecretKey::from(100_000_000u64);
        assert_eq!(
            k.to_hex(),
            "00e1f50500000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn serialize_deserialize_base64() {
        let mut rng = rand::thread_rng();
        let (k, pk) = RistrettoPublicKey::random_keypair(&mut rng);
        let ser_k = k.to_base64().unwrap();
        let ser_pk = pk.to_base64().unwrap();
        let k2: RistrettoSecretKey = RistrettoSecretKey::from_base64(&ser_k).unwrap();
        assert_eq!(k, k2, "Deserialised secret key");
        let pk2: RistrettoPublicKey = RistrettoPublicKey::from_base64(&ser_pk).unwrap();
        assert_completely_equal(&pk, &pk2);
    }

    #[test]
    fn serialize_deserialize_json() {
        let mut rng = rand::thread_rng();
        let (k, pk) = RistrettoPublicKey::random_keypair(&mut rng);
        let ser_k = k.to_json().unwrap();
        let ser_pk = pk.to_json().unwrap();
        println!("JSON pubkey: {ser_pk} privkey: {ser_k}");
        let k2: RistrettoSecretKey = RistrettoSecretKey::from_json(&ser_k).unwrap();
        assert_eq!(k, k2, "Deserialised secret key");
        let pk2: RistrettoPublicKey = RistrettoPublicKey::from_json(&ser_pk).unwrap();
        assert_completely_equal(&pk, &pk2);
    }

    #[test]
    fn serialize_deserialize_binary() {
        let mut rng = rand::thread_rng();
        let (k, pk) = RistrettoPublicKey::random_keypair(&mut rng);
        let ser_k = k.to_binary().unwrap();
        let ser_pk = pk.to_binary().unwrap();
        let k2: RistrettoSecretKey = RistrettoSecretKey::from_binary(&ser_k).unwrap();
        assert_eq!(k, k2);
        let pk2: RistrettoPublicKey = RistrettoPublicKey::from_binary(&ser_pk).unwrap();
        assert_completely_equal(&pk, &pk2);
    }

    #[test]
    fn display_and_debug() {
        let hex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
        let pk = RistrettoPublicKey::from_hex(hex).unwrap();
        assert_eq!(format!("{pk}"), hex);
        assert_eq!(format!("{pk:?}"), hex);
    }

    #[test]
    fn pubkey_display_width_formatting() {
        let hex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
        let pk = RistrettoPublicKey::from_hex(hex).unwrap();
        assert_eq!(format!("{:0}", pk), hex);
        assert_eq!(format!("{pk:2}"), "e2");
        assert_eq!(format!("{pk:6}"), "e2f2ae");
        assert_eq!(format!("{pk:7}"), "e2...76");
        assert_eq!(format!("{pk:16}"), "e2f2ae...08d2d76");
        assert_eq!(
            format!("{pk:62}"),
            "e2f2ae0a6abc4e71a884a961c5005...e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:63}"),
            "e2f2ae0a6abc4e71a884a961c50051...e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:64}"),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:65}"),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76 "
        );
        assert_eq!(
            format!("{pk:*>66}"),
            "**e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:*<66}"),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76**"
        );
        assert_eq!(
            format!("{pk:*^66}"),
            "*e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76*"
        );
    }

    #[test]
    fn pubkey_hex_formatting() {
        let hex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
        let pk = RistrettoPublicKey::from_hex(hex).unwrap();
        assert_eq!(
            format!("{pk:#x}"),
            "0xe2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:x}"),
            "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
        );
        assert_eq!(
            format!("{pk:#X}"),
            "0xE2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76"
        );
        assert_eq!(
            format!("{pk:X}"),
            "E2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76"
        );
    }

    #[test]
    fn pubkey_combined_formatting() {
        let hex = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76";
        let pk = RistrettoPublicKey::from_hex(hex).unwrap();
        assert_eq!(format!("{pk:2X}"), "E2");
        assert_eq!(format!("{pk:9X}"), "E2F...D76");
        assert_eq!(
            format!("{pk:*^#68X}"),
            "*0xE2F2AE0A6ABC4E71A884A961C500515F58E30B6AA582DD8DB6A65945E08D2D76*"
        );
    }

    #[test]
    // Regression test
    fn ristretto_kdf_metadata() {
        assert_eq!(RistrettoKdf::version(), 1);
        assert_eq!(RistrettoKdf::domain(), "com.tari.kdf.ristretto");
        assert_eq!(
            RistrettoKdf::domain_separation_tag("test"),
            "com.tari.kdf.ristretto.v1.test"
        );
    }

    #[test]
    fn kdf_key_too_short() {
        let err = RistrettoKdf::generate::<Blake256>(b"this_key_is_too_short", b"data", "test").err();
        assert!(matches!(err, Some(HashingError::InputTooShort{})));
    }

    #[test]
    fn kdf_test() {
        let key =
            RistrettoSecretKey::from_hex("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c").unwrap();
        let derived1 = RistrettoKdf::generate::<Blake256>(key.as_bytes(), b"derived1", "test").unwrap();
        let derived2 = RistrettoKdf::generate::<Blake256>(key.as_bytes(), b"derived2", "test").unwrap();
        assert_eq!(
            derived1.to_hex(),
            "e8df6fa40344c1fde721e9a35d46daadb48dc66f7901a9795ebb0374474ea601"
        );
        assert_eq!(
            derived2.to_hex(),
            "3ae035e2663d9c561300cca67743ccdb56ea07ca7dacd8394356c4354b030e0c"
        );
    }

    #[test]
    fn visibility_test() {
        let key =
            RistrettoSecretKey::from_hex("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c").unwrap();
        let invisible = format!("{key:?}");
        assert!(!invisible.contains("016c"));
        let visible = format!("{:?}", key.reveal());
        assert!(visible.contains("016c"));
    }
    #[cfg(feature = "zero")]
    #[test]
    fn zeroize_test() {
        let mut rng = rand::thread_rng();
        let zeros = [0u8; 32];

        // Zeroize scalar
        let mut s = RistrettoSecretKey::random(&mut rng);
        s.zeroize();
        assert_eq!(s.as_bytes(), &zeros);

        // Zeroize point
        let mut p = RistrettoPublicKey::from_secret_key(&RistrettoSecretKey::random(&mut rng));
        p.zeroize();
        assert_eq!(p.compressed.get(), None); // no compressed point yet
        assert_eq!(p.as_bytes(), &zeros); // this compresses the point
        assert_eq!(p.compressed.get().unwrap().as_bytes(), &zeros); // check directly for good measure
    }

    #[cfg(feature = "borsh")]
    mod borsh {
        use borsh::{BorshDeserialize, BorshSerialize};

        use crate::ristretto::{test_common::get_keypair, RistrettoPublicKey, RistrettoSecretKey};

        #[test]
        fn test_serialize_secret_key() {
            let (secret_key_a, public_key_a) = get_keypair();
            let (secret_key_b, public_key_b) = get_keypair();
            let mut v = Vec::new();
            secret_key_a.serialize(&mut v).unwrap();
            public_key_a.serialize(&mut v).unwrap();
            secret_key_b.serialize(&mut v).unwrap();
            public_key_b.serialize(&mut v).unwrap();
            let buf = &mut v.as_slice();
            assert_eq!(RistrettoSecretKey::deserialize(buf).unwrap(), secret_key_a);
            assert_eq!(RistrettoPublicKey::deserialize(buf).unwrap(), public_key_a);
            assert_eq!(RistrettoSecretKey::deserialize(buf).unwrap(), secret_key_b);
            assert_eq!(RistrettoPublicKey::deserialize(buf).unwrap(), public_key_b);
            assert!(buf.is_empty());
        }
    }
}
