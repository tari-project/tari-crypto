// Copyright 2025. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! This stores a public key in compressed form, keeping it in compressed form until the point is needed, only then
//! decompressing it back down to a public key
use alloc::vec::Vec;
use core::fmt;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    prelude::rust_2015::{String, ToString},
    sync::OnceLock,
};

use blake2::Blake2b;
use digest::{Digest, consts::U64};
use rand_core::{CryptoRng, Rng};
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer, de, ser};
use subtle::ConstantTimeEq;
use tari_utilities::{ByteArray, ByteArrayError, Hashable, hex::Hex};
use zeroize::Zeroize;

use crate::keys::{PublicKey, SecretKey};

/// This stores a public key in compressed form, keeping it in compressed form until the point is needed, only then
/// decompressing it back down to a public key
#[derive(Clone)]
pub struct CompressedKey<T> {
    key: Vec<u8>,
    public_key: OnceLock<T>,
}

impl<T: PublicKey> CompressedKey<T> {
    /// Create a new compressed key from a public key
    pub fn new_from_pk(pk: T) -> Self {
        Self {
            key: pk.as_bytes().to_vec(),
            public_key: pk.into(),
        }
    }

    /// Return the public key
    pub fn to_public_key(&self) -> Result<T, ByteArrayError> {
        match self.public_key.get() {
            Some(pk) => Ok(pk.clone()),
            None => {
                let pk = T::from_canonical_bytes(&self.key)?;
                let _unused = self.public_key.set(pk.clone());
                Ok(pk)
            },
        }
    }

    /// Create a new compressed key from a secret key
    pub fn from_secret_key(sk: &T::K) -> Self {
        let pk = T::from_secret_key(sk);
        Self {
            key: pk.as_bytes().to_vec(),
            public_key: pk.into(),
        }
    }

    /// Create a new cnew random compressed key and secret key
    pub fn random_keypair<R: Rng + CryptoRng>(rng: &mut R) -> (T::K, Self) {
        let k = T::K::random(rng);
        let pk = Self::from_secret_key(&k);
        (k, pk)
    }

    /// returns the length of the key
    pub fn key_length() -> usize {
        T::KEY_LEN
    }

    /// Create a compressed key from bytes, returning an error if the bytes are not exactly `T::KEY_LEN` long or do
    /// not decompress to a valid public key. The decompressed key is cached.
    pub fn from_canonical_bytes_validated(bytes: &[u8]) -> Result<Self, ByteArrayError> {
        let pk = T::from_canonical_bytes(bytes)?;
        Ok(Self::new_from_pk(pk))
    }
}

impl<T> CompressedKey<T> {
    /// Create a new compressed key
    pub fn new(key: &[u8]) -> CompressedKey<T> {
        Self {
            key: key.to_vec(),
            public_key: OnceLock::new(),
        }
    }

    // Formats a 64 char hex string to a given width.
    // If w >= 64, we pad the result.
    // If 7 <= w < 64, we replace the middle of the string with "..."
    // If w <= 6, we return the first w chars of the string
    // Keys of other lengths fall back to the full string when the slice would be invalid.
    fn fmt_case(&self, f: &mut fmt::Formatter, uppercase: bool) -> fmt::Result {
        let mut hex = self.to_hex_trimmed();
        if uppercase {
            hex = hex.to_uppercase();
        }
        if f.alternate() {
            hex = format!("0x{hex}");
        }
        match f.width() {
            None => f.write_str(hex.as_str()),
            Some(w @ 1..=6) => f.write_str(hex.get(..w).unwrap_or(&hex)),
            Some(w @ 7..=63) => {
                let left = (w - 3) / 2;
                let right = hex.len().checked_sub(w - left - 3);
                match (hex.get(..left), right.and_then(|r| hex.get(r..))) {
                    (Some(start), Some(end)) => write!(f, "{start}...{end}"),
                    _ => f.write_str(&hex),
                }
            },
            _ => core::fmt::Display::fmt(&hex, f),
        }
    }
}

#[cfg(feature = "borsh")]
impl<T: borsh::BorshSerialize> borsh::BorshSerialize for CompressedKey<T> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        borsh::BorshSerialize::serialize(&self.as_bytes(), writer)
    }
}

#[cfg(feature = "borsh")]
impl<T: borsh::BorshDeserialize> borsh::BorshDeserialize for CompressedKey<T> {
    fn deserialize_reader<R>(reader: &mut R) -> Result<Self, borsh::io::Error>
    where R: borsh::io::Read {
        let bytes: Vec<u8> = borsh::BorshDeserialize::deserialize_reader(reader)?;
        Self::from_canonical_bytes(bytes.as_slice())
            .map_err(|e| borsh::io::Error::new(borsh::io::ErrorKind::InvalidInput, e.to_string()))
    }
}

impl<T> Hashable for CompressedKey<T> {
    fn hash(&self) -> Vec<u8> {
        Blake2b::<U64>::digest(self.as_bytes()).to_vec()
    }
}

impl<T> Hash for CompressedKey<T> {
    /// Require the implementation of the Hash trait for Hashmaps
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl<T: Default + ByteArray + PublicKey> Default for CompressedKey<T> {
    fn default() -> Self {
        let key = T::default();
        Self::new_from_pk(key)
    }
}

impl<T> fmt::Display for CompressedKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, false)
    }
}

impl<T> ConstantTimeEq for CompressedKey<T> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.key.ct_eq(&other.key)
    }
}

impl<T> fmt::LowerHex for CompressedKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, false)
    }
}

impl<T> fmt::UpperHex for CompressedKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_case(f, true)
    }
}

impl<T> fmt::Debug for CompressedKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_trimmed())
    }
}

impl<T> PartialEq for CompressedKey<T> {
    fn eq(&self, other: &CompressedKey<T>) -> bool {
        self.ct_eq(other).into()
    }
}

impl<T> Eq for CompressedKey<T> {}

impl<T> PartialOrd for CompressedKey<T> {
    fn partial_cmp(&self, other: &CompressedKey<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for CompressedKey<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl<T> ByteArray for CompressedKey<T> {
    /// Create a new `CompressedKey` from the given byte array. This only checks that the byte array is exactly 32
    /// bytes; it does not check that the bytes represent a valid point. Use
    /// [`CompressedKey::from_canonical_bytes_validated`] for that.
    fn from_canonical_bytes(bytes: &[u8]) -> Result<CompressedKey<T>, ByteArrayError>
    where Self: Sized {
        // Check the length here, because The Ristretto constructor panics rather than returning an error
        if bytes.len() != 32 {
            return Err(ByteArrayError::IncorrectLength {});
        }
        Ok(Self::new(bytes))
    }

    /// Return the little-endian byte array representation of the compressed public key
    fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl<T> Zeroize for CompressedKey<T> {
    /// Zeroizes both the point and (if it exists) the compressed point
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(feature = "serde")]
impl<'de, T> Deserialize<'de> for CompressedKey<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct CompressedKeyVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<T> Visitor<'_> for CompressedKeyVisitor<T> {
            type Value = CompressedKey<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a public key in binary format")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<CompressedKey<T>, E>
            where E: de::Error {
                CompressedKey::from_canonical_bytes(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            CompressedKey::from_hex(&s).map_err(de::Error::custom)
        } else {
            deserializer.deserialize_bytes(CompressedKeyVisitor { phantom: PhantomData })
        }
    }
}

#[cfg(feature = "serde")]
impl<T> Serialize for CompressedKey<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            self.to_hex().map_err(ser::Error::custom)?.serialize(serializer)
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(test)]
mod test {
    use tari_utilities::ByteArray;

    use super::CompressedKey;
    use crate::ristretto::RistrettoPublicKey;

    #[test]
    fn from_canonical_bytes_validated_rejects_non_points() {
        let (_, key) = CompressedKey::<RistrettoPublicKey>::random_keypair(&mut rand::rng());
        let decoded = CompressedKey::<RistrettoPublicKey>::from_canonical_bytes_validated(key.as_bytes()).unwrap();
        assert_eq!(decoded, key);

        // The identity point is a valid point
        assert!(CompressedKey::<RistrettoPublicKey>::from_canonical_bytes_validated(&[0u8; 32]).is_ok());

        let not_a_point = [0xffu8; 32];
        assert!(CompressedKey::<RistrettoPublicKey>::from_canonical_bytes_validated(&not_a_point).is_err());
        assert!(CompressedKey::<RistrettoPublicKey>::from_canonical_bytes(&not_a_point).is_ok());

        assert!(CompressedKey::<RistrettoPublicKey>::from_canonical_bytes_validated(&[1u8; 31]).is_err());
    }

    #[test]
    fn fmt_32_byte_key() {
        let bytes: Vec<u8> = (0u8..32).collect();
        let key = CompressedKey::<RistrettoPublicKey>::new(&bytes);
        let hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert_eq!(format!("{key}"), hex);
        assert_eq!(format!("{key:x}"), hex);
        assert_eq!(format!("{key:?}"), hex);
        assert_eq!(format!("{key:X}"), hex.to_uppercase());
        assert_eq!(format!("{key:#x}"), format!("0x{hex}"));
        assert_eq!(format!("{key:5}"), "00010");
        assert_eq!(format!("{key:26}"), "00010203040...1a1b1c1d1e1f");
        assert_eq!(format!("{key:27x}"), "000102030405...1a1b1c1d1e1f");
        assert_eq!(format!("{key:#10x}"), "0x0...1e1f");
        assert_eq!(format!("{key:70}"), format!("{hex}      "));
    }

    #[test]
    fn fmt_does_not_panic_for_any_key_length() {
        let keys = [
            CompressedKey::<RistrettoPublicKey>::new(&[]),
            CompressedKey::<RistrettoPublicKey>::new(&[0xab]),
            CompressedKey::<RistrettoPublicKey>::new(&[0xab; 4]),
            CompressedKey::<RistrettoPublicKey>::new(&vec![0xab; 256 * 1024 + 1]),
        ];
        for key in &keys {
            for w in 1..80 {
                drop(format!("{key:w$}"));
                drop(format!("{key:w$x}"));
                drop(format!("{key:#w$X}"));
            }
            drop(format!("{key}"));
            drop(format!("{key:?}"));
        }
    }
}
