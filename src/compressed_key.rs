// Copyright 2025. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause
use alloc::vec::Vec;
use core::fmt;
use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    marker::PhantomData,
    prelude::rust_2015::ToString,
};

use blake2::Blake2b;
use digest::{consts::U64, Digest};
use subtle::ConstantTimeEq;
use tari_utilities::{hex::Hex, ByteArray, ByteArrayError, Hashable};
use zeroize::Zeroize;

use crate::keys::PublicKey;

/// This stores a public key in compressed form, keeping it in compressed form until the point is needed, only then
/// decompressing it back down to a public key
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CompressedKey<T> {
    key: Vec<u8>,
    phantom_data: PhantomData<T>,
}


impl<T: PublicKey> CompressedKey<T> {
    pub fn new_from_pk(pk: &T) -> Self {
        Self::new(pk.as_bytes())
    }

    pub fn to_public_key(&self) -> Result<T, ByteArrayError> {
        T::from_canonical_bytes(&self.key)
    }
}

impl<T> CompressedKey<T> {
    /// Create a new compressed key
    pub fn new(key: &[u8]) -> CompressedKey<T> {
        Self {
            key: key.to_vec(),
            phantom_data: PhantomData,
        }
    }

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

impl<T: Default + ByteArray> Default for CompressedKey<T> {
    fn default() -> Self {
        let key = T::default();
        Self::new(key.as_bytes())
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
        write!(f, "{}", self.to_hex())
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
    /// Create a new `RistrettoPublicKey` instance form the given byte array. The constructor returns errors under
    /// the following circumstances:
    /// * The byte array is not exactly 32 bytes
    /// * The byte array does not represent a valid (compressed) point on the ristretto255 curve
    fn from_canonical_bytes(bytes: &[u8]) -> Result<CompressedKey<T>, ByteArrayError>
    where Self: Sized {
        // Check the length here, because The Ristretto constructor panics rather than returning an error
        if bytes.len() != 32 {
            return Err(ByteArrayError::IncorrectLength {});
        }
        Ok(Self::new(&bytes))
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
