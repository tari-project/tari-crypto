// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Custom serializers for Ristretto keys
//!
//! The Dalek libraries only serialize to binary (understandably), but this has 2 yucky implications:
//!
//! 1. Exporting to "human readable" formats like JSON yield crappy looking 'binary arrays', e.g. /[12, 223, 65, .../]
//! 2. Reading back from JSON is broken because serde doesn't read this back as a byte string, but as a seq.
//!
//! The workaround is to have binary serialization by default, but if a struct is going to be saved in JSON format,
//! then you can override that behaviour with `with_serialize`, e.g.
//!
//! ```nocompile
//!   #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
//!   pub struct KeyManager<K: SecretKey, D: Digest> {
//!       #[serde(serialize_with = "serialise_to_hex", deserialize_with = "secret_from_hex")]
//!       pub master_key: K,
//!       pub branch_seed: String,
//!       pub primary_key_index: usize,
//!       digest_type: PhantomData<D>,
//!   }
//! ```

use core::fmt;

use serde::{
    de::{self, Visitor},
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};
use tari_utilities::{byte_array::ByteArray, hex::Hex};
#[cfg(feature = "zero")]
use zeroize::Zeroize;

use crate::ristretto::{RistrettoPublicKey, RistrettoSecretKey};

impl<'de> Deserialize<'de> for RistrettoPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct RistrettoPubKeyVisitor;

        impl<'de> Visitor<'de> for RistrettoPubKeyVisitor {
            type Value = RistrettoPublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a public key in binary format")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<RistrettoPublicKey, E>
            where E: de::Error {
                RistrettoPublicKey::from_bytes(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            RistrettoPublicKey::from_hex(&s).map_err(de::Error::custom)
        } else {
            deserializer.deserialize_bytes(RistrettoPubKeyVisitor)
        }
    }
}

impl Serialize for RistrettoPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            self.to_hex().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for RistrettoSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct RistrettoVisitor;

        impl<'de> Visitor<'de> for RistrettoVisitor {
            type Value = RistrettoSecretKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a secret key in binary format")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<RistrettoSecretKey, E>
            where E: de::Error {
                RistrettoSecretKey::from_bytes(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            let mut s = String::deserialize(deserializer)?;
            let v = RistrettoSecretKey::from_hex(&s).map_err(de::Error::custom);
            #[cfg(feature = "zero")]
            {
                s.zeroize();
            }
            v
        } else {
            deserializer.deserialize_bytes(RistrettoVisitor)
        }
    }
}

impl Serialize for RistrettoSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            let mut s = self.to_hex();
            let result = s.serialize(serializer);
            #[cfg(feature = "zero")]
            {
                s.zeroize();
            }
                result
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}
