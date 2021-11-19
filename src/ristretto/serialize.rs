// Copyright 2019. The Tari Project
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

use crate::{
    ristretto::{
        ristretto_com_sig::CompressedRistrettoComSig,
        ristretto_keys::CompressedRistrettoPublicKey,
        RistrettoPublicKey,
        RistrettoSecretKey,
    },
    signatures::CompressedCommitmentSignature,
};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};
use std::fmt;
use tari_utilities::{byte_array::ByteArray, hex::Hex};

impl<'de> Deserialize<'de> for CompressedRistrettoPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        struct CompressedRistrettoPubKeyVisitor;

        impl<'de> Visitor<'de> for CompressedRistrettoPubKeyVisitor {
            type Value = CompressedRistrettoPublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a public key in binary format")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<CompressedRistrettoPublicKey, E>
            where E: de::Error {
                CompressedRistrettoPublicKey::from_bytes(v).map_err(E::custom)
            }
        }

        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            CompressedRistrettoPublicKey::from_hex(&s).map_err(de::Error::custom)
        } else {
            deserializer.deserialize_bytes(CompressedRistrettoPubKeyVisitor)
        }
    }
}

impl Serialize for CompressedRistrettoPublicKey {
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
            let s = String::deserialize(deserializer)?;
            RistrettoSecretKey::from_hex(&s).map_err(de::Error::custom)
        } else {
            deserializer.deserialize_bytes(RistrettoVisitor)
        }
    }
}

impl Serialize for RistrettoSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            self.to_hex().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for CompressedRistrettoComSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            PublicNonce,
            U,
            V,
        }

        struct CompressedRistrettoComSigVisitor;

        impl<'de> Visitor<'de> for CompressedRistrettoComSigVisitor {
            type Value = CompressedRistrettoComSig;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a public key in binary format, followed by 2 secret keys in binary form")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<CompressedRistrettoComSig, E>
            where E: de::Error {
                if v.is_empty() {
                    return Ok(Default::default());
                }
                if v.len() != 96 {
                    return Err(E::invalid_length(v.len(), &"a vector of length 96"));
                }
                let public_nonce = CompressedRistrettoPublicKey::from_bytes(&v[0..32]).map_err(E::custom)?;
                let u = RistrettoSecretKey::from_bytes(&v[32..64]).map_err(E::custom)?;
                let v = RistrettoSecretKey::from_bytes(&v[64..96]).map_err(E::custom)?;
                Ok(CompressedRistrettoComSig::new(public_nonce, u, v))
            }

            fn visit_map<V>(self, mut map: V) -> Result<CompressedRistrettoComSig, V::Error>
            where V: MapAccess<'de> {
                let mut public_nonce = None;
                let mut u = None;
                let mut v = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::PublicNonce => {
                            if public_nonce.is_some() {
                                return Err(de::Error::duplicate_field("public_nonce"));
                            }
                            public_nonce = Some(map.next_value()?);
                        },
                        Field::U => {
                            if u.is_some() {
                                return Err(de::Error::duplicate_field("u"));
                            }
                            u = Some(map.next_value()?);
                        },
                        Field::V => {
                            if v.is_some() {
                                return Err(de::Error::duplicate_field("v"));
                            }
                            v = Some(map.next_value()?);
                        },
                    }
                }
                let public_nonce = public_nonce.ok_or_else(|| de::Error::missing_field("public_nonce"))?;
                let u = u.ok_or_else(|| de::Error::missing_field("u"))?;
                let v = v.ok_or_else(|| de::Error::missing_field("v"))?;
                Ok(CompressedRistrettoComSig::new(public_nonce, u, v))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_map(CompressedRistrettoComSigVisitor)
        } else {
            deserializer.deserialize_bytes(CompressedRistrettoComSigVisitor)
        }
    }
}

impl Serialize for CompressedRistrettoComSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if serializer.is_human_readable() {
            self.to_hex().serialize(serializer)
        } else {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}
