// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Hashing API

use mut_static::MutStatic;
use serde::{Deserialize, Serialize};
use tari_utilities::hex::Hex;
use wasm_bindgen::prelude::*;

use crate::{
    hash::blake2::Blake256,
    hashing::{DomainSeparatedHasher, DomainSeparation},
};

/// A struct that holds the hashing domain value for the MutStatic
pub struct Domain {
    value: &'static str,
}

impl Domain {
    /// Create a new `Domain`
    pub fn new(value: &'static str) -> Self {
        Domain { value }
    }

    /// Getter method for `Domain` - used in conjunction with MutStatic
    pub fn get_value(&self) -> &str {
        self.value
    }

    /// Setter method for `Domain` - used in conjunction with MutStatic
    pub fn set_value(&mut self, value: &'static str) {
        self.value = value
    }
}

/// A struct that holds the hashing version value for the MutStatic
pub struct Version {
    value: u8,
}

impl Version {
    /// Create a new `Version`
    pub fn new(value: u8) -> Self {
        Version { value }
    }

    /// Getter method for `Version` - used in conjunction with MutStatic
    pub fn get_value(&self) -> u8 {
        self.value
    }

    /// Setter method for `Version` - used in conjunction with MutStatic
    pub fn set_value(&mut self, value: u8) {
        self.value = value
    }
}

/// Generated from [Blake256DomainHasher::finalize]
#[derive(Default, Serialize, Deserialize)]
pub struct HashResult {
    hash: String,
    domain_separation_tag: String,
}

/// A Blake256 domain hasher for domain separated hashing
#[wasm_bindgen]
pub struct Blake256DomainHasher {
    data: Vec<String>,
}

#[wasm_bindgen]
impl Blake256DomainHasher {
    /// Create a new `Blake256DomainHasher`
    pub fn new() -> Self {
        Blake256DomainHasher { data: Vec::new() }
    }

    /// Adds data to be hashed - not exactly the same as chaining data to a Digest, but similar usage
    pub fn chain(mut self, data: &str) -> Self {
        self.data.push(data.to_string());
        self
    }

    /// This will create the domain separated hasher, update all the chained data and finalize, rolled up into one
    /// operation
    pub fn finalize(&self, domain: &str, version: u8, label: &str) -> JsValue {
        // These mutable lazy statics are required for 'WasmHashDomain'
        lazy_static! {
            static ref DOMAIN: MutStatic<Domain> = MutStatic::from(Domain::new("domain.must.be.set"));
        }
        lazy_static! {
            static ref VERSION: MutStatic<Version> = MutStatic::from(Version::new(1));
        }

        let mut result = HashResult::default();
        {
            {
                let mut handle = DOMAIN.write().expect("Hashing domain cannot be set in WASM interface");
                handle.set_value(unsafe { std::mem::transmute(domain) });
            }
            {
                let mut handle = VERSION.write().expect("Hashing label cannot be set in WASM interface");
                handle.set_value(version);
            }

            struct WasmHashDomain;
            impl DomainSeparation for WasmHashDomain {
                fn version() -> u8 {
                    VERSION
                        .read()
                        .expect("Cannot read hashing domain version in WASM interface")
                        .get_value()
                }

                fn domain() -> &'static str {
                    unsafe {
                        std::mem::transmute(
                            DOMAIN
                                .read()
                                .expect("Cannot read hashing domain name in WASM interface")
                                .get_value(),
                        )
                    }
                }
            }

            result.domain_separation_tag = WasmHashDomain::domain_separation_tag(label);
            let mut hasher = DomainSeparatedHasher::<Blake256, WasmHashDomain>::new_with_label(unsafe {
                std::mem::transmute(label)
            });
            for item in &self.data {
                hasher.update(&item);
            }
            result.hash = hasher.finalize().as_ref().to_vec().to_hex();
        }

        JsValue::from_serde(&result).unwrap()
    }
}

impl Default for Blake256DomainHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use tari_utilities::hex::Hex;
    use wasm_bindgen_test::*;

    use crate::{
        hash::blake2::Blake256,
        hash_domain,
        hashing::{DomainSeparatedHasher, DomainSeparation},
        wasm::hashing::{Blake256DomainHasher, HashResult},
    };

    #[wasm_bindgen_test]
    fn it_correctly_computes_domain_separated_hashes() {
        const TEST_DOMAIN: &str = "tari.com.hashing";
        const TEST_VERSION: u8 = 1;
        const TEST_LABEL: &str = "test";
        let data = vec!["one", "two", "three"];

        let hasher = Blake256DomainHasher::new();
        let hash_from_wasm = hasher
            .chain(data[0])
            .chain(data[1])
            .chain(data[2])
            .finalize(TEST_DOMAIN, TEST_VERSION, TEST_LABEL)
            .into_serde::<HashResult>()
            .unwrap();

        hash_domain!(HashTestDomain, TEST_DOMAIN, TEST_VERSION);
        let mut hasher = DomainSeparatedHasher::<Blake256, HashTestDomain>::new_with_label(TEST_LABEL);
        for item in data {
            hasher.update(item);
        }
        let hash_from_hashing = hasher.finalize().as_ref().to_vec().to_hex();

        assert_eq!(hash_from_wasm.hash, hash_from_hashing);
        assert_eq!(
            hash_from_wasm.domain_separation_tag,
            HashTestDomain::domain_separation_tag(TEST_LABEL)
        );
    }
}
