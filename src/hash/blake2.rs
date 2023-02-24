// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! A convenience wrapper produce 256 bit hashes from Blake2b

use blake2::{digest::consts::U32, Blake2b};

use crate::hashing::LengthExtensionAttackResistant;

/// Blake2b 256-bit hash function
pub type Blake256 = Blake2b<U32>;

impl LengthExtensionAttackResistant for Blake256 {}

#[cfg(test)]
mod test {
    use digest::{generic_array::GenericArray, Digest, Update};
    use tari_utilities::hex;

    use crate::hash::blake2::Blake256;

    #[test]
    fn blake256() {
        let e = Blake256::default().chain(b"one").chain(b"two").finalize().to_vec();
        let h = hex::to_hex(&e);
        assert_eq!(
            h.as_str(),
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0"
        );
    }

    #[test]
    fn reset() {
        let mut e = Blake256::default().chain(b"foobar");
        e.reset();
        let v = e.chain(b"onetwo").finalize().to_vec();
        let h = hex::to_hex(&v);
        assert_eq!(
            h.as_str(),
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0"
        );
    }

    #[test]
    fn finalise_reset() {
        let mut e = Blake256::default().chain(b"onetwo");
        let mut out = GenericArray::default();
        e.finalize_into_reset(&mut out);
        let h = hex::to_hex(out.as_slice());
        assert_eq!(
            h.as_str(),
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0"
        );
        let v = e.chain(b"onetwo").finalize().to_vec();
        let h = hex::to_hex(&v);
        assert_eq!(
            h.as_str(),
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0"
        );
    }

    #[test]
    fn derived_functions() {
        let e = Blake256::default().chain(b"onetwo");
        // test Clone impl
        let e2 = e.clone();
        // test Debug impl
        assert_eq!(format!("{e:?}"), "Blake2b_32 { .. }");
        assert_eq!(e.finalize(), e2.finalize());
    }
}
