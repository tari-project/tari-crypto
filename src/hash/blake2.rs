// Copyright 2020 The Tari Project
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

use blake2::{digest::VariableOutput, VarBlake2b};
use digest::{
    consts::U32,
    generic_array::{typenum::Unsigned, GenericArray},
    FixedOutput,
    Reset,
    Update,
};

/// A convenience wrapper produce 256 bit hashes from Blake2b
#[derive(Clone, Debug)]
pub struct Blake256(VarBlake2b);

impl Blake256 {
    pub fn with_params(key: &[u8], salt: &[u8], persona: &[u8]) -> Self {
        Self(VarBlake2b::with_params(
            key,
            salt,
            persona,
            <Self as FixedOutput>::OutputSize::USIZE,
        ))
    }
}

impl Default for Blake256 {
    fn default() -> Self {
        let h = VariableOutput::new(<Self as FixedOutput>::OutputSize::USIZE).unwrap();
        Blake256(h)
    }
}

impl FixedOutput for Blake256 {
    type OutputSize = U32;

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.0.finalize_variable(|res| out.copy_from_slice(res));
    }

    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.0.finalize_variable_reset(|res| out.copy_from_slice(res));
    }
}

impl Reset for Blake256 {
    fn reset(&mut self) {
        (self.0).reset()
    }
}

impl Update for Blake256 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data);
    }
}

#[cfg(test)]
mod test {
    use crate::common::Blake256;
    use blake2::digest::FixedOutput;
    use digest::{generic_array::GenericArray, Digest};
    use tari_utilities::hex;

    #[test]
    fn blake256() {
        let e = Blake256::new().chain(b"one").chain(b"two").finalize().to_vec();
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
        let mut e = Blake256::default();
        e.update(b"onetwo");
        // test Clone impl
        let e2 = e.clone();
        // test Debug impl
        assert_eq!(format!("{:?}", e), "Blake256(VarBlake2b { ... })");
        assert_eq!(e.finalize(), e2.finalize());
    }

    #[test]
    fn personalisation() {
        let default = Blake256::new().chain(b"onetwo").finalize();
        let personalised = Blake256::with_params(&[], &[], b"unit-test")
            .chain(b"onetwo")
            .finalize();
        let salted = Blake256::with_params(&[], b"unit-test", &[])
            .chain(b"onetwo")
            .finalize();
        let keyed = Blake256::with_params(&[1u8; 64], &[], &[]).chain(b"onetwo").finalize();

        assert_ne!(default, personalised);
        assert_ne!(default, salted);
        assert_ne!(salted, personalised);
        assert_ne!(salted, keyed);
        assert_ne!(keyed, personalised);
        assert_ne!(keyed, salted);
    }
}
