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

use blake2::VarBlake2b;
use digest::{
    generic_array::{typenum::U32, GenericArray},
    FixedOutputDirty,
    Reset,
    Update,
    VariableOutput,
    VariableOutputDirty,
};

/// A convenience wrapper produce 256 bit hashes from Blake2b
#[derive(Clone, Debug)]
pub struct Blake256(VarBlake2b);

impl Blake256 {
    pub fn new() -> Self {
        let h = VariableOutput::new(32).unwrap();
        Blake256(h)
    }

    pub fn finalize(self) -> GenericArray<u8, U32> {
        let mut buf = [0; 32];
        (self.0).finalize_variable(|res| buf.copy_from_slice(res));

        GenericArray::from(buf)
    }
}

impl Default for Blake256 {
    fn default() -> Self {
        let h = VariableOutput::new(32).unwrap();
        Blake256(h)
    }
}

impl Update for Blake256 {
    fn update(&mut self, data: impl AsRef<[u8]>) {
        (self.0).update(data);
    }
}

impl FixedOutputDirty for Blake256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, out: &mut GenericArray<u8, Self::OutputSize>) {
        (self.0).finalize_variable_dirty(|res| out.copy_from_slice(res))
    }
}

impl Reset for Blake256 {
    fn reset(&mut self) {
        (self.0).reset()
    }
}

#[cfg(test)]
mod test {
    use crate::common::Blake256;
    use digest::{Reset, Update};
    use tari_utilities::hex;

    #[test]
    fn blake256() {
        let e = Blake256::new().chain(b"one").chain(b"two").finalize().to_vec();
        let h = hex::to_hex(&e);
        assert_eq!(
            h,
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0".to_string()
        );
    }

    #[test]
    fn reset() {
        let mut e = Blake256::default().chain(b"foobar");
        e.reset();
        let e = e.chain(b"onetwo").finalize().to_vec();
        let h = hex::to_hex(&e);
        assert_eq!(
            h,
            "03521c1777639fc6e5c3d8c3b4600870f18becc155ad7f8053d2c65bc78e4aa0".to_string()
        );
    }
}
