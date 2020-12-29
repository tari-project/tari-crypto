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

use digest::{
    generic_array::{typenum::U32, GenericArray},
    FixedOutput,
    Input,
};
use k12::{
    digest::{ExtendableOutput, Reset, Update},
    KangarooTwelve,
};

/// A convenience wrapper produce 256 bit hashes from Kangaroo12
#[deprecated(
    note = "This wrapper becomes obsolete once tari_crypto updates to digest v0.9, which is dependent on Dalek \
            libraries updating to digest 0.9. When that happens, you can use the underlying KangarooTwelve hasher \
            directly and this wrapper will be removed."
)]
#[derive(Debug)]
pub struct K12(KangarooTwelve);

#[allow(deprecated)]
impl K12 {
    pub fn new() -> Self {
        let h = KangarooTwelve::new();
        K12(h)
    }

    pub fn result(self) -> GenericArray<u8, U32> {
        self.fixed_result()
    }
}

#[allow(deprecated)]
impl Default for K12 {
    fn default() -> Self {
        let h = KangarooTwelve::new();
        K12(h)
    }
}

#[allow(deprecated)]
impl Input for K12 {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        (self.0).update(data.as_ref());
    }
}

#[allow(deprecated)]
impl FixedOutput for K12 {
    type OutputSize = U32;

    fn fixed_result(self) -> GenericArray<u8, U32> {
        let v = (self.0).finalize_boxed(32);
        GenericArray::clone_from_slice(&v)
    }
}

#[allow(deprecated)]
impl Reset for K12 {
    fn reset(&mut self) {
        (self.0).reset();
    }
}

#[allow(deprecated)]
#[cfg(test)]
mod test {
    use crate::hash::k12::K12;
    use digest::Input;
    use k12::digest::Reset;
    use tari_utilities::hex;

    #[test]
    fn k12_test() {
        let e = K12::new().chain(b"").result().to_vec();
        let h = hex::to_hex(&e);
        assert_eq!(
            h,
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5".to_string()
        );
    }

    #[test]
    fn reset() {
        let mut e = K12::default().chain(b"foobar");
        e.reset();
        let e = e.result().to_vec();
        let h = hex::to_hex(&e);
        assert_eq!(
            h,
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5".to_string()
        );
    }
}
