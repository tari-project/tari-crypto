// Copyright 2019 The Tari Project
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

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
/// These points on the Ristretto curve have been created by sequentially hashing a domain separated Generator point
/// with SHA512 and using the byte string representation of the hash as input into the `from_uniform_bytes` constructor
/// in [RistrettoPoint](Struct.RistrettoPoint.html). This process is validated with the `check_nums_points` test below.
pub const RISTRETTO_NUMS_POINTS_COMPRESSED: [CompressedRistretto; 10] = [
    CompressedRistretto([
        206, 56, 152, 65, 192, 200, 105, 138, 185, 91, 112, 36, 42, 238, 166, 72, 64, 177, 234, 197, 246, 68, 183, 208,
        8, 172, 5, 135, 207, 71, 29, 112,
    ]),
    CompressedRistretto([
        54, 179, 59, 85, 148, 85, 113, 114, 237, 39, 200, 19, 236, 249, 193, 45, 13, 194, 254, 236, 39, 225, 9, 66,
        123, 41, 222, 21, 125, 254, 102, 77,
    ]),
    CompressedRistretto([
        152, 202, 159, 30, 58, 170, 77, 68, 126, 51, 86, 197, 114, 69, 19, 227, 202, 190, 145, 71, 127, 19, 101, 207,
        17, 221, 227, 175, 5, 88, 90, 85,
    ]),
    CompressedRistretto([
        242, 2, 148, 178, 187, 151, 148, 185, 122, 161, 129, 17, 83, 85, 124, 125, 30, 139, 225, 50, 69, 73, 206, 68,
        114, 177, 81, 20, 255, 56, 82, 71,
    ]),
    CompressedRistretto([
        196, 93, 153, 124, 195, 94, 29, 16, 123, 234, 15, 2, 184, 227, 67, 128, 103, 87, 113, 86, 69, 132, 187, 122,
        11, 194, 246, 23, 111, 190, 164, 28,
    ]),
    CompressedRistretto([
        70, 122, 19, 104, 23, 41, 249, 95, 206, 125, 54, 95, 126, 136, 57, 94, 54, 200, 73, 141, 40, 206, 124, 156,
        224, 237, 133, 95, 3, 225, 220, 102,
    ]),
    CompressedRistretto([
        212, 243, 209, 88, 16, 127, 237, 87, 22, 162, 111, 122, 214, 165, 70, 23, 71, 139, 35, 16, 187, 144, 228, 5,
        182, 51, 244, 148, 184, 63, 222, 26,
    ]),
    CompressedRistretto([
        106, 114, 88, 57, 144, 221, 187, 75, 248, 13, 1, 136, 214, 61, 106, 235, 221, 175, 66, 184, 107, 31, 113, 2,
        142, 36, 210, 62, 91, 35, 45, 25,
    ]),
    CompressedRistretto([
        206, 164, 160, 199, 62, 109, 174, 203, 69, 222, 211, 23, 80, 44, 161, 143, 118, 138, 145, 140, 51, 145, 84,
        208, 173, 74, 97, 128, 193, 239, 30, 30,
    ]),
    CompressedRistretto([
        218, 174, 170, 84, 178, 150, 240, 77, 72, 189, 188, 156, 46, 84, 202, 209, 80, 14, 212, 160, 195, 106, 149, 59,
        173, 24, 184, 4, 233, 38, 232, 44,
    ]),
];

lazy_static! {
    /// A static array of pre-generated NUMS points
    pub static ref RISTRETTO_NUMS_POINTS: [RistrettoPoint; 10] = {
        let mut arr = [RistrettoPoint::default(); 10];
        for i in 0..10 {
            arr[i] = RISTRETTO_NUMS_POINTS_COMPRESSED[i].decompress().unwrap();
        }
        arr
    };
}

#[cfg(test)]
mod test {
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use sha2::{Digest, Sha512};

    use crate::ristretto::constants::{RISTRETTO_NUMS_POINTS, RISTRETTO_NUMS_POINTS_COMPRESSED};

    /// Generate a set of NUMS points by hashing domain separation labels and converting the hash output to a Ristretto
    /// generator point. By using `RistrettoPoint::from_uniform_bytes`, the resulting point is a NUMS point if the input
    /// bytes are from a uniform distribution.
    fn nums_ristretto(n: usize) -> (Vec<RistrettoPoint>, Vec<CompressedRistretto>) {
        let mut points = Vec::with_capacity(n);
        let mut compressed_points = Vec::with_capacity(n);
        let mut a: [u8; 64] = [0; 64];
        for i in 0..n {
            let mut data = b"TARI CRYPTO NUMS BASEPOINT LABEL - ".to_vec();
            data.append(&mut i.to_le_bytes().to_vec());
            let hashed_v = Sha512::digest(&*data);
            a.copy_from_slice(&hashed_v);
            let next_val = RistrettoPoint::from_uniform_bytes(&a);
            points.push(next_val);
            compressed_points.push(next_val.compress());
        }
        (points, compressed_points)
    }

    /// Confirm that the [RISTRETTO_NUM_POINTS array](Const.RISTRETTO_NUMS_POINTS.html) is generated with Nothing Up
    /// My Sleeve (NUMS).
    #[test]
    pub fn check_nums_points() {
        let n = RISTRETTO_NUMS_POINTS_COMPRESSED.len();
        let v_arr = nums_ristretto(n);
        for i in 0..n {
            assert_eq!(v_arr.0[i], RISTRETTO_NUMS_POINTS[i]);
            assert_eq!(v_arr.1[i], RISTRETTO_NUMS_POINTS_COMPRESSED[i]);
        }
    }
}
