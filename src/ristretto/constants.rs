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
        98, 56, 19, 177, 234, 20, 111, 117, 13, 149, 154, 171, 219, 38, 67, 110, 72, 144, 158, 23, 116, 160, 228, 130,
        217, 64, 206, 217, 215, 47, 191, 18,
    ]),
    CompressedRistretto([
        200, 37, 26, 97, 156, 96, 132, 114, 160, 100, 250, 74, 137, 61, 100, 162, 10, 73, 6, 48, 232, 156, 192, 145,
        204, 198, 148, 70, 155, 142, 204, 33,
    ]),
    CompressedRistretto([
        242, 134, 145, 123, 35, 223, 241, 95, 17, 252, 219, 222, 48, 71, 43, 27, 225, 135, 92, 148, 221, 50, 41, 125,
        57, 110, 201, 109, 191, 193, 214, 60,
    ]),
    CompressedRistretto([
        222, 31, 108, 78, 74, 126, 187, 234, 126, 57, 207, 107, 78, 168, 125, 234, 1, 207, 106, 101, 90, 37, 66, 92,
        140, 154, 110, 142, 204, 188, 181, 117,
    ]),
    CompressedRistretto([
        164, 245, 103, 45, 167, 255, 166, 15, 130, 229, 14, 27, 244, 89, 228, 236, 163, 67, 234, 153, 188, 120, 50,
        182, 44, 20, 235, 182, 6, 230, 155, 108,
    ]),
    CompressedRistretto([
        66, 229, 208, 151, 225, 98, 88, 6, 33, 54, 185, 126, 149, 4, 215, 114, 48, 120, 254, 237, 97, 166, 26, 161, 70,
        234, 152, 3, 120, 44, 199, 24,
    ]),
    CompressedRistretto([
        234, 153, 246, 145, 163, 1, 37, 83, 29, 141, 204, 207, 14, 7, 148, 2, 132, 77, 48, 146, 87, 244, 29, 92, 0, 23,
        135, 180, 38, 252, 113, 119,
    ]),
    CompressedRistretto([
        136, 16, 34, 235, 193, 68, 129, 24, 197, 150, 189, 17, 69, 8, 239, 220, 52, 98, 249, 229, 213, 216, 219, 138,
        154, 94, 182, 224, 134, 1, 2, 76,
    ]),
    CompressedRistretto([
        208, 187, 119, 38, 163, 204, 121, 219, 111, 215, 141, 8, 134, 238, 82, 60, 245, 224, 139, 255, 111, 252, 4, 81,
        179, 238, 176, 77, 88, 210, 144, 123,
    ]),
    CompressedRistretto([
        110, 128, 149, 108, 46, 193, 113, 71, 214, 210, 246, 51, 128, 210, 102, 205, 47, 27, 179, 247, 191, 20, 106,
        199, 84, 218, 136, 137, 120, 9, 133, 93,
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
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
    };
    use sha2::{Digest, Sha512};

    use crate::ristretto::constants::{RISTRETTO_NUMS_POINTS, RISTRETTO_NUMS_POINTS_COMPRESSED};

    /// Generate a set of NUMS points by sequentially hashing domain separated Ristretto255 generator point. By using
    /// `from_uniform_bytes`, the resulting point is a NUMS point if the input bytes are from a uniform distribution.
    fn nums_ristretto(n: usize) -> (Vec<RistrettoPoint>, Vec<CompressedRistretto>) {
        let mut val = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let mut points = Vec::with_capacity(n);
        let mut compressed_points = Vec::with_capacity(n);
        let mut a: [u8; 64] = [0; 64];
        for i in 0..n {
            let mut data = b"TARI CRYPTO - ".to_vec();
            data.append(&mut i.to_le_bytes().to_vec());
            data.append(&mut val.to_vec());
            let hashed_v = Sha512::digest(&*data);
            a.copy_from_slice(&hashed_v);
            let next_val = RistrettoPoint::from_uniform_bytes(&a);
            points.push(next_val);
            let next_compressed = next_val.compress();
            val = next_compressed.to_bytes();
            compressed_points.push(next_compressed);
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
