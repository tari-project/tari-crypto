// Copyright 2020. The Tari Project
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{fmt, ops::Deref};
use tari_utilities::hex::Hex;

pub type HashValue = [u8; 32];

/// Convert a slice into a HashValue.
///
/// # Panics
///
/// The function does not check slice for length at all.  You need to check this / guarantee it yourself.
pub fn to_hash(slice: &[u8]) -> Box<HashValue> {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(slice);
    Box::new(hash)
}

// Opcode constants: Script termination
pub const OP_RETURN: u8 = 0x60;

// Opcode constants: Stack manipulation
pub const OP_DROP: u8 = 0x70;
pub const OP_DUP: u8 = 0x71;
pub const OP_REV_ROT: u8 = 0x72;
pub const OP_PUSH_HASH: u8 = 0x7a;

// Opcode constants: Comparisons
pub const OP_EQUAL: u8 = 0x80;
pub const OP_EQUAL_VERIFY: u8 = 0x81;

// Opcode constants: Arithmetic
pub const OP_ADD: u8 = 0x93;
pub const OP_SUB: u8 = 0x94;

// Opcode constants: Cryptography
pub const OP_CHECK_SIG: u8 = 0xac;
pub const OP_CHECK_SIG_VERIFY: u8 = 0xad;
pub const OP_HASH_BLAKE256: u8 = 0xb0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opcode {
    /// Push the associated 32-byte value onto the stack
    PushHash(Box<HashValue>),
    /// Hash to top stack element with the Blake256 hash function and push the result to the stack
    HashBlake256,
    /// Fail the script immediately. (Must be executed.)
    Return,
    /// Drops the top stack item
    Drop,
    /// Duplicates the top stack item
    Dup,
    /// Reverse rotation. The top stack item moves into 3rd place, abc => bca
    RevRot,
    /// Pop two items and push their sum
    Add,
    /// Pop two items and push the second minus the top
    Sub,
    /// Pop the public key and then the signature. If the signature signs the script, push 0 to the stack, otherwise
    /// push 1
    CheckSig,
    /// As for CheckSig, but aborts immediately if the signature is invalid. As opposed to Bitcoin, it pushes a zero
    /// to the stack if successful
    CheckSigVerify,
    /// Pushes 0, if the inputs are exactly equal, 1 otherwise
    Equal,
    /// Pushes 0, if the inputs are exactly equal, aborts otherwise
    EqualVerify,
}

impl Opcode {
    /// Take a byte slice and read the next opcode from it, including any associated data. `read_next` returns a tuple
    /// of the deserialised opcode, and an updated slice that has the Opcode and data removed.
    pub fn read_next(bytes: &[u8]) -> Option<(Opcode, &[u8])> {
        let code = bytes.get(0)?;
        match *code {
            OP_RETURN => Some((Opcode::Return, &bytes[1..])),
            OP_DROP => Some((Opcode::Drop, &bytes[1..])),
            OP_DUP => Some((Opcode::Dup, &bytes[1..])),
            OP_REV_ROT => Some((Opcode::RevRot, &bytes[1..])),
            OP_EQUAL => Some((Opcode::Equal, &bytes[1..])),
            OP_EQUAL_VERIFY => Some((Opcode::EqualVerify, &bytes[1..])),
            OP_ADD => Some((Opcode::Add, &bytes[1..])),
            OP_SUB => Some((Opcode::Sub, &bytes[1..])),
            OP_CHECK_SIG => Some((Opcode::CheckSig, &bytes[1..])),
            OP_CHECK_SIG_VERIFY => Some((Opcode::CheckSigVerify, &bytes[1..])),
            OP_HASH_BLAKE256 => Some((Opcode::HashBlake256, &bytes[1..])),
            OP_PUSH_HASH => {
                if bytes.len() < 33 {
                    return None;
                }
                let hash = to_hash(&bytes[1..33]);
                Some((Opcode::PushHash(hash), &bytes[33..]))
            },
            _ => None,
        }
    }

    /// Convert an opcode into its binary representation and append it to the array. The function returns the byte slice
    /// that matches the opcode as a convenience
    pub fn to_bytes<'a>(&self, array: &'a mut Vec<u8>) -> &'a [u8] {
        let n = array.len();
        match self {
            // Simple matches
            Opcode::Return => array.push(OP_RETURN),
            Opcode::Drop => array.push(OP_DROP),
            Opcode::Dup => array.push(OP_DUP),
            Opcode::Equal => array.push(OP_EQUAL),
            Opcode::EqualVerify => array.push(OP_EQUAL_VERIFY),
            Opcode::Add => array.push(OP_ADD),
            Opcode::Sub => array.push(OP_SUB),
            Opcode::CheckSig => array.push(OP_CHECK_SIG),
            Opcode::CheckSigVerify => array.push(OP_CHECK_SIG_VERIFY),
            Opcode::RevRot => array.push(OP_REV_ROT),
            Opcode::HashBlake256 => array.push(OP_HASH_BLAKE256),
            // Complex matches
            Opcode::PushHash(h) => {
                array.push(OP_PUSH_HASH);
                array.extend_from_slice(h.deref());
            },
        };
        &array[n..]
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use Opcode::*;
        match self {
            HashBlake256 => fmt.write_str("HashBlake256"),
            Return => fmt.write_str("Return"),
            Drop => fmt.write_str("Drop"),
            Dup => fmt.write_str("Dup"),
            RevRot => fmt.write_str("RevRot"),
            Add => fmt.write_str("Add"),
            Sub => fmt.write_str("Sub"),
            CheckSig => fmt.write_str("CheckSig"),
            CheckSigVerify => fmt.write_str("CheckSigVerify"),
            Equal => fmt.write_str("Equal"),
            EqualVerify => fmt.write_str("EqualVerify"),
            PushHash(h) => fmt.write_str(&format!("PushHash({})", (*h).to_hex())),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::script::{Opcode, Opcode::*};

    #[test]
    fn empty_script() {
        assert!(Opcode::read_next(&[]).is_none())
    }

    #[test]
    fn read_next() {
        let script = [0x60u8, 0x71, 0x00];
        let (code, b) = Opcode::read_next(&script).unwrap();
        assert_eq!(code, Return);
        let (code, b) = Opcode::read_next(b).unwrap();
        assert_eq!(code, Dup);
        assert!(Opcode::read_next(b).is_none());
        assert!(Opcode::read_next(&[0x7a]).is_none());
    }

    #[test]
    fn push_hash() {
        let (code, b) = Opcode::read_next(b"\x7a/thirty-two~character~hash~val./").unwrap();
        match code {
            PushHash(v) if &*v == b"/thirty-two~character~hash~val./" => {},
            _ => panic!("Did bot decode push hash"),
        }
        assert!(b.is_empty());
    }
}
