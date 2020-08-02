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

use crate::{
    ristretto::{pedersen::PedersenCommitment, RistrettoPublicKey, RistrettoSchnorr},
    script::{error::ScriptError, op_codes::HashValue},
};
use tari_utilities::ByteArray;
use crate::ristretto::RistrettoSecretKey;

pub const MAX_STACK_SIZE: usize = 256;

#[macro_export]
macro_rules! inputs {
    ($($input:expr),+) => {{
        use crate::script::{ExecutionStack, StackItem};

        let items = vec![$(StackItem::from($input)),+];
        ExecutionStack::new(items)
    }}
}

macro_rules! stack_item_from {
    ($from_type:ty => $variant:ident) => {
        impl From<$from_type> for StackItem {
            fn from(item: $from_type) -> Self {
                StackItem::$variant(item)
            }
        }
    };
}

pub const TYPE_NUMBER: u8 = 1;
pub const TYPE_HASH: u8 = 2;
pub const TYPE_COMMITMENT: u8 = 3;
pub const TYPE_PUBKEY: u8 = 4;
pub const TYPE_SIG: u8 = 5;

#[derive(Debug, Clone)]
pub enum StackItem {
    Number(i64),
    Hash(HashValue),
    Commitment(PedersenCommitment),
    PublicKey(RistrettoPublicKey),
    Signature(RistrettoSchnorr),
}

impl StackItem {
    pub fn to_bytes<'a>(&self, array: &'a mut Vec<u8>) -> &'a [u8] {
        let n = array.len();
        match self {
            StackItem::Number(v) => {
                array.push(TYPE_NUMBER);
                array.extend_from_slice(&v.to_le_bytes());
            }
            StackItem::Hash(h) => {
                array.push(TYPE_HASH);
                array.extend_from_slice(&h[..]);
            }
            StackItem::Commitment(c) => {
                array.push(TYPE_COMMITMENT);
                array.extend_from_slice(c.as_bytes());
            }
            StackItem::PublicKey(p) => {
                array.push(TYPE_PUBKEY);
                array.extend_from_slice(p.as_bytes());
            }
            StackItem::Signature(s) => {
                array.push(TYPE_SIG);
                array.extend_from_slice(s.get_public_nonce().as_bytes());
                array.extend_from_slice(s.get_signature().as_bytes());
            }
        };
        &array[n..]
    }

    /// Take a byte slice an read the next stack item from it, including any associated data. `read_next` returns a
    /// tuple of the deserialised item, and an updated slice that has the Opcode and data removed.
    pub fn read_next(bytes: &[u8]) -> Option<(Self, &[u8])> {
        let code = bytes.get(0)?;
        match *code {
            TYPE_NUMBER => StackItem::to_number(&bytes[1..]),
            TYPE_HASH => StackItem::to_hash(&bytes[1..]),
            TYPE_COMMITMENT => StackItem::to_commitemnt(&bytes[1..]),
            TYPE_PUBKEY => StackItem::to_pubkey(&bytes[1..]),
            TYPE_SIG => StackItem::to_sig(&bytes[1..]),
            _ => None,
        }
    }

    fn to_number(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < 4 {
            return None;
        }
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&b[..4]);
        Some((StackItem::Number(i64::from_le_bytes(arr)), &b[4..]))
    }

    fn to_hash(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b[..32]);
        Some((StackItem::Hash(arr), &b[32..]))
    }

    fn to_commitment(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < 32 {
            return None;
        }
        let c = PedersenCommitment::from_bytes(&b[..32])?;
        Some((StackItem::Commitment(c), &b[32..]))
    }

    fn to_pubkey(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < 32 {
            return None;
        }
        let p = RistrettoPublicKey::from_bytes(&b[..32])?;
        Some((StackItem::PublicKey(c), &b[32..]))
    }

    fn to_sig(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < 64 {
            return None;
        }
        let r = RistrettoPublicKey::from_bytes(&b[..32])?;
        let s = RistrettoSecretKey::from_bytes(&b[32..64])?;
        let sig = RistrettoSchnorr::new(r, s);
        Some((StackItem::Signature(sig), &b[64..]))
    }
}

stack_item_from!(i64 => Number);
stack_item_from!(PedersenCommitment => Commitment);
stack_item_from!(RistrettoPublicKey => PublicKey);
stack_item_from!(RistrettoSchnorr => Signature);

#[derive(Debug, Default, Clone)]
pub struct ExecutionStack {
    items: Vec<StackItem>,
}

impl ExecutionStack {
    pub fn new(items: Vec<StackItem>) -> Self {
        ExecutionStack { items }
    }

    pub fn size(&self) -> usize {
        self.items.len()
    }

    pub fn peek(&self) -> Option<&StackItem> {
        self.items.last()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn pop(&mut self) -> Option<StackItem> {
        self.items.pop()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.items.iter().fold(Vec::with_capacity(512), |mut bytes, item| {
            item.to_bytes(&mut bytes);
            bytes
        })
    }

    pub fn push(&mut self, item: StackItem) -> Result<(), ScriptError> {
        if self.size() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackOverflow);
        }
        self.items.push(item);
        Ok(())
    }

    /// Pushes the top stack element down `depth` positions
    pub(crate) fn push_down(&mut self, depth: usize) -> Result<(), ScriptError> {
        let n = self.size();
        if n < depth + 1 {
            return Err(ScriptError::StackUnderflow);
        }
        if depth == 0 {
            return Ok(());
        }
        let top = self.pop().unwrap();
        self.items.insert(n - depth - 1, top);
        Ok(())
    }
}
