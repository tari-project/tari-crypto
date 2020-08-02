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

#[derive(Debug, Clone)]
pub enum StackItem {
    Number(i64),
    Hash(HashValue),
    Commitment(PedersenCommitment),
    PublicKey(RistrettoPublicKey),
    Signature(RistrettoSchnorr),
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
