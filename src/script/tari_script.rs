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

// pending updates to Dalek/Digest
#[allow(deprecated)]
use crate::{
    common::Blake256,
    hash::sha3::Sha3,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    script::{
        error::ScriptError,
        op_codes::{slice_to_hash, Message, Opcode},
        ExecutionStack,
        HashValue,
        ScriptContext,
        StackItem,
    },
};
use blake2::Digest;
use sha2::Sha256;
use std::{cmp::Ordering, convert::TryFrom, fmt, ops::Deref};
use tari_utilities::{
    hex::{from_hex, to_hex, Hex, HexError},
    ByteArray,
};

#[macro_export]
macro_rules! script {
    ($($opcode:ident$(($var:expr))?) +) => {{
        use $crate::script::TariScript;
        use $crate::script::Opcode;
        let script = vec![$(Opcode::$opcode $(($var))?),+];
        TariScript::new(script)
    }}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TariScript {
    script: Vec<Opcode>,
}

impl TariScript {
    pub fn new(script: Vec<Opcode>) -> Self {
        TariScript { script }
    }

    /// Executes the script using a default context. If successful, returns the final stack item.
    pub fn execute(&self, inputs: &ExecutionStack) -> Result<StackItem, ScriptError> {
        self.execute_with_context(inputs, &ScriptContext::default())
    }

    /// Execute the script with the given inputs and the provided context. If successful, returns the final stack item.
    pub fn execute_with_context(
        &self,
        inputs: &ExecutionStack,
        context: &ScriptContext,
    ) -> Result<StackItem, ScriptError>
    {
        // Copy all inputs onto the stack
        let mut stack = inputs.clone();

        // Local execution state
        let mut state = ExecutionState::default();

        for opcode in self.script.iter() {
            if self.should_execute(opcode, &state)? {
                self.execute_opcode(opcode, &mut stack, context, &mut state)?
            } else {
                continue;
            }
        }

        // the script has finished but there was an open IfThen or Else!
        if state.if_count > 0 || state.else_count > 0 {
            return Err(ScriptError::MissingOpcode);
        }

        // After the script completes, it is successful if and only if it has not aborted, and there is exactly a single
        // element on the stack. The script fails if the stack is empty, or contains more than one element, or aborts
        // early.
        if stack.size() == 1 {
            stack.pop().ok_or(ScriptError::NonUnitLengthStack)
        } else {
            Err(ScriptError::NonUnitLengthStack)
        }
    }

    fn should_execute(&self, opcode: &Opcode, state: &ExecutionState) -> Result<bool, ScriptError> {
        match opcode {
            &Opcode::Else | &Opcode::EndIf => {
                // if we're getting Else or EndIf before an IfThen then the script is invalid
                if state.if_count == 0 {
                    return Err(ScriptError::InvalidOpcode);
                }
                // if the opcode is Else or EndIf then execute it
                // Else or EndIf will update the execution state
                Ok(true)
            },
            _ => {
                // otherwise continue either executing or skipping opcodes
                // until reaching Else or Endif
                Ok(state.executing)
            },
        }
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.script.iter().fold(Vec::with_capacity(512), |mut bytes, op| {
            op.to_bytes(&mut bytes);
            bytes
        })
    }

    /// Calculate the hash of the script.
    /// `as_hash` returns [ScriptError::InvalidDigest] if the digest function does not produce at least 32 bytes of
    /// output.
    pub fn as_hash<D: Digest>(&self) -> Result<HashValue, ScriptError> {
        if D::output_size() < 32 {
            return Err(ScriptError::InvalidDigest);
        }
        let h = D::digest(&self.as_bytes());
        Ok(slice_to_hash(&h.as_slice()[..32]))
    }

    /// Try to deserialise a byte slice into a valid Tari script
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScriptError> {
        let script = Opcode::parse(bytes)?;

        Ok(TariScript { script })
    }

    /// Convert the script into an array of opcode strings.
    ///
    /// # Example
    /// ```edition2018
    /// use tari_crypto::script::TariScript;
    /// use tari_utilities::hex::Hex;
    ///
    /// let hex_script = "71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e58170ac276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708";
    /// let script = TariScript::from_hex(hex_script).unwrap();
    /// let ops = vec![
    ///     "Dup",
    ///     "HashBlake256",
    ///     "PushHash(ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5)",
    ///     "EqualVerify",
    ///     "Drop",
    ///     "CheckSig(276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708)",
    /// ]
    /// .into_iter()
    /// .map(String::from)
    /// .collect::<Vec<String>>();
    /// assert_eq!(script.to_opcodes(), ops);
    /// ```
    pub fn to_opcodes(&self) -> Vec<String> {
        self.script.iter().map(|op| op.to_string()).collect()
    }

    /// Calculate the message hash that CHECKSIG uses to verify signatures
    pub fn script_message(&self, pub_key: &RistrettoPublicKey) -> Result<RistrettoSecretKey, ScriptError> {
        let b = Blake256::new()
            .chain(pub_key.as_bytes())
            .chain(&self.as_bytes())
            .result();
        RistrettoSecretKey::from_bytes(b.as_slice()).map_err(|_| ScriptError::InvalidSignature)
    }

    // pending updates to Dalek/Digest
    #[allow(deprecated)]
    fn execute_opcode(
        &self,
        opcode: &Opcode,
        stack: &mut ExecutionStack,
        ctx: &ScriptContext,
        state: &mut ExecutionState,
    ) -> Result<(), ScriptError>
    {
        use Opcode::*;
        use StackItem::*;
        match opcode {
            CheckHeightVerify(height) => TariScript::handle_check_height_verify(*height, ctx.block_height()),
            CheckHeight(height) => TariScript::handle_check_height(stack, *height, ctx.block_height()),
            CompareHeightVerify => TariScript::handle_compare_height_verify(stack, ctx.block_height()),
            CompareHeight => TariScript::handle_compare_height(stack, ctx.block_height()),
            Nop => Ok(()),
            PushZero => stack.push(Number(0)),
            PushOne => stack.push(Number(1)),
            PushHash(h) => stack.push(Hash(*h.clone())),
            PushInt(n) => stack.push(Number(*n)),
            PushPubKey(p) => stack.push(PublicKey(*p.clone())),
            Drop => TariScript::handle_drop(stack),
            Dup => TariScript::handle_dup(stack),
            RevRot => stack.push_down(2),
            GeZero => TariScript::handle_cmp_to_zero(stack, &[Ordering::Greater, Ordering::Equal]),
            GtZero => TariScript::handle_cmp_to_zero(stack, &[Ordering::Greater]),
            LeZero => TariScript::handle_cmp_to_zero(stack, &[Ordering::Less, Ordering::Equal]),
            LtZero => TariScript::handle_cmp_to_zero(stack, &[Ordering::Less]),
            Add => TariScript::handle_op_add(stack),
            Sub => TariScript::handle_op_sub(stack),
            Equal => match TariScript::handle_equal(stack)? {
                true => stack.push(Number(1)),
                false => stack.push(Number(0)),
            },
            EqualVerify => match TariScript::handle_equal(stack)? {
                true => Ok(()),
                false => Err(ScriptError::VerifyFailed),
            },
            Or(n) => TariScript::handle_or(stack, *n),
            OrVerify(n) => TariScript::handle_or_verify(stack, *n),
            HashBlake256 => TariScript::handle_hash::<Blake256>(stack),
            HashSha256 => TariScript::handle_hash::<Sha256>(stack),
            HashSha3 => TariScript::handle_hash::<Sha3>(stack),
            CheckSig(msg) => match self.check_sig(stack, *msg.deref())? {
                true => stack.push(Number(1)),
                false => stack.push(Number(0)),
            },
            CheckSigVerify(msg) => match self.check_sig(stack, *msg.deref())? {
                true => Ok(()),
                false => Err(ScriptError::VerifyFailed),
            },
            Return => Err(ScriptError::Return),
            IfThen => TariScript::handle_if_then(stack, state),
            Else => TariScript::handle_else(state),
            EndIf => TariScript::handle_end_if(state),
        }
    }

    fn handle_check_height_verify(height: u64, block_height: u64) -> Result<(), ScriptError> {
        if block_height >= height {
            Ok(())
        } else {
            Err(ScriptError::VerifyFailed)
        }
    }

    fn handle_check_height(stack: &mut ExecutionStack, height: u64, block_height: u64) -> Result<(), ScriptError> {
        let height = i64::try_from(height)?;
        let block_height = i64::try_from(block_height)?;
        let item = StackItem::Number(block_height - height);

        stack.push(item)
    }

    fn handle_compare_height_verify(stack: &mut ExecutionStack, block_height: u64) -> Result<(), ScriptError> {
        let target_height = stack.pop_into_number::<u64>()?;

        if block_height >= target_height {
            Ok(())
        } else {
            Err(ScriptError::VerifyFailed)
        }
    }

    fn handle_compare_height(stack: &mut ExecutionStack, block_height: u64) -> Result<(), ScriptError> {
        let target_height = stack.pop_into_number::<i64>()?;
        let block_height = i64::try_from(block_height)?;

        let item = StackItem::Number(block_height - target_height);

        stack.push(item)
    }

    fn handle_cmp_to_zero(stack: &mut ExecutionStack, valid_orderings: &[Ordering]) -> Result<(), ScriptError> {
        let stack_number = stack.pop_into_number::<i64>()?;
        let ordering = &stack_number.cmp(&0);

        if valid_orderings.contains(ordering) {
            stack.push(StackItem::Number(1))
        } else {
            stack.push(StackItem::Number(0))
        }
    }

    fn handle_or(stack: &mut ExecutionStack, n: u8) -> Result<(), ScriptError> {
        if stack.pop_n_plus_one_contains(n)? {
            stack.push(StackItem::Number(1))
        } else {
            stack.push(StackItem::Number(0))
        }
    }

    fn handle_or_verify(stack: &mut ExecutionStack, n: u8) -> Result<(), ScriptError> {
        if stack.pop_n_plus_one_contains(n)? {
            Ok(())
        } else {
            Err(ScriptError::VerifyFailed)
        }
    }

    fn handle_if_then(stack: &mut ExecutionStack, state: &mut ExecutionState) -> Result<(), ScriptError> {
        let pred = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match pred {
            StackItem::Number(1) => {
                // continue execution until Else opcode
                state.executing = true;
                state.if_count += 1;
                Ok(())
            },
            StackItem::Number(0) => {
                // skip execution until Else opcode
                state.executing = false;
                state.if_count += 1;
                Ok(())
            },
            _ => Err(ScriptError::InvalidInput),
        }
    }

    fn handle_else(state: &mut ExecutionState) -> Result<(), ScriptError> {
        // check to make sure Else is expected
        // and not trying to execute more Else opcodes than IfThen
        if state.if_count > 0 && state.else_count < state.if_count {
            state.executing = !state.executing;
            state.else_count += 1;
            Ok(())
        } else {
            Err(ScriptError::InvalidOpcode)
        }
    }

    fn handle_end_if(state: &mut ExecutionState) -> Result<(), ScriptError> {
        // check to make sure EndIf is expected
        // if_count may be greater than else_count when there are nested IfThen-Else-EndIf opcodes
        if state.if_count > 0 && state.if_count >= state.else_count {
            state.executing = true;
            state.if_count -= 1;
            if state.else_count > 0 {
                state.else_count -= 1;
            } else {
                return Err(ScriptError::MissingOpcode);
            }
            Ok(())
        } else {
            Err(ScriptError::InvalidOpcode)
        }
    }

    /// Handle opcodes that push a hash to the stack. I'm not doing any length checks right now, so this should be
    /// added once other digest functions are provided that don't produce 32 byte hashes
    fn handle_hash<D: Digest>(stack: &mut ExecutionStack) -> Result<(), ScriptError> {
        use StackItem::*;
        let top = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        // use a closure to grab &b while it still exists in the match expression
        let to_arr = |b: &[u8]| {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(D::digest(b).as_slice());
            hash
        };
        let hash_value = match top {
            Commitment(c) => to_arr(c.as_bytes()),
            PublicKey(k) => to_arr(k.as_bytes()),
            Hash(h) => to_arr(&h),
            _ => return Err(ScriptError::IncompatibleTypes),
        };

        stack.push(Hash(hash_value))
    }

    fn handle_dup(stack: &mut ExecutionStack) -> Result<(), ScriptError> {
        let last = if let Some(last) = stack.peek() {
            last.clone()
        } else {
            return Err(ScriptError::StackUnderflow);
        };
        stack.push(last)
    }

    fn handle_drop(stack: &mut ExecutionStack) -> Result<(), ScriptError> {
        match stack.pop() {
            Some(_) => Ok(()),
            None => Err(ScriptError::StackUnderflow),
        }
    }

    fn handle_op_add(stack: &mut ExecutionStack) -> Result<(), ScriptError> {
        use StackItem::*;
        let top = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let two = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match (top, two) {
            (Number(v1), Number(v2)) => stack.push(Number(v1.checked_add(v2).ok_or(ScriptError::ValueExceedsBounds)?)),
            (Commitment(c1), Commitment(c2)) => stack.push(Commitment(&c1 + &c2)),
            (PublicKey(p1), PublicKey(p2)) => stack.push(PublicKey(&p1 + &p2)),
            (Signature(s1), Signature(s2)) => stack.push(Signature(&s1 + &s2)),
            (_, _) => Err(ScriptError::IncompatibleTypes),
        }
    }

    fn handle_op_sub(stack: &mut ExecutionStack) -> Result<(), ScriptError> {
        use StackItem::*;
        let top = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let two = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match (top, two) {
            (Number(v1), Number(v2)) => stack.push(Number(v2.checked_sub(v1).ok_or(ScriptError::ValueExceedsBounds)?)),
            (Commitment(c1), Commitment(c2)) => stack.push(Commitment(&c2 - &c1)),
            (..) => Err(ScriptError::IncompatibleTypes),
        }
    }

    fn handle_equal(stack: &mut ExecutionStack) -> Result<bool, ScriptError> {
        use StackItem::*;
        let top = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let two = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match (top, two) {
            (Number(v1), Number(v2)) => Ok(v1 == v2),
            (Commitment(c1), Commitment(c2)) => Ok(c1 == c2),
            (Signature(s1), Signature(s2)) => Ok(s1 == s2),
            (PublicKey(p1), PublicKey(p2)) => Ok(p1 == p2),
            (Hash(h1), Hash(h2)) => Ok(h1 == h2),
            (..) => Err(ScriptError::IncompatibleTypes),
        }
    }

    fn check_sig(&self, stack: &mut ExecutionStack, message: Message) -> Result<bool, ScriptError> {
        use StackItem::*;
        let pk = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let sig = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match (pk, sig) {
            (PublicKey(p), Signature(s)) => Ok(s.verify_challenge(&p, &message)),
            (..) => Err(ScriptError::IncompatibleTypes),
        }
    }
}

impl Hex for TariScript {
    fn from_hex(hex: &str) -> Result<Self, HexError>
    where Self: Sized {
        let bytes = from_hex(hex)?;
        TariScript::from_bytes(&bytes).map_err(|_| HexError::HexConversionError)
    }

    fn to_hex(&self) -> String {
        to_hex(&self.as_bytes())
    }
}

/// The default Tari script is to push a single zero onto the stack; which will execute successfully with zero inputs.
impl Default for TariScript {
    fn default() -> Self {
        script!(PushZero)
    }
}

impl fmt::Display for TariScript {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.to_opcodes().join(" ");
        f.write_str(&s)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExecutionState {
    executing: bool,
    if_count: u16,
    else_count: u16,
}

impl Default for ExecutionState {
    fn default() -> Self {
        Self {
            executing: true,
            if_count: 0,
            else_count: 0,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::script::StackItem;
    #[allow(deprecated)]
    use crate::{
        common::Blake256,
        hash::sha3::Sha3,
        inputs,
        keys::{PublicKey, SecretKey},
        ristretto::{pedersen::PedersenCommitment, RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
        script::{
            error::ScriptError,
            op_codes::{slice_to_boxed_hash, slice_to_boxed_message, HashValue},
            ExecutionStack,
            ScriptContext,
            StackItem::{Commitment, Hash, Number},
            TariScript,
            DEFAULT_SCRIPT_HASH,
        },
    };
    use blake2::Digest;
    use sha2::Sha256;
    use tari_utilities::{hex::Hex, ByteArray};

    fn context_with_height(height: u64) -> ScriptContext {
        ScriptContext::new(height, &HashValue::default(), &PedersenCommitment::default())
    }

    #[test]
    fn default_script() {
        let script = TariScript::default();
        let inputs = ExecutionStack::default();
        assert!(script.execute(&inputs).is_ok());
        assert_eq!(&script.to_hex(), "7b");
        assert_eq!(script.as_hash::<Blake256>().unwrap(), DEFAULT_SCRIPT_HASH);
    }

    #[test]
    fn op_or() {
        let script = script!(Or(1));

        let inputs = inputs!(4, 4);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let inputs = inputs!(3, 4);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(0));

        let script = script!(Or(3));

        let inputs = inputs!(1, 2, 1, 3);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let inputs = inputs!(1, 2, 4, 3);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(0));

        let mut rng = rand::thread_rng();
        let (_, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let inputs = inputs!(1, p.clone(), 1, 3);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::InvalidInput));

        let inputs = inputs!(p, 2, 1, 3);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::InvalidInput));

        let inputs = inputs!(2, 4, 3);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::StackUnderflow));

        let script = script!(OrVerify(1));

        let inputs = inputs!(1, 4, 4);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let inputs = inputs!(1, 3, 4);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::VerifyFailed));

        let script = script!(OrVerify(2));

        let inputs = inputs!(1, 2, 2, 3);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let inputs = inputs!(1, 2, 3, 4);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::VerifyFailed));
    }

    #[test]
    fn op_if_then_else() {
        let script = script!(IfThen PushInt(420) Else PushInt(66) EndIf);

        let inputs = inputs!(1);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap(), Number(420));

        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap(), Number(66));

        // nested
        let script = script!(IfThen PushOne IfThen PushInt(420) Else PushInt(555) EndIf Else PushInt(66) EndIf);
        let inputs = inputs!(1);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap(), Number(420));

        let script = script!(IfThen PushInt(420) Else PushZero IfThen PushInt(111) Else PushInt(66) EndIf Nop EndIf);
        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap(), Number(66));

        // duplicate else
        let script = script!(IfThen PushInt(420) Else PushInt(66) Else PushInt(777) EndIf);

        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::InvalidOpcode);

        // unexpected else
        let script = script!(Else);

        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::InvalidOpcode);

        // unexpected endif
        let script = script!(EndIf);

        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::InvalidOpcode);

        // duplicate endif
        let script = script!(IfThen PushInt(420) Else PushInt(66) EndIf EndIf);
        let inputs = inputs!(0);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::InvalidOpcode);

        // no else or endif
        let script = script!(IfThen PushOne IfThen PushOne);
        let inputs = inputs!(1);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::MissingOpcode);

        // no else
        let script = script!(IfThen PushOne EndIf);
        let inputs = inputs!(1);
        let result = script.execute(&inputs);
        assert_eq!(result.unwrap_err(), ScriptError::MissingOpcode);
    }

    #[test]
    fn op_check_height() {
        let inputs = ExecutionStack::default();
        let script = script!(CheckHeight(5));

        for block_height in 1..=10 {
            let ctx = context_with_height(block_height as u64);
            assert_eq!(
                script.execute_with_context(&inputs, &ctx).unwrap(),
                Number(block_height - 5)
            );
        }

        let script = script!(CheckHeight(u64::MAX));
        let ctx = context_with_height(i64::MAX as u64);
        let err = script.execute_with_context(&inputs, &ctx).unwrap_err();
        assert!(matches!(err, ScriptError::ValueExceedsBounds));

        let script = script!(CheckHeightVerify(5));
        let inputs = inputs!(1);

        for block_height in 1..5 {
            let ctx = context_with_height(block_height);
            let err = script.execute_with_context(&inputs, &ctx).unwrap_err();
            assert!(matches!(err, ScriptError::VerifyFailed));
        }

        for block_height in 5..=10 {
            let ctx = context_with_height(block_height);
            let result = script.execute_with_context(&inputs, &ctx).unwrap();
            assert_eq!(result, Number(1));
        }
    }

    #[test]
    fn op_compare_height() {
        let script = script!(CompareHeight);
        let inputs = inputs!(5);

        for block_height in 1..=10 {
            let ctx = context_with_height(block_height as u64);
            assert_eq!(
                script.execute_with_context(&inputs, &ctx).unwrap(),
                Number(block_height - 5)
            );
        }

        let script = script!(CompareHeightVerify);
        let inputs = inputs!(1, 5);

        for block_height in 1..5 {
            let ctx = context_with_height(block_height);
            let err = script.execute_with_context(&inputs, &ctx).unwrap_err();
            assert!(matches!(err, ScriptError::VerifyFailed));
        }

        for block_height in 5..=10 {
            let ctx = context_with_height(block_height);
            let result = script.execute_with_context(&inputs, &ctx).unwrap();
            assert_eq!(result, Number(1));
        }
    }

    #[test]
    fn op_drop_push() {
        let inputs = inputs!(420);
        let script = script!(Drop PushOne);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));

        let script = script!(Drop PushZero);
        assert_eq!(script.execute(&inputs).unwrap(), Number(0));

        let script = script!(Drop PushInt(5));
        assert_eq!(script.execute(&inputs).unwrap(), Number(5));
    }

    #[test]
    fn op_comparison_to_zero() {
        let script = script!(GeZero);
        let inputs = inputs!(1);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));
        let inputs = inputs!(0);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));

        let script = script!(GtZero);
        let inputs = inputs!(1);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));
        let inputs = inputs!(0);
        assert_eq!(script.execute(&inputs).unwrap(), Number(0));

        let script = script!(LeZero);
        let inputs = inputs!(-1);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));
        let inputs = inputs!(0);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));

        let script = script!(LtZero);
        let inputs = inputs!(-1);
        assert_eq!(script.execute(&inputs).unwrap(), Number(1));
        let inputs = inputs!(0);
        assert_eq!(script.execute(&inputs).unwrap(), Number(0));
    }

    #[test]
    #[allow(deprecated)]
    fn op_hash() {
        let mut rng = rand::thread_rng();
        let (_, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let c = PedersenCommitment::from_public_key(&p);
        let script = script!(HashSha256);

        let hash = Sha256::digest(p.as_bytes());
        let inputs = inputs!(p.clone());
        assert_eq!(script.execute(&inputs).unwrap(), Hash(hash.into()));

        let hash = Sha256::digest(c.as_bytes());
        let inputs = inputs!(c.clone());
        assert_eq!(script.execute(&inputs).unwrap(), Hash(hash.into()));

        let script = script!(HashSha3);

        let hash = Sha3::digest(p.as_bytes());
        let inputs = inputs!(p);
        assert_eq!(script.execute(&inputs).unwrap(), Hash(hash.into()));

        let hash = Sha3::digest(c.as_bytes());
        let inputs = inputs!(c);
        assert_eq!(script.execute(&inputs).unwrap(), Hash(hash.into()));
    }

    #[test]
    fn op_return() {
        let script = script!(Return);
        let inputs = ExecutionStack::default();
        assert_eq!(script.execute(&inputs), Err(ScriptError::Return));
    }

    #[test]
    fn op_add() {
        let script = script!(Add);
        let inputs = inputs!(3, 2);
        assert_eq!(script.execute(&inputs).unwrap(), Number(5));
        let inputs = inputs!(3, -3);
        assert_eq!(script.execute(&inputs).unwrap(), Number(0));
        let inputs = inputs!(i64::MAX, 1);
        assert_eq!(script.execute(&inputs), Err(ScriptError::ValueExceedsBounds));
        let inputs = inputs!(1);
        assert_eq!(script.execute(&inputs), Err(ScriptError::StackUnderflow));
    }

    #[test]
    fn op_add_commitments() {
        let script = script!(Add);
        let mut rng = rand::thread_rng();
        let (_, c1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (_, c2) = RistrettoPublicKey::random_keypair(&mut rng);
        let c3 = &c1 + &c2;
        let c3 = PedersenCommitment::from_public_key(&c3);
        let inputs = inputs!(
            PedersenCommitment::from_public_key(&c1),
            PedersenCommitment::from_public_key(&c2)
        );
        assert_eq!(script.execute(&inputs).unwrap(), Commitment(c3));
    }

    #[test]
    fn op_sub() {
        use crate::script::StackItem::Number;
        let script = script!(Add Sub);
        let inputs = inputs!(5, 3, 2);
        assert_eq!(script.execute(&inputs).unwrap(), Number(0));
        let inputs = inputs!(i64::MAX, 1);
        assert_eq!(script.execute(&inputs), Err(ScriptError::ValueExceedsBounds));
        let script = script!(Sub);
        let inputs = inputs!(5, 3);
        assert_eq!(script.execute(&inputs).unwrap(), Number(2));
    }

    #[test]
    fn serialisation() {
        let script = script!(Add Sub Add);
        assert_eq!(&script.as_bytes(), &[0x93, 0x94, 0x93]);
        assert_eq!(TariScript::from_bytes(&[0x93, 0x94, 0x93]).unwrap(), script);
        assert_eq!(script.to_hex(), "939493");
        assert_eq!(TariScript::from_hex("939493").unwrap(), script);
    }

    #[test]
    fn check_sig() {
        use crate::script::StackItem::Number;
        let mut rng = rand::thread_rng();
        let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let r = RistrettoSecretKey::random(&mut rng);
        let m = RistrettoSecretKey::random(&mut rng);
        let s = RistrettoSchnorr::sign(k.clone(), r.clone(), m.as_bytes()).unwrap();
        let msg = slice_to_boxed_message(m.as_bytes());
        let script = script!(CheckSig(msg));
        let inputs = inputs!(s.clone(), p.clone());
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let n = RistrettoSecretKey::random(&mut rng);
        let msg = slice_to_boxed_message(n.as_bytes());
        let script = script!(CheckSig(msg));
        let inputs = inputs!(s, p);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(0));
    }

    #[test]
    fn check_sig_verify() {
        use crate::script::StackItem::Number;
        let mut rng = rand::thread_rng();
        let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let r = RistrettoSecretKey::random(&mut rng);
        let m = RistrettoSecretKey::random(&mut rng);
        let s = RistrettoSchnorr::sign(k.clone(), r.clone(), m.as_bytes()).unwrap();
        let msg = slice_to_boxed_message(m.as_bytes());
        let script = script!(CheckSigVerify(msg) PushOne);
        let inputs = inputs!(s.clone(), p.clone());
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        let n = RistrettoSecretKey::random(&mut rng);
        let msg = slice_to_boxed_message(n.as_bytes());
        let script = script!(CheckSigVerify(msg));
        let inputs = inputs!(s, p);
        let err = script.execute(&inputs).unwrap_err();
        assert!(matches!(err, ScriptError::VerifyFailed));
    }

    #[test]
    fn add_partial_signatures() {
        use crate::script::StackItem::Number;
        let mut rng = rand::thread_rng();
        let (k1, p1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, p2) = RistrettoPublicKey::random_keypair(&mut rng);
        let r1 = RistrettoSecretKey::random(&mut rng);
        let r2 = RistrettoSecretKey::random(&mut rng);

        let m = RistrettoSecretKey::random(&mut rng);
        let msg = slice_to_boxed_message(m.as_bytes());
        let script = script!(Add RevRot Add CheckSigVerify(msg) PushOne);

        let s1 = RistrettoSchnorr::sign(k1.clone(), r1.clone(), m.as_bytes()).unwrap();
        let s2 = RistrettoSchnorr::sign(k2.clone(), r2.clone(), m.as_bytes()).unwrap();
        let inputs = inputs!(p1, p2, s1, s2);
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));
    }

    #[test]
    fn pay_to_public_key_hash() {
        use crate::script::StackItem::PublicKey;
        let k =
            RistrettoSecretKey::from_hex("7212ac93ee205cdbbb57c4f0f815fbf8db25b4d04d3532e2262e31907d82c700").unwrap();
        let p = RistrettoPublicKey::from_secret_key(&k); // 56c0fa32558d6edc0916baa26b48e745de834571534ca253ea82435f08ebbc7c
        let hash = Blake256::digest(p.as_bytes());
        let pkh = slice_to_boxed_hash(hash.as_slice()); // ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5

        // Unlike in Bitcoin where P2PKH includes a CheckSig at the end of the script, that part of the process is built
        // into definition of how TariScript is evaluated by a base node or wallet
        let script = script!(Dup HashBlake256 PushHash(pkh) EqualVerify);
        let hex_script = "71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e581";
        // Test serialisation
        assert_eq!(script.to_hex(), hex_script);
        // Test de-serialisation
        assert_eq!(TariScript::from_hex(hex_script).unwrap(), script);

        let inputs = inputs!(p.clone());

        let result = script.execute(&inputs).unwrap();

        assert_eq!(result, PublicKey(p));
    }

    #[test]
    fn hex_only() {
        use crate::script::StackItem::Number;
        let hex = "0500f7c695528c858cde76dab3076908e01228b6dbdd5f671bed1b03b89e170c313d415e0584ef82b79e3bf9bdebeeef53d13aefdc0cfa64f616acea0229e6ee0f0456c0fa32558d6edc0916baa26b48e745de834571534ca253ea82435f08ebbc7c";
        let inputs = ExecutionStack::from_hex(hex).unwrap();
        let script =
            TariScript::from_hex("71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e581ac276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708")
                .unwrap();
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(1));

        // Try again with invalid sig
        let inputs = ExecutionStack::from_hex("0500b7c695528c858cde76dab3076908e01228b6dbdd5f671bed1b03\
        b89e170c314c7b413e971dbb85879ba990e851607454da4bdf65839456d7cac19e5a338f060456c0fa32558d6edc0916baa26b48e745de8\
        34571534ca253ea82435f08ebbc7c").unwrap();
        let result = script.execute(&inputs).unwrap();
        assert_eq!(result, Number(0));
    }

    #[test]
    fn disassemble() {
        let hex_script = "71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e58170ac276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708";
        let script = TariScript::from_hex(hex_script).unwrap();
        let ops = vec![
            "Dup",
            "HashBlake256",
            "PushHash(ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5)",
            "EqualVerify",
            "Drop",
            "CheckSig(276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708)",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        assert_eq!(script.to_opcodes(), ops);
        assert_eq!(
            script.to_string(),
            "Dup HashBlake256 PushHash(ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5) EqualVerify \
             Drop CheckSig(276657a418820f34036b20ea615302b373c70ac8feab8d30681a3e0f0960e708)"
        );
    }

    #[test]
    fn time_locked_contract_example() {
        let k_alice =
            RistrettoSecretKey::from_hex("f305e64c0e73cbdb665165ac97b69e5df37b2cd81f9f8f569c3bd854daff290e").unwrap();
        let p_alice = RistrettoPublicKey::from_secret_key(&k_alice); // 9c35e9f0f11cf25ce3ca1182d37682ab5824aa033f2024651e007364d06ec355

        let k_bob =
            RistrettoSecretKey::from_hex("e0689386a018e88993a7bb14cbff5bad8a8858ea101d6e0da047df3ddf499c0e").unwrap();
        let p_bob = RistrettoPublicKey::from_secret_key(&k_bob); // 3a58f371e94da76a8902e81b4b55ddabb7dc006cd8ebde3011c46d0e02e9172f

        let lock_height = 4000u64;

        let script = script!(Dup PushPubKey(Box::new(p_bob.clone())) CheckHeight(lock_height) GeZero IfThen PushPubKey(Box::new(p_alice.clone())) OrVerify(2) Else EqualVerify EndIf );

        // Alice tries to spend the output before the height is reached
        let inputs_alice_spends_early = inputs!(p_alice.clone());
        let ctx = context_with_height(3990u64);
        assert_eq!(
            script.execute_with_context(&inputs_alice_spends_early, &ctx),
            Err(ScriptError::VerifyFailed)
        );

        // Alice tries to spend the output after the height is reached
        let inputs_alice_spends_early = inputs!(p_alice.clone());
        let ctx = context_with_height(4000u64);
        assert_eq!(
            script.execute_with_context(&inputs_alice_spends_early, &ctx).unwrap(),
            StackItem::PublicKey(p_alice)
        );

        // Bob spends before time lock is reached
        let inputs_bob_spends_early = inputs!(p_bob.clone());
        let ctx = context_with_height(3990u64);
        assert_eq!(
            script.execute_with_context(&inputs_bob_spends_early, &ctx).unwrap(),
            StackItem::PublicKey(p_bob.clone())
        );

        // Bob spends after time lock is reached
        let inputs_bob_spends_early = inputs!(p_bob.clone());
        let ctx = context_with_height(4001u64);
        assert_eq!(
            script.execute_with_context(&inputs_bob_spends_early, &ctx).unwrap(),
            StackItem::PublicKey(p_bob)
        );
    }
}
