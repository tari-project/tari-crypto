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
    common::Blake256,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
    script::{error::ScriptError, op_codes::Opcode, ExecutionStack, ScriptContext, StackItem},
};
use blake2::Digest;
use std::fmt;
use tari_utilities::{
    hex::{from_hex, to_hex, Hex, HexError},
    ByteArray,
};

#[macro_export]
macro_rules! script {
    ($($opcode:ident$(($var:expr))?) +) => {{
        use crate::script::TariScript;
        use crate::script::Opcode;
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

    /// Executes the script using a default context
    pub fn execute(&self, inputs: &ExecutionStack) -> Result<(), ScriptError> {
        self.execute_with_context(inputs, &ScriptContext::default())
    }

    /// Execute the script with the given inputs and the provided context
    pub fn execute_with_context(&self, inputs: &ExecutionStack, context: &ScriptContext) -> Result<(), ScriptError> {
        // Copy all inputs onto the stack
        let mut stack = inputs.clone();
        for opcode in self.script.iter() {
            self.execute_opcode(opcode, &mut stack, context)?
        }
        TariScript::stack_is_zero(&stack)
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.script.iter().fold(Vec::with_capacity(512), |mut bytes, op| {
            op.to_bytes(&mut bytes);
            bytes
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScriptError> {
        let mut script = Vec::with_capacity(512);
        let mut byte_str = bytes;
        while !byte_str.is_empty() {
            match Opcode::read_next(byte_str) {
                Some((code, b)) => {
                    script.push(code);
                    byte_str = b;
                },
                None => return Err(ScriptError::InvalidOpcode),
            }
        }
        Ok(TariScript { script })
    }

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

    fn execute_opcode(
        &self,
        opcode: &Opcode,
        stack: &mut ExecutionStack,
        ctx: &ScriptContext,
    ) -> Result<(), ScriptError>
    {
        use StackItem::*;
        match opcode {
            Opcode::Return => Err(ScriptError::Return),
            Opcode::PushHeight => TariScript::handle_push_height(stack, ctx),
            Opcode::Add => TariScript::handle_op_add(stack),
            Opcode::Sub => TariScript::handle_op_sub(stack),
            Opcode::Dup => TariScript::handle_dup(stack),
            Opcode::Drop => TariScript::handle_drop(stack),
            Opcode::Equal => match TariScript::handle_equal(stack)? {
                true => stack.push(Number(0)),
                false => stack.push(Number(1)),
            },
            Opcode::EqualVerify => match TariScript::handle_equal(stack)? {
                true => stack.push(Number(0)),
                false => Err(ScriptError::VerifyFailed),
            },
            Opcode::CheckSig => match self.check_sig(stack)? {
                true => stack.push(Number(0)),
                false => stack.push(Number(1)),
            },
            Opcode::CheckSigVerify => match self.check_sig(stack)? {
                true => stack.push(Number(0)),
                false => Err(ScriptError::InvalidSignature),
            },
            Opcode::RevRot => stack.push_down(2),
            Opcode::PushHash(h) => stack.push(Hash(*h.clone())),
            Opcode::HashBlake256 => TariScript::handle_hash::<Blake256>(stack),
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

    fn handle_push_height(stack: &mut ExecutionStack, ctx: &ScriptContext) -> Result<(), ScriptError> {
        stack.push(StackItem::Number(ctx.block_height() as i64))
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

    fn check_sig(&self, stack: &mut ExecutionStack) -> Result<bool, ScriptError> {
        use StackItem::*;
        let pk = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        let sig = stack.pop().ok_or(ScriptError::StackUnderflow)?;
        match (pk, sig) {
            (PublicKey(p), Signature(s)) => {
                let m = self.script_message(&p)?;
                Ok(s.verify(&p, &m))
            },
            (..) => Err(ScriptError::IncompatibleTypes),
        }
    }

    fn stack_is_zero(stack: &ExecutionStack) -> Result<(), ScriptError> {
        if stack.size() != 1 {
            return Err(ScriptError::NonUnitLengthStack);
        }
        use StackItem::*;
        match stack.peek().unwrap() {
            Number(0) => Ok(()),
            Number(v) => Err(ScriptError::NonZeroValue(*v)),
            Commitment(c) if c.as_public_key() == &RistrettoPublicKey::default() => Ok(()),
            Commitment(c) => Err(ScriptError::NonZeroCommitment(c.clone())),
            _ => Err(ScriptError::IncorrectFinalState),
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

impl fmt::Display for TariScript {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = self.to_opcodes().join(" ");
        f.write_str(&s)
    }
}

#[derive(Default)]
pub struct Builder {}

impl Builder {
    pub fn new() -> Self {
        Builder {}
    }
}

#[cfg(test)]
mod test {
    use crate::{
        common::Blake256,
        inputs,
        keys::{PublicKey, SecretKey},
        ristretto::{pedersen::PedersenCommitment, RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
        script::{error::ScriptError, op_codes::to_hash, ExecutionStack, TariScript},
    };
    use blake2::Digest;
    use tari_utilities::{hex::Hex, ByteArray};

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
        assert_eq!(script.execute(&inputs), Err(ScriptError::NonZeroValue(5)));
        let inputs = inputs!(3, -3);
        assert!(script.execute(&inputs).is_ok());
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
        assert_eq!(script.execute(&inputs), Err(ScriptError::NonZeroCommitment(c3)));
    }

    #[test]
    fn op_sub() {
        let script = script!(Add Sub);
        let inputs = inputs!(5, 3, 2);
        assert!(script.execute(&inputs).is_ok());
        let inputs = inputs!(i64::MAX, 1);
        assert_eq!(script.execute(&inputs), Err(ScriptError::ValueExceedsBounds));
        let script = script!(Sub);
        let inputs = inputs!(5, 3);
        assert_eq!(script.execute(&inputs), Err(ScriptError::NonZeroValue(2)));
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
        let mut rng = rand::thread_rng();
        let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let r = RistrettoSecretKey::random(&mut rng);
        let script = script!(CheckSig);
        let m = script.script_message(&p).unwrap();
        let s = RistrettoSchnorr::sign(k.clone(), r.clone(), m.as_bytes()).unwrap();
        let inputs = inputs!(s, p);
        assert!(script.execute(&inputs).is_ok());
    }

    #[test]
    fn check_sig_verify() {
        let mut rng = rand::thread_rng();
        let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
        let r = RistrettoSecretKey::random(&mut rng);
        let script = script!(CheckSigVerify);
        let m = script.script_message(&p).unwrap();
        let s = RistrettoSchnorr::sign(k.clone(), r.clone(), m.as_bytes()).unwrap();
        let inputs = inputs!(s, p);
        assert!(script.execute(&inputs).is_ok());
    }

    #[test]
    fn add_partial_signatures() {
        let mut rng = rand::thread_rng();
        let (k1, p1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, p2) = RistrettoPublicKey::random_keypair(&mut rng);
        let r1 = RistrettoSecretKey::random(&mut rng);
        let r2 = RistrettoSecretKey::random(&mut rng);
        let script = script!(Add RevRot Add CheckSigVerify);
        let m = script.script_message(&(&p1 + &p2)).unwrap();
        let s1 = RistrettoSchnorr::sign(k1.clone(), r1.clone(), m.as_bytes()).unwrap();
        let s2 = RistrettoSchnorr::sign(k2.clone(), r2.clone(), m.as_bytes()).unwrap();
        let inputs = inputs!(p1, p2, s1, s2);
        assert_eq!(script.execute(&inputs), Ok(()));
    }

    #[test]
    fn pay_to_public_key_hash() {
        let k =
            RistrettoSecretKey::from_hex("7212ac93ee205cdbbb57c4f0f815fbf8db25b4d04d3532e2262e31907d82c700").unwrap();
        let p = RistrettoPublicKey::from_secret_key(&k); // 56c0fa32558d6edc0916baa26b48e745de834571534ca253ea82435f08ebbc7c
        let r =
            RistrettoSecretKey::from_hex("193ee873f3de511eda8ae387db6498f3d194d31a130a94cdf13dc5890ec1ad0f").unwrap();
        let hash = Blake256::digest(p.as_bytes());
        let pkh = to_hash(hash.as_slice()); // ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5
        let script = script!(Dup HashBlake256 PushHash(pkh) EqualVerify Drop CheckSig);
        let hex_script = "71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e58170ac";
        // Test serialisation
        assert_eq!(script.to_hex(), hex_script);
        // Test de-serialisation
        assert_eq!(TariScript::from_hex(hex_script).unwrap(), script);
        let m = script.script_message(&p).unwrap();
        let sig = RistrettoSchnorr::sign(k, r, m.as_bytes()).unwrap();
        // The top of the stack is the right-most element!
        let inputs = inputs!(sig, p);
        assert_eq!(script.execute(&inputs), Ok(()));
    }

    #[test]
    fn hex_only() {
        let inp = ExecutionStack::from_hex("0500f7c695528c858cde76dab3076908e01228b6dbdd5f671bed1b03\
        b89e170c314c7b413e971dbb85879ba990e851607454da4bdf65839456d7cac19e5a338f060456c0fa32558d6edc0916baa26b48e745de8\
        34571534ca253ea82435f08ebbc7c").unwrap();
        let script =
            TariScript::from_hex("71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e58170ac")
                .unwrap();
        assert_eq!(script.execute(&inp), Ok(()));
        // Try again with invalid sig
        let inp = ExecutionStack::from_hex("0500b7c695528c858cde76dab3076908e01228b6dbdd5f671bed1b03\
        b89e170c314c7b413e971dbb85879ba990e851607454da4bdf65839456d7cac19e5a338f060456c0fa32558d6edc0916baa26b48e745de8\
        34571534ca253ea82435f08ebbc7c").unwrap();
        assert_eq!(script.execute(&inp), Err(ScriptError::NonZeroValue(1)));
    }

    #[test]
    fn disassemble() {
        let hex_script = "71b07aae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e58170ac";
        let script = TariScript::from_hex(hex_script).unwrap();
        let ops = vec![
            "Dup",
            "HashBlake256",
            "PushHash(ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5)",
            "EqualVerify",
            "Drop",
            "CheckSig",
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<String>>();
        assert_eq!(script.to_opcodes(), ops);
        assert_eq!(
            script.to_string(),
            "Dup HashBlake256 PushHash(ae2337ce44f9ebb6169c863ec168046cb35ab4ef7aa9ed4f5f1f669bb74b09e5) EqualVerify \
             Drop CheckSig"
        );
    }
}
