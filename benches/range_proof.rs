// Copyright 2019. The Tari Project
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

use std::time::Duration;

use criterion::{criterion_group, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use tari_crypto::{
    commitment::HomomorphicCommitmentFactory,
    keys::SecretKey,
    range_proof::RangeProofService,
    ristretto::{
        dalek_range_proof::DalekRangeProofService,
        pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
        RistrettoSecretKey,
    },
};

fn setup(n: usize) -> (DalekRangeProofService, RistrettoSecretKey, u64, PedersenCommitment) {
    let mut rng = thread_rng();
    let base = PedersenCommitmentFactory::default();
    let prover = DalekRangeProofService::new(n, &base).unwrap();
    let k = RistrettoSecretKey::random(&mut rng);
    let n_max = 1u64 << (n as u64 - 1);
    let v = rng.gen_range(1..n_max);
    let c = base.commit_value(&k, v);
    (prover, k, v, c)
}

pub fn generate_rangeproof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Generate and validate range proofs");
    for input in &[8, 16, 32, 64] {
        let parameter_str = format!("{} bytes", input);
        // let proof = prover.construct_proof(&k, v).unwrap();
        group.bench_with_input(BenchmarkId::new("construct_proof", &parameter_str), input, |b, n| {
            let (prover, k, v, _) = setup(*n);
            b.iter(move || prover.construct_proof(&k, v).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("validate_proof", &parameter_str), input, |b, n| {
            let (verifier, k, v, c) = setup(*n);
            let proof = verifier.construct_proof(&k, v).unwrap();
            b.iter(move || assert!(verifier.verify(&proof, &c)));
        });
    }
    group.finish();
}

criterion_group!(
name = range_proofs;
config = Criterion::default().warm_up_time(Duration::from_millis(1_500));
targets = generate_rangeproof
);
