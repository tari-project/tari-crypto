// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::time::Duration;

use criterion::{criterion_group, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use tari_crypto::{
    commitment::HomomorphicCommitmentFactory,
    keys::SecretKey,
    range_proof::RangeProofService,
    ristretto::{
        pedersen::{commitment_factory::PedersenCommitmentFactory, PedersenCommitment},
        DalekRangeProofService,
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
        let parameter_str = format!("{input} bytes");
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
