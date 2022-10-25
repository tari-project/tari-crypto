// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::time::Duration;

use criterion::{criterion_group, Criterion};
use rand::thread_rng;
use tari_crypto::{
    commitment::HomomorphicCommitmentFactory,
    keys::SecretKey,
    ristretto::{pedersen::commitment_factory::PedersenCommitmentFactory, RistrettoSecretKey},
};

pub fn commit_default(c: &mut Criterion) {
    let factory = PedersenCommitmentFactory::default();
    let mut rng = thread_rng();

    c.bench_function("commit_default key pair", |b| {
        // Commitment value and mask
        let v = RistrettoSecretKey::random(&mut rng);
        let m = RistrettoSecretKey::random(&mut rng);
        b.iter(|| factory.commit(&m, &v));
    });
}

criterion_group!(
name = commitment;
config = Criterion::default().warm_up_time(Duration::from_millis(500));
targets = commit_default
);
