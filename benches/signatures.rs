// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::time::Duration;

use criterion::{criterion_group, BatchSize, Criterion};
use rand::{thread_rng, RngCore};
use tari_crypto::{
    hash_domain,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
};

hash_domain!(BenchDomain, "com.example.bench");

fn generate_secret_key(c: &mut Criterion) {
    c.bench_function("Generate secret key", |b| {
        let mut rng = thread_rng();
        b.iter(|| {
            let _key = RistrettoSecretKey::random(&mut rng);
        });
    });
}

fn native_keypair(c: &mut Criterion) {
    c.bench_function("Generate key pair", |b| {
        let mut rng = thread_rng();
        b.iter(|| RistrettoPublicKey::random_keypair(&mut rng));
    });
}

struct SigningData {
    k: RistrettoSecretKey,
    p: RistrettoPublicKey,
    m: [u8; 32],
}

fn gen_keypair() -> SigningData {
    let mut rng = thread_rng();
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    let (k, p) = RistrettoPublicKey::random_keypair(&mut rng);
    SigningData { k, p, m }
}

fn sign_message(c: &mut Criterion) {
    c.bench_function("Create RistrettoSchnorr", move |b| {
        b.iter_batched(
            gen_keypair,
            |d| {
                let _sig: RistrettoSchnorr<BenchDomain> = RistrettoSchnorr::sign_message(&d.k, d.m).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    //    assert!(sig.verify(&p, &msg_key));
}

fn verify_message(c: &mut Criterion) {
    c.bench_function("Verify RistrettoSchnorr", move |b| {
        b.iter_batched(
            || {
                let d = gen_keypair();
                let s: RistrettoSchnorr<BenchDomain> = RistrettoSchnorr::sign_message(&d.k, d.m).unwrap();
                (d, s)
            },
            |(d, s)| assert!(s.verify_message(&d.p, d.m)),
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
name = signatures;
config = Criterion::default().warm_up_time(Duration::from_millis(500));
targets = generate_secret_key, native_keypair, sign_message, verify_message
);
