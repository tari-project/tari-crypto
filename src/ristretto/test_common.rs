// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
use crate::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

#[cfg(test)]
pub(crate) fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    let mut rng = ChaCha12Rng::seed_from_u64(12345);
    let k = RistrettoSecretKey::random(&mut rng);
    let pk = RistrettoPublicKey::from_secret_key(&k);
    (k, pk)
}
