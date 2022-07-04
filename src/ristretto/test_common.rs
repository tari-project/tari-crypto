// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use crate::{
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

pub(crate) fn get_keypair() -> (RistrettoSecretKey, RistrettoPublicKey) {
    let mut rng = rand::thread_rng();
    let k = RistrettoSecretKey::random(&mut rng);
    let pk = RistrettoPublicKey::from_secret_key(&k);
    (k, pk)
}
