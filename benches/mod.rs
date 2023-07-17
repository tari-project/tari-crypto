// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![allow(missing_docs)]

use criterion::criterion_main;

pub mod commitment;
pub mod signatures;

use commitment::commitment;
use signatures::signatures;

criterion_main!(commitment, signatures);
