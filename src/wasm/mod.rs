// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! WASM bindings and functions

use std::string::String;

use wasm_bindgen::prelude::*;

const VERSION: &str = env!("CARGO_PKG_VERSION");

mod keyring;

pub mod commitments;
pub mod key_utils;
pub mod range_proofs;
pub use keyring::KeyRing;

/// The version of this library
#[wasm_bindgen]
pub fn version() -> String {
    VERSION.into()
}
