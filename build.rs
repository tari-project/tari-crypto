// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Custom build step to generate FFI header if needed
#[cfg(feature = "ffi")]
use std::{env, path::Path};

#[cfg(feature = "ffi")]
use cbindgen::Config;
fn main() {
    #[cfg(feature = "ffi")]
    {
        let needs_ffi = &env::var("CARGO_FEATURE_FFI").unwrap_or_default() == "1";
        if needs_ffi {
            generate_ffi_header();
        }
    }
}
#[cfg(feature = "ffi")]
fn generate_ffi_header() {
    let crate_env = env::var("CARGO_MANIFEST_DIR").unwrap();
    let crate_path = Path::new(&crate_env);
    let config = Config::from_root_or_default(crate_path);
    cbindgen::Builder::new()
        .with_crate(crate_path.to_str().unwrap())
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("libtari/tari_crypto.h");
}
