#![cfg_attr(not(debug_assertions), deny(unused_variables))]
#![cfg_attr(not(debug_assertions), deny(unused_imports))]
#![cfg_attr(not(debug_assertions), deny(dead_code))]
#![cfg_attr(not(debug_assertions), deny(unused_extern_crates))]
#![deny(unused_must_use)]
#![deny(unreachable_patterns)]
#![deny(unknown_lints)]

#[macro_use]
extern crate lazy_static;

#[macro_use]
pub mod macros;
pub mod commitment;
pub mod hash;
pub mod keys;
#[cfg(feature = "musig")]
pub mod musig;
pub mod range_proof;
pub mod ristretto;
pub mod signatures;

#[cfg(feature = "wasm")]
pub mod wasm;

#[cfg(feature = "ffi")]
pub mod ffi;

// Re-export tari_utils
pub use hash::blake2 as common;
pub use tari_utilities;
