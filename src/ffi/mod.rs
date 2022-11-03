// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! FFI interface for using this library in other langauges that support it

use std::os::raw::c_char;

mod error;
mod keys;

pub use error::lookup_error_message;
pub use keys::{
    commitment,
    random_keypair,
    sign,
    sign_comandpubsig,
    sign_comsig,
    verify,
    verify_comandpubsig,
    verify_comsig,
};

const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\u{00}");

/// The version of this library
#[no_mangle]
pub extern "C" fn version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod test {
    use std::ffi::CStr;

    use super::version;

    #[test]
    pub fn test_version() {
        unsafe {
            assert_eq!(env!("CARGO_PKG_VERSION"), CStr::from_ptr(version()).to_str().unwrap());
        }
    }
}
