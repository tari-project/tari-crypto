// Copyright 2020. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use std::{
    convert::TryFrom,
    os::raw::{c_char, c_int},
    ptr,
    slice,
};

/// Looks up the error message associated with the given error code.
///
/// This function returns 0 on successful execution, or an error code on a failure.
///
/// # Safety
/// Returns -1 if `buffer` is null.
/// The *caller* must manage memory, this function will return an error if the memory allocated in `buffer` is too small
/// for the error message.
#[no_mangle]
pub unsafe extern "C" fn lookup_error_message(code: c_int, buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        return NULL_POINTER;
    }

    let error_message = get_error_message(code);
    let length = match usize::try_from(length) {
        Ok(l) => l,
        Err(_) => return INTEGER_OVERFLOW,
    };
    let buffer = slice::from_raw_parts_mut(buffer as *mut u8, length);

    if error_message.len() >= buffer.len() {
        return BUFFER_TOO_SMALL;
    }

    ptr::copy_nonoverlapping(error_message.as_ptr(), buffer.as_mut_ptr(), error_message.len());

    // Add a trailing null so people using the string as a `char *` don't
    // accidentally read into garbage.
    buffer[error_message.len()] = 0;

    // Explicitly truncate usize to c_int (not possible anyway) because adding #[allow(clippy::cast-possible-wrap)]
    // attribute requires unstable rust feature
    c_int::try_from(error_message.len()).unwrap_or(c_int::MAX)
}

pub const OK: i32 = 0;
pub const NULL_POINTER: i32 = -1;
pub const BUFFER_TOO_SMALL: i32 = -2;
pub const INVALID_SECRET_KEY_SER: i32 = -1000;
pub const SIGNING_ERROR: i32 = -1100;
pub const STR_CONV_ERR: i32 = -2000;
pub const INTEGER_OVERFLOW: i32 = -3000;

pub fn get_error_message(code: i32) -> &'static str {
    match code {
        OK => "The operation completed without errors.",
        NULL_POINTER => "A null pointer was passed as an input pointer",
        BUFFER_TOO_SMALL => "The provided buffer was too small",
        INVALID_SECRET_KEY_SER => "Invalid secret key representation.",
        SIGNING_ERROR => "Error creating signature",
        STR_CONV_ERR => "String conversion error",
        INTEGER_OVERFLOW => "Integer overflowed",
        _ => "Unknown error code.",
    }
}

#[cfg(test)]
mod test {
    use std::{ptr::null_mut, string::String};

    use super::*;

    #[test]
    pub fn test_lookup_error_message_invalid_params() {
        unsafe {
            assert_eq!(lookup_error_message(OK, null_mut(), 0), NULL_POINTER);
        }
        unsafe {
            let mut buffer = [0i8; 1];
            assert_eq!(lookup_error_message(OK, buffer.as_mut_ptr(), 1), BUFFER_TOO_SMALL);
        }
    }

    #[test]
    pub fn test_lookup_error_message_valid_params() {
        unsafe {
            let mut buffer = [0u8; 1000];
            assert_eq!(
                usize::try_from(lookup_error_message(OK, buffer.as_mut_ptr() as *mut i8, 1000)).unwrap(),
                get_error_message(OK).len()
            );
            assert_eq!(
                String::from_utf8_lossy(&buffer)[0..get_error_message(OK).len()],
                *get_error_message(OK)
            );
        }
    }

    #[test]
    pub fn test_get_error_message() {
        let unknown_error = get_error_message(12345); // Force unknown error
        assert_eq!(unknown_error, "Unknown error code.");
        assert_ne!(unknown_error, get_error_message(OK));
        assert_ne!(unknown_error, get_error_message(NULL_POINTER));
        assert_ne!(unknown_error, get_error_message(BUFFER_TOO_SMALL));
        assert_ne!(unknown_error, get_error_message(INVALID_SECRET_KEY_SER));
        assert_ne!(unknown_error, get_error_message(SIGNING_ERROR));
        assert_ne!(unknown_error, get_error_message(STR_CONV_ERR));
    }
}
