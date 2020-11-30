// Copyright 2020. The Tari Project
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::{
    os::raw::{c_char, c_int},
    ptr,
    slice,
};

/// Looks up the error message associated with the given error code.
///
/// This function returns 0 on successful execution, or an error code on a failure.
#[no_mangle]
pub unsafe extern "C" fn lookup_error_message(code: c_int, buffer: *mut c_char, length: c_int) -> c_int {
    if buffer.is_null() {
        return NULL_POINTER;
    }

    let error_message = get_error_message(code).to_string();
    let buffer = slice::from_raw_parts_mut(buffer as *mut u8, length as usize);

    if error_message.len() >= buffer.len() {
        return BUFFER_TOO_SMALL;
    }

    ptr::copy_nonoverlapping(error_message.as_ptr(), buffer.as_mut_ptr(), error_message.len());

    // Add a trailing null so people using the string as a `char *` don't
    // accidentally read into garbage.
    buffer[error_message.len()] = 0;

    error_message.len() as c_int
}

pub const OK: i32 = 0;
pub const NULL_POINTER: i32 = -1;
pub const BUFFER_TOO_SMALL: i32 = -2;
pub const INVALID_SECRET_KEY_SER: i32 = -1000;
pub const SIGNING_ERROR: i32 = -1100;
pub const STR_CONV_ERR: i32 = -2000;

pub fn get_error_message(code: i32) -> &'static str {
    match code {
        OK => "The operation completed without errors.",
        NULL_POINTER => "A null pointer was passed as an input pointer",
        BUFFER_TOO_SMALL => "The provided buffer was too small",
        INVALID_SECRET_KEY_SER => "Invalid secret key representation.",
        SIGNING_ERROR => "Error creating signature",
        STR_CONV_ERR => "String conversion error",
        _ => "Unknown error code.",
    }
}
