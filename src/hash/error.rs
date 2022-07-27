// Copyright 2022. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Error types for hash funcions

use thiserror::Error;

/// Hash error type
#[derive(Debug, Error)]
pub enum HashError {
    /// Length of input data exceeded a limit
    #[error("wrong length")]
    WrongLength,
}
