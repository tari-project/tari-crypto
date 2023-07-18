// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Errors used in the Tari Crypto crate

use serde::{Deserialize, Serialize};
use tari_utilities::ByteArrayError;
use thiserror::Error;

/// Errors encountered when creating of verifying range proofs
#[derive(Debug, Clone, Error, PartialEq, Eq, Deserialize, Serialize)]
pub enum RangeProofError {
    /// Cold not construct a range proof
    #[error("Could not construct range proof: `{0}`")]
    ProofConstructionError(String),
    /// The deserialization of the range proof failed
    #[error("The deserialization of the range proof failed")]
    InvalidProof,
    /// Invalid input was provided to the RangeProofService constructor
    #[error("Invalid input was provided to the RangeProofService constructor: `{0}`")]
    InitializationError(String),
    /// Invalid range proof provided
    #[error("Invalid range proof provided: `{0}`")]
    InvalidRangeProof(String),
    /// Invalid range proof rewind, the rewind keys provided must be invalid
    #[error("Invalid range proof rewind, the rewind keys provided must be invalid")]
    InvalidRewind(String),
    /// Inconsistent extension degree
    #[error("Inconsistent extension degree: `{0}`")]
    ExtensionDegree(String),
}

/// Errors encountered when committing values
#[derive(Debug, Clone, Error, PartialEq, Eq, Deserialize, Serialize)]
pub enum CommitmentError {
    /// Inconsistent extension degree
    #[error("Inconsistent extension degree: `{0}`")]
    ExtensionDegree(String),
}

/// Errors encountered when hashing
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashingError {
    /// The input to the hashing function is too short
    #[error("The input to the hashing function is too short.")]
    InputTooShort,
    /// Converting a byte string into a secret key failed
    #[error("Converting a byte string into a secret key failed: {0}")]
    ConversionFromBytes(String),
    /// The digest does not produce enough output
    #[error("The digest does produce enough output. {0} bytes are required.")]
    DigestTooShort(usize),
}

impl From<ByteArrayError> for HashingError {
    fn from(byte_error: ByteArrayError) -> Self {
        HashingError::ConversionFromBytes(byte_error.to_string())
    }
}

/// Errors encountered when copying to a buffer
#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum SliceError {
    /// The requested fixed slice length exceeds the available slice length
    #[error("Cannot create fixed slice of length {0} from a slice of length {1}.")]
    CopyFromSlice(usize, usize),
}
