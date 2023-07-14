// Copyright 2019. The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! Errors used in the Tari Crypto crate

use alloc::string::String;

use snafu::prelude::*;
/// Errors encountered when creating of verifying range proofs
#[derive(Debug, Clone, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RangeProofError {
    /// Cold not construct a range proof
    #[snafu(display("Could not construct range proof: `{reason}'"))]
    ProofConstructionError {
        /// The reason for the error
        reason: String,
    },
    /// The deserialization of the range proof failed
    #[snafu(display("The deserialization of the range proof failed"))]
    InvalidProof {},
    /// Invalid input was provided to the RangeProofService constructor
    #[snafu(display("Invalid input was provided to the RangeProofService constructor: `{reason}'"))]
    InitializationError {
        /// The reason for the error
        reason: String,
    },
    /// Invalid range proof provided
    #[snafu(display("Invalid range proof provided: `{reason}"))]
    InvalidRangeProof {
        /// The reason for the error
        reason: String,
    },
    /// Invalid range proof rewind, the rewind keys provided must be invalid
    #[snafu(display("Invalid range proof rewind, the rewind keys provided must be invalid: `{reason}'"))]
    InvalidRewind {
        /// The reason for the error
        reason: String,
    },
    /// Inconsistent extension degree
    #[snafu(display("Inconsistent extension degree: `{reason}'"))]
    RPExtensionDegree {
        /// The reason for the error
        reason: String,
    },
}

/// Errors encountered when committing values
#[derive(Debug, Clone, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CommitmentError {
    /// Inconsistent extension degree
    #[snafu(display("Inconsistent extension degree: `{reason}'"))]
    CommitmentExtensionDegree {
        /// The reason for the error
        reason: String,
    },
}

/// Errors encountered when hashing
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum HashingError {
    /// The input to the hashing function is too short
    #[snafu(display("The input to the hashing function is too short."))]
    InputTooShort {},
    /// Converting a byte string into a secret key failed
    #[snafu(display("Converting a byte string into a secret key failed.  `{reason}'"))]
    ConversionFromBytes {
        /// The reason for the error
        reason: String,
    },
    /// The digest does not produce enough output
    #[snafu(display("The digest does produce enough output.`{bytes}' bytes are required."))]
    DigestTooShort {
        /// The number of bytes required
        bytes: usize,
    },
}

/// Errors encountered when copying to a buffer
#[derive(Debug, Clone, Snafu, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SliceError {
    /// The requested fixed slice length exceeds the available slice length
    #[snafu(display("Cannot create fixed slice of length '{target}' from a slice of length '{provided}'"))]
    CopyFromSlice {
        /// The requested fixed slice length
        target: usize,
        /// The available slice length
        provided: usize,
    },
}
