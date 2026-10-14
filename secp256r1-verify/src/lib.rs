#![no_std]

//! Stateless secp256r1 (NIST P-256) ECDSA verification utilities for Solana
//! programs.
//!
//! This crate contains the reusable verifier used by
//! `solana-secp256r1-program`. Programs can also depend on it directly to
//! verify secp256r1 signatures without invoking the standalone verifier
//! program.
//!
//! **Not ready for use.** The final elliptic-curve check is not implemented
//! yet, so [`Secp256r1Verifier`] currently accepts any signature that passes
//! the scalar range and malleability checks. It will be added once the
//! secp256r1 curve syscalls from SIMD-0565 are available.

#[cfg(feature = "instruction")]
pub mod instruction;

#[cfg(feature = "instruction")]
pub use instruction::{id, verify, ID};

#[cfg(feature = "verify")]
pub mod constants;
#[cfg(feature = "verify")]
mod error;
#[cfg(feature = "verify")]
mod hash;
#[cfg(feature = "verify")]
mod verifier;
#[cfg(feature = "verify")]
mod verify;

#[cfg(feature = "verify")]
pub use {
    error::Secp256r1VerifyError,
    hash::{MessageHasher, RawHasher, Sha256Hasher},
    verifier::Secp256r1Verifier,
};
