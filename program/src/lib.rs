#![no_std]

//! Pinocchio SBF wrapper for [`solana_secp256r1_verify`].

use {
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, ProgramResult,
    },
    solana_secp256r1_verify::{
        constants::{COMPRESSED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
        Secp256r1Verifier,
    },
};

const PUBKEY_OFFSET: usize = 0;
const SIGNATURE_OFFSET: usize = PUBKEY_OFFSET + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();

lazy_program_entrypoint!(process_instruction);

/// Program entry point.
///
/// Expects no accounts and instruction data encoded as
/// `public_key || signature || message`, where `public_key` is a 33-byte
/// compressed point and `signature` is `r || s`. The message is hashed with
/// SHA-256 and high-s signatures are rejected ([`Secp256r1Verifier::default`]),
/// matching the native secp256r1 precompile. Any [`Secp256r1VerifyError`]
/// surfaces on-chain as `ProgramError::InvalidInstructionData`; callers that
/// need to distinguish failure reasons, or a different configuration, should
/// depend on `solana-secp256r1-verify` directly.
///
/// [`Secp256r1VerifyError`]: solana_secp256r1_verify::Secp256r1VerifyError
pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    if context.remaining() > 0 {
        return Err(ProgramError::InvalidArgument);
    }

    let instruction_data = context.instruction_data()?;
    if instruction_data.len() < MESSAGE_OFFSET {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Both ranges are fixed-size and in bounds after the length check above,
    // so the conversions to fixed-size arrays cannot fail.
    let public_key = instruction_data[PUBKEY_OFFSET..SIGNATURE_OFFSET]
        .try_into()
        .unwrap();
    let signature = instruction_data[SIGNATURE_OFFSET..MESSAGE_OFFSET]
        .try_into()
        .unwrap();
    let message = &instruction_data[MESSAGE_OFFSET..];

    Secp256r1Verifier::default()
        .verify_signature(public_key, signature, message)
        .map_err(|_| ProgramError::InvalidInstructionData)
}
