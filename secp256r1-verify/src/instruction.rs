extern crate alloc;

use {
    alloc::{vec, vec::Vec},
    solana_address::{declare_id, Address},
    solana_instruction::Instruction,
};

declare_id!("SeRHg6wwUdgmWBuiAS4NHzzEpskiprRTv4hWFURQD7h");

/// Constructs an on-chain instruction to invoke `solana-secp256r1-program`.
///
/// The instruction data is `public_key || signature || message`, where
/// `public_key` is a 33-byte compressed point and `signature` is `r || s`.
pub fn verify(
    program_id: &Address,
    public_key: &[u8; 33],
    signature: &[u8; 64],
    message: &[u8],
) -> Instruction {
    // 33 (public key) + 64 (signature) = 97 bytes ahead of the message.
    let mut data = Vec::with_capacity(97 + message.len());
    data.extend_from_slice(public_key);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(*program_id, &data, vec![])
}
