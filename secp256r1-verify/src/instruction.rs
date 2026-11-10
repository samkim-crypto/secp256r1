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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_lays_out_public_key_signature_and_message() {
        const SIGNATURE_START: usize = 33;
        const MESSAGE_START: usize = 97;

        let program_id = Address::new_from_array([7; 32]);
        let public_key = [0x02; 33];
        let signature = [0xab; 64];
        let message = b"hello secp256r1";

        let instruction = verify(&program_id, &public_key, &signature, message);

        assert_eq!(instruction.program_id, program_id);
        assert!(instruction.accounts.is_empty());
        assert_eq!(&instruction.data[..SIGNATURE_START], &public_key);
        assert_eq!(
            &instruction.data[SIGNATURE_START..MESSAGE_START],
            &signature
        );
        assert_eq!(&instruction.data[MESSAGE_START..], message);
    }
}
