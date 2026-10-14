use crate::{constants::SCALAR_BYTES, error::Secp256r1VerifyError};

/// Defines the hashing algorithm applied to the message before verification.
pub trait MessageHasher {
    /// Hashes a dynamic message down to a 32-byte scalar.
    fn hash(message: &[u8]) -> Result<[u8; SCALAR_BYTES], Secp256r1VerifyError>;
}

/// Applies the `SHA256` algorithm to the message (standard secp256r1 ECDSA
/// behavior).
pub struct Sha256Hasher;

impl MessageHasher for Sha256Hasher {
    #[inline(always)]
    fn hash(message: &[u8]) -> Result<[u8; SCALAR_BYTES], Secp256r1VerifyError> {
        Ok(solana_sha256_hasher::hash(message).to_bytes())
    }
}

/// A strict pass-through `hasher` for messages that have already been hashed to
/// exactly 32 bytes.
pub struct RawHasher;

impl MessageHasher for RawHasher {
    #[inline(always)]
    fn hash(message: &[u8]) -> Result<[u8; SCALAR_BYTES], Secp256r1VerifyError> {
        message
            .try_into()
            .map_err(|_| Secp256r1VerifyError::InvalidMessageLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_hasher_success() {
        let message = [0xab; 32];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Ok(message));
    }

    #[test]
    fn test_raw_hasher_rejects_truncated_input() {
        let message = [0xab; 31];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256r1VerifyError::InvalidMessageLength));
    }

    #[test]
    fn test_raw_hasher_rejects_extended_input() {
        // 33 bytes, which must not be silently truncated.
        let message = [0xab; 33];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256r1VerifyError::InvalidMessageLength));
    }

    #[test]
    fn test_raw_hasher_rejects_empty_input() {
        let message = [];
        let result = RawHasher::hash(&message);
        assert_eq!(result, Err(Secp256r1VerifyError::InvalidMessageLength));
    }

    #[test]
    fn test_sha256_hasher() {
        let hash = Sha256Hasher::hash(b"hello world").unwrap();

        // Standard SHA256 hash of "hello world"
        let expected = [
            0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d,
            0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee, 0x90, 0x88, 0xf7, 0xac,
            0xe2, 0xef, 0xcd, 0xe9,
        ];

        assert_eq!(hash, expected);
    }
}
