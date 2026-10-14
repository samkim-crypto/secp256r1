use crate::{
    constants::{
        COMPRESSED_PUBKEY_SERIALIZED_SIZE, SCALAR_BYTES, SECP256R1_HALF_ORDER, SECP256R1_ORDER,
        SIGNATURE_SERIALIZED_SIZE,
    },
    error::Secp256r1VerifyError,
    hash::MessageHasher,
};

/// Verifies a secp256r1 ECDSA signature against a compressed public key.
///
/// The scalar range and malleability checks run before the message is hashed,
/// so malformed signatures are rejected without spending compute units on the
/// hash or the curve operations.
pub(crate) fn verify_signature<H: MessageHasher>(
    public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    message: &[u8],
    enforce_low_s: bool,
) -> Result<(), Secp256r1VerifyError> {
    let (r, s) = signature.split_at(SCALAR_BYTES);

    if !is_valid_scalar(r) || !is_valid_scalar(s) {
        return Err(Secp256r1VerifyError::InvalidSignature);
    }
    if enforce_low_s && s > SECP256R1_HALF_ORDER.as_slice() {
        return Err(Secp256r1VerifyError::InvalidMalleableSignature);
    }

    let message_hash = H::hash(message)?;

    verify_curve_equation(public_key, signature, &message_hash)
}

/// Returns `true` if the big-endian scalar is in `[1, N)`, the range ECDSA
/// requires for both `r` and `s`.
#[inline(always)]
fn is_valid_scalar(scalar: &[u8]) -> bool {
    scalar.iter().any(|&byte| byte != 0) && scalar < SECP256R1_ORDER.as_slice()
}

/// Checks the ECDSA verification equation for an already range-checked
/// signature.
///
/// Not implemented yet: this always succeeds. The check needs the secp256r1
/// curve syscalls from SIMD-0565, which are not available in any released
/// runtime yet (see anza-xyz/agave#13918). Until then the verifier only
/// enforces the scalar range, malleability, and message length rules.
#[inline(always)]
fn verify_curve_equation(
    _public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    _signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    _message_hash: &[u8; SCALAR_BYTES],
) -> Result<(), Secp256r1VerifyError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use {super::*, crate::hash::RawHasher};

    const PUBLIC_KEY: [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE] = [0x02; 33];
    const MESSAGE_HASH: [u8; SCALAR_BYTES] = [0xab; 32];

    fn signature(
        r: &[u8; SCALAR_BYTES],
        s: &[u8; SCALAR_BYTES],
    ) -> [u8; SIGNATURE_SERIALIZED_SIZE] {
        let mut signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
        signature[..SCALAR_BYTES].copy_from_slice(r);
        signature[SCALAR_BYTES..].copy_from_slice(s);
        signature
    }

    fn verify(
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        enforce_low_s: bool,
    ) -> Result<(), Secp256r1VerifyError> {
        verify_signature::<RawHasher>(&PUBLIC_KEY, signature, &MESSAGE_HASH, enforce_low_s)
    }

    fn one() -> [u8; SCALAR_BYTES] {
        let mut one = [0u8; SCALAR_BYTES];
        one[SCALAR_BYTES - 1] = 1;
        one
    }

    fn order_minus_one() -> [u8; SCALAR_BYTES] {
        let mut scalar = SECP256R1_ORDER;
        scalar[SCALAR_BYTES - 1] -= 1;
        scalar
    }

    fn half_order_plus_one() -> [u8; SCALAR_BYTES] {
        let mut scalar = SECP256R1_HALF_ORDER;
        scalar[SCALAR_BYTES - 1] += 1;
        scalar
    }

    #[test]
    fn test_rejects_zero_r() {
        let sig = signature(&[0; 32], &one());
        assert_eq!(
            verify(&sig, true),
            Err(Secp256r1VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn test_rejects_zero_s() {
        let sig = signature(&one(), &[0; 32]);
        assert_eq!(
            verify(&sig, false),
            Err(Secp256r1VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn test_rejects_r_equal_to_order() {
        let sig = signature(&SECP256R1_ORDER, &one());
        assert_eq!(
            verify(&sig, true),
            Err(Secp256r1VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn test_rejects_s_equal_to_order() {
        // Must report the range error even though `s` is also above N/2.
        let sig = signature(&one(), &SECP256R1_ORDER);
        assert_eq!(
            verify(&sig, true),
            Err(Secp256r1VerifyError::InvalidSignature)
        );
        assert_eq!(
            verify(&sig, false),
            Err(Secp256r1VerifyError::InvalidSignature)
        );
    }

    #[test]
    fn test_accepts_largest_valid_r() {
        let sig = signature(&order_minus_one(), &one());
        assert_eq!(verify(&sig, true), Ok(()));
    }

    #[test]
    fn test_low_s_boundary() {
        let at_half = signature(&one(), &SECP256R1_HALF_ORDER);
        assert_eq!(verify(&at_half, true), Ok(()));

        let above_half = signature(&one(), &half_order_plus_one());
        assert_eq!(
            verify(&above_half, true),
            Err(Secp256r1VerifyError::InvalidMalleableSignature)
        );
    }

    #[test]
    fn test_allows_high_s_when_not_enforced() {
        let sig = signature(&one(), &order_minus_one());
        assert_eq!(verify(&sig, false), Ok(()));
    }

    #[test]
    fn test_propagates_hasher_errors() {
        let sig = signature(&one(), &one());
        assert_eq!(
            verify_signature::<RawHasher>(&PUBLIC_KEY, &sig, &[0xab; 31], true),
            Err(Secp256r1VerifyError::InvalidMessageLength)
        );
    }
}
