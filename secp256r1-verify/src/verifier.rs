use {
    crate::{
        constants::{COMPRESSED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_SERIALIZED_SIZE},
        error::Secp256r1VerifyError,
        hash::{MessageHasher, Sha256Hasher},
        verify::verify_signature,
    },
    core::marker::PhantomData,
};

/// A stateless, zero-allocation configuration for secp256r1 verification.
///
/// # ECDSA Signature Malleability
/// In ECDSA, if a signature `(r, s)` is valid, the signature `(r, N - s)` is also
/// valid (where `N` is the order of the secp256r1 curve). This is known as signature
/// malleability.
///
/// The native secp256r1 precompile rejected signatures whose `s` value is in the
/// upper half of the curve order (`s > N/2`), and this verifier does the same by
/// default (`enforce_low_s = true`). Many signers, including most WebAuthn
/// authenticators, do not normalize `s`, so [`Secp256r1Verifier::allow_high_s`]
/// is available for protocols that are not affected by malleability.
#[derive(Debug, Clone, Copy)]
pub struct Secp256r1Verifier<H = Sha256Hasher> {
    enforce_low_s: bool,
    _phantom: PhantomData<H>,
}

impl Default for Secp256r1Verifier<Sha256Hasher> {
    fn default() -> Self {
        Self::new()
    }
}

// Constructor functions
impl<H> Secp256r1Verifier<H> {
    /// Initializes a new configuration with strict defaults.
    pub fn new() -> Self {
        Self {
            enforce_low_s: true,
            _phantom: PhantomData,
        }
    }

    /// Disables malleability checks entirely.
    ///
    /// Both low-s and high-s signatures will be accepted. Use this only if your
    /// protocol is inherently immune to transaction malleability attacks.
    pub fn allow_high_s(mut self) -> Self {
        self.enforce_low_s = false;
        self
    }
}

// Verification functions
impl<H: MessageHasher> Secp256r1Verifier<H> {
    /// Verifies a signature over `message` against a compressed public key.
    pub fn verify_signature(
        &self,
        public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        message: &[u8],
    ) -> Result<(), Secp256r1VerifyError> {
        verify_signature::<H>(public_key, signature, message, self.enforce_low_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_default_state() {
        // Defaults should match the native precompile (no malleability)
        let verifier = Secp256r1Verifier::default();
        assert!(verifier.enforce_low_s);
    }

    #[test]
    fn test_verifier_allow_high_s() {
        let verifier = Secp256r1Verifier::<Sha256Hasher>::new().allow_high_s();
        assert!(!verifier.enforce_low_s);
    }
}
