/// Errors that can occur during secp256r1 signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secp256r1VerifyError {
    /// The signature's `r` or `s` is zero or not less than the group order.
    InvalidSignature,
    /// The signature has a high 's' value and the verifier enforces low-s signatures.
    InvalidMalleableSignature,
    /// The message provided to a strict `hasher` was not the correct length.
    InvalidMessageLength,
    /// The public key does not decode to a valid secp256r1 point.
    InvalidPublicKey,
    /// The public key, signature, and message all decoded successfully, but
    /// the signature does not satisfy the verification equation.
    SignatureMismatch,
}
