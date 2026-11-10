use {
    crate::{
        constants::{
            COMPRESSED_PUBKEY_SERIALIZED_SIZE, SCALAR_BYTES, SECP256R1_GENERATOR,
            SECP256R1_HALF_ORDER, SECP256R1_ORDER, SIGNATURE_SERIALIZED_SIZE,
            UNCOMPRESSED_POINT_SERIALIZED_SIZE,
        },
        error::Secp256r1VerifyError,
        hash::MessageHasher,
        points, scalar,
    },
    core::mem::MaybeUninit,
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
    // `signature` is exactly two scalars long, so both conversions succeed.
    let r: &[u8; SCALAR_BYTES] = signature[..SCALAR_BYTES].try_into().unwrap();
    let s: &[u8; SCALAR_BYTES] = signature[SCALAR_BYTES..].try_into().unwrap();

    // ECDSA requires both `r` and `s` to be in `[1, N)`.
    if is_zero(r) || r >= &SECP256R1_ORDER || is_zero(s) {
        return Err(Secp256r1VerifyError::InvalidSignature);
    }
    // Only an `s` above `N/2` can be out of range.
    if s > &SECP256R1_HALF_ORDER {
        if s >= &SECP256R1_ORDER {
            return Err(Secp256r1VerifyError::InvalidSignature);
        }
        if enforce_low_s {
            return Err(Secp256r1VerifyError::InvalidMalleableSignature);
        }
    }

    let mut scalars = [H::hash(message)?, *r];
    scalar::divide_by_s(&mut scalars, s);

    verify_curve_equation(public_key, &scalars, r)
}

#[inline(always)]
fn is_zero(scalar: &[u8; SCALAR_BYTES]) -> bool {
    scalar.iter().all(|&byte| byte == 0)
}

/// Checks the ECDSA verification equation for an already range-checked
/// signature, given `[z/s, r/s]`.
///
/// ECDSA accepts when `x(R) mod N == r` for `R = (z/s)·G + (r/s)·Q`. The
/// identity is encoded with an X-coordinate of zero, which can never match
/// because `r` is not zero.
#[inline(always)]
fn verify_curve_equation(
    public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    scalars: &[[u8; SCALAR_BYTES]; 2],
    r: &[u8; SCALAR_BYTES],
) -> Result<(), Secp256r1VerifyError> {
    let mut msm_points = [MaybeUninit::<[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]>::uninit(); 2];
    msm_points[0].write(SECP256R1_GENERATOR);
    if !points::decompress_into(public_key, &mut msm_points[1]) {
        return Err(Secp256r1VerifyError::InvalidPublicKey);
    }
    // SAFETY: Both elements are initialized above, and `MaybeUninit<T>` has the
    // same layout as `T`.
    let msm_points = unsafe {
        &*msm_points
            .as_ptr()
            .cast::<[[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]; 2]>()
    };

    let mut nonce_point = MaybeUninit::uninit();
    // This cannot fail: `G` is a constant, `Q` was just decompressed, and
    // `divide_by_s` returns reduced scalars.
    if !points::multiscalar_multiply_2_into(scalars, msm_points, &mut nonce_point) {
        return Err(Secp256r1VerifyError::SignatureMismatch);
    }
    // SAFETY: A successful multiscalar multiplication initializes `nonce_point`.
    let nonce_point = unsafe { nonce_point.assume_init_mut() };

    // The point is at least one scalar long, so the conversion succeeds.
    let x = nonce_point.first_chunk_mut::<SCALAR_BYTES>().unwrap();
    scalar::reduce_mod_order(x);

    if x == r {
        Ok(())
    } else {
        Err(Secp256r1VerifyError::SignatureMismatch)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            constants::{SECP256R1_FIELD_MODULUS, SECP256R1_FIELD_MODULUS_MINUS_ORDER},
            hash::{RawHasher, Sha256Hasher},
            scalar::small_scalar,
            verifier::Secp256r1Verifier,
        },
        p256::ecdsa::{
            signature::{hazmat::PrehashVerifier, Signer},
            Signature, SigningKey, VerifyingKey,
        },
        solana_secp256r1::{
            group::{AffinePoint, ProjectivePoint},
            scalar::Scalar,
            Endianness,
        },
    };

    const PUBLIC_KEY: [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE] = [0x02; 33];
    const MESSAGE_HASH: [u8; SCALAR_BYTES] = [0xab; 32];
    // The smallest positive integer that is an X-coordinate on the curve.
    const SMALL_NONCE_X: u8 = 5;

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

    fn verify_with_key(
        public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        hash: &[u8; SCALAR_BYTES],
        enforce_low_s: bool,
    ) -> Result<(), Secp256r1VerifyError> {
        verify_signature::<RawHasher>(public_key, signature, hash, enforce_low_s)
    }

    fn p256_accepts(
        public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        hash: &[u8; SCALAR_BYTES],
    ) -> bool {
        let key = VerifyingKey::from_sec1_bytes(public_key).unwrap();
        let signature = Signature::from_slice(signature).unwrap();
        key.verify_prehash(hash, &signature).is_ok()
    }

    fn assert_accepted(
        public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        hash: &[u8; SCALAR_BYTES],
    ) {
        assert!(p256_accepts(public_key, signature, hash));
        assert_eq!(verify_with_key(public_key, signature, hash, false), Ok(()));
    }

    fn assert_mismatch(
        public_key: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
        hash: &[u8; SCALAR_BYTES],
    ) {
        assert!(!p256_accepts(public_key, signature, hash));
        assert_eq!(
            verify_with_key(public_key, signature, hash, false),
            Err(Secp256r1VerifyError::SignatureMismatch)
        );
    }

    /// Solves `s·R = z·G + r·Q` for the public key `Q`, where `R` is a curve
    /// point with X-coordinate `nonce_x` and `r` is `nonce_x mod N`.
    ///
    /// This builds valid signatures with chosen `r` and `s`, which a signer
    /// cannot produce.
    fn public_key_for(
        nonce_x: &[u8; SCALAR_BYTES],
        s: &[u8; SCALAR_BYTES],
        hash: &[u8; SCALAR_BYTES],
    ) -> [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE] {
        let mut compressed = [0x02; COMPRESSED_PUBKEY_SERIALIZED_SIZE];
        compressed[1..].copy_from_slice(nonce_x);
        let nonce_point = AffinePoint::from_compressed(&compressed, Endianness::Big).unwrap();

        let r_inverse = Scalar::from_bytes_reduced(nonce_x, Endianness::Big)
            .invert()
            .unwrap();
        let generator_scalar = -(Scalar::from_bytes_reduced(hash, Endianness::Big) * r_inverse);
        let nonce_scalar = Scalar::from_bytes(s, Endianness::Big).unwrap() * r_inverse;

        ProjectivePoint::multi_scalar_mul_vartime(
            &[AffinePoint::generator(), nonce_point],
            &[generator_scalar.to_be_bytes(), nonce_scalar.to_be_bytes()],
        )
        .unwrap()
        .to_affine()
        .to_compressed(Endianness::Big)
        .unwrap()
    }

    fn generator_public_key() -> [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE] {
        AffinePoint::generator()
            .to_compressed(Endianness::Big)
            .unwrap()
    }

    fn compressed_key(signing_key: &SigningKey) -> [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE] {
        signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn one() -> [u8; SCALAR_BYTES] {
        small_scalar(1)
    }

    fn order_minus(delta: u8) -> [u8; SCALAR_BYTES] {
        let mut scalar = SECP256R1_ORDER;
        scalar[SCALAR_BYTES - 1] -= delta;
        scalar
    }

    fn order_plus(delta: u8) -> [u8; SCALAR_BYTES] {
        let mut scalar = SECP256R1_ORDER;
        scalar[SCALAR_BYTES - 1] += delta;
        scalar
    }

    /// A low-s signature over `message` and its high-s counterpart.
    fn low_and_high_s(
        signing_key: &SigningKey,
        message: &[u8],
    ) -> (
        [u8; SIGNATURE_SERIALIZED_SIZE],
        [u8; SIGNATURE_SERIALIZED_SIZE],
    ) {
        let signature: Signature = signing_key.sign(message);
        let low = signature.normalize_s();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -s).unwrap();
        (low.to_bytes().into(), high.to_bytes().into())
    }

    fn sample_signed_hash() -> (
        [u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
        [u8; SIGNATURE_SERIALIZED_SIZE],
    ) {
        let r = small_scalar(SMALL_NONCE_X);
        let s = small_scalar(9);
        (public_key_for(&r, &s, &MESSAGE_HASH), signature(&r, &s))
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
        // N - 2 is the largest scalar that is an X-coordinate on the curve.
        let r = order_minus(2);
        let s = one();
        let public_key = public_key_for(&r, &s, &MESSAGE_HASH);
        assert_accepted(&public_key, &signature(&r, &s), &MESSAGE_HASH);
    }

    #[test]
    fn test_largest_in_range_r_reaches_curve_check() {
        // N - 1 passes the range check, but it is not an X-coordinate on the
        // curve and adding N to it leaves the base field.
        let sig = signature(&order_minus(1), &one());
        assert_eq!(
            verify_with_key(&generator_public_key(), &sig, &MESSAGE_HASH, true),
            Err(Secp256r1VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn test_low_s_boundary() {
        let r = small_scalar(SMALL_NONCE_X);
        let at_half = signature(&r, &SECP256R1_HALF_ORDER);
        let public_key = public_key_for(&r, &SECP256R1_HALF_ORDER, &MESSAGE_HASH);
        assert_eq!(
            verify_with_key(&public_key, &at_half, &MESSAGE_HASH, true),
            Ok(())
        );

        let above_half = signature(&one(), &half_order_plus_one());
        assert_eq!(
            verify(&above_half, true),
            Err(Secp256r1VerifyError::InvalidMalleableSignature)
        );
    }

    #[test]
    fn test_allows_high_s_when_not_enforced() {
        let r = small_scalar(SMALL_NONCE_X);
        let s = order_minus(1);
        let public_key = public_key_for(&r, &s, &MESSAGE_HASH);
        assert_accepted(&public_key, &signature(&r, &s), &MESSAGE_HASH);
    }

    #[test]
    fn test_propagates_hasher_errors() {
        let sig = signature(&one(), &one());
        assert_eq!(
            verify_signature::<RawHasher>(&PUBLIC_KEY, &sig, &[0xab; 31], true),
            Err(Secp256r1VerifyError::InvalidMessageLength)
        );
    }

    #[test]
    fn test_verifies_real_signatures() {
        for seed in 1..=16u8 {
            let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
            let public_key = compressed_key(&signing_key);
            let message = [seed; 40];
            let (low, high) = low_and_high_s(&signing_key, &message);

            let strict = Secp256r1Verifier::<Sha256Hasher>::new();
            assert_eq!(strict.verify_signature(&public_key, &low, &message), Ok(()));
            assert_eq!(
                strict.verify_signature(&public_key, &high, &message),
                Err(Secp256r1VerifyError::InvalidMalleableSignature)
            );

            let relaxed = Secp256r1Verifier::<Sha256Hasher>::new().allow_high_s();
            assert_eq!(
                relaxed.verify_signature(&public_key, &low, &message),
                Ok(())
            );
            assert_eq!(
                relaxed.verify_signature(&public_key, &high, &message),
                Ok(())
            );
        }
    }

    #[test]
    fn test_rejects_tampered_hash() {
        let (public_key, sig) = sample_signed_hash();
        let mut hash = MESSAGE_HASH;
        hash[0] ^= 1;
        assert_mismatch(&public_key, &sig, &hash);
    }

    #[test]
    fn test_rejects_wrong_public_key() {
        let (_, sig) = sample_signed_hash();
        assert_mismatch(&generator_public_key(), &sig, &MESSAGE_HASH);
    }

    #[test]
    fn test_rejects_negated_public_key() {
        let (mut public_key, sig) = sample_signed_hash();
        public_key[0] ^= 1;
        assert_mismatch(&public_key, &sig, &MESSAGE_HASH);
    }

    #[test]
    fn test_rejects_tampered_s() {
        let (public_key, _) = sample_signed_hash();
        let sig = signature(&small_scalar(SMALL_NONCE_X), &small_scalar(10));
        assert_mismatch(&public_key, &sig, &MESSAGE_HASH);
    }

    #[test]
    fn test_rejects_tampered_r() {
        let (public_key, _) = sample_signed_hash();
        let sig = signature(&small_scalar(SMALL_NONCE_X + 1), &small_scalar(9));
        assert_mismatch(&public_key, &sig, &MESSAGE_HASH);
    }

    #[test]
    fn test_rejects_invalid_public_keys() {
        let sig = signature(&small_scalar(SMALL_NONCE_X), &one());

        let mut bad_prefix = generator_public_key();
        bad_prefix[0] = 0x04;

        // 1 is not an X-coordinate on the curve.
        let mut off_curve = [0u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE];
        off_curve[0] = 0x02;
        off_curve[COMPRESSED_PUBKEY_SERIALIZED_SIZE - 1] = 1;

        let mut above_field = [0xff; COMPRESSED_PUBKEY_SERIALIZED_SIZE];
        above_field[0] = 0x02;

        for public_key in [bad_prefix, off_curve, above_field] {
            assert_eq!(
                verify_with_key(&public_key, &sig, &MESSAGE_HASH, true),
                Err(Secp256r1VerifyError::InvalidPublicKey)
            );
        }
    }

    #[test]
    fn test_reduces_message_hash_modulo_order() {
        let r = small_scalar(SMALL_NONCE_X);
        let s = one();

        for hash in [SECP256R1_ORDER, order_plus(7), [0xff; SCALAR_BYTES]] {
            let public_key = public_key_for(&r, &s, &hash);
            assert_accepted(&public_key, &signature(&r, &s), &hash);
        }
    }

    #[test]
    fn test_accepts_zero_message_hash() {
        let r = small_scalar(SMALL_NONCE_X);
        let s = one();
        let hash = [0u8; SCALAR_BYTES];
        let public_key = public_key_for(&r, &s, &hash);
        assert_accepted(&public_key, &signature(&r, &s), &hash);
    }

    #[test]
    fn test_rejects_identity_nonce_point() {
        // With `Q = G` and `z = -r`, `R` is the identity, whose X-coordinate of
        // zero cannot match a non-zero `r`.
        let r = small_scalar(SMALL_NONCE_X);
        let hash = (-Scalar::from_bytes(&r, Endianness::Big).unwrap()).to_be_bytes();

        assert_mismatch(&generator_public_key(), &signature(&r, &one()), &hash);
    }

    #[test]
    fn test_accepts_nonce_x_above_order() {
        let s = one();

        // The largest X-coordinate on the curve is p - 3.
        let mut largest_r = SECP256R1_FIELD_MODULUS_MINUS_ORDER;
        largest_r[SCALAR_BYTES - 1] -= 3;
        let mut largest_nonce_x = SECP256R1_FIELD_MODULUS;
        largest_nonce_x[SCALAR_BYTES - 1] -= 3;

        // `R` has the X-coordinate `r + N`, so it has to be reduced to match `r`.
        for (r, nonce_x) in [
            (small_scalar(3), order_plus(3)),
            (small_scalar(6), order_plus(6)),
            (largest_r, largest_nonce_x),
        ] {
            let public_key = public_key_for(&nonce_x, &s, &MESSAGE_HASH);
            assert_accepted(&public_key, &signature(&r, &s), &MESSAGE_HASH);
        }
    }

    #[test]
    fn test_accepts_nonce_x_below_order() {
        let r = small_scalar(6);
        let s = one();
        let public_key = public_key_for(&r, &s, &MESSAGE_HASH);
        assert_accepted(&public_key, &signature(&r, &s), &MESSAGE_HASH);
    }
}
