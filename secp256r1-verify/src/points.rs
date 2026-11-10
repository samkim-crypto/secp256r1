//! secp256r1 point operations on big-endian `X || Y` encodings.
//!
//! On-chain these call the curve syscalls from SIMD-0565. Off-chain they use
//! `solana-secp256r1`, the arithmetic behind those syscalls.
//!
//! The wrappers write into caller-provided `MaybeUninit` buffers. Compared with
//! taking initialized buffers and returning `Option`, that saves 39 compute
//! units per verification.

use {
    crate::constants::{
        COMPRESSED_PUBKEY_SERIALIZED_SIZE, SCALAR_BYTES, UNCOMPRESSED_POINT_SERIALIZED_SIZE,
    },
    core::mem::MaybeUninit,
};

/// Decompresses a point into `output`, returning `false` if it is not on the
/// curve. `output` is initialized only when this returns `true`.
#[inline(always)]
pub(crate) fn decompress_into(
    point: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    output: &mut MaybeUninit<[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]>,
) -> bool {
    #[cfg(not(target_os = "solana"))]
    {
        use solana_secp256r1::{group::AffinePoint, Endianness};

        AffinePoint::from_compressed(point, Endianness::Big)
            .map(|point| output.write(point.to_uncompressed(Endianness::Big)))
            .is_some()
    }

    #[cfg(target_os = "solana")]
    {
        use solana_define_syscall::{
            curve_constants::SECP256R1_BE, definitions::sol_curve_decompress,
        };

        // SAFETY: The input is one compressed point. The output has space for
        // one uncompressed point and does not overlap the input.
        let status = unsafe {
            sol_curve_decompress(
                SECP256R1_BE,
                point.as_ptr(),
                output.as_mut_ptr().cast::<u8>(),
            )
        };

        status == 0
    }
}

/// Writes a multiscalar multiplication with exactly two scalar-point pairs to
/// `output`, returning `false` if a point is not on the curve or a scalar is
/// not below the group order. `output` is initialized only when this returns
/// `true`.
#[inline(always)]
pub(crate) fn multiscalar_multiply_2_into(
    scalars: &[[u8; SCALAR_BYTES]; 2],
    points: &[[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]; 2],
    output: &mut MaybeUninit<[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]>,
) -> bool {
    #[cfg(not(target_os = "solana"))]
    {
        use solana_secp256r1::{
            group::{AffinePoint, ProjectivePoint},
            Endianness,
        };

        let (Some(first), Some(second)) = (
            AffinePoint::from_uncompressed(&points[0], Endianness::Big),
            AffinePoint::from_uncompressed(&points[1], Endianness::Big),
        ) else {
            return false;
        };
        ProjectivePoint::multi_scalar_mul_vartime(&[first, second], scalars)
            .map(|sum| output.write(sum.to_uncompressed(Endianness::Big)))
            .is_some()
    }

    #[cfg(target_os = "solana")]
    {
        use solana_define_syscall::{
            curve_constants::SECP256R1_BE, definitions::sol_curve_multiscalar_mul,
        };

        // SAFETY: Both input arrays contain exactly two contiguous encodings.
        // The output has space for one uncompressed point and does not overlap
        // either input.
        let status = unsafe {
            sol_curve_multiscalar_mul(
                SECP256R1_BE,
                scalars.as_ptr().cast::<u8>(),
                points.as_ptr().cast::<u8>(),
                2,
                output.as_mut_ptr().cast::<u8>(),
            )
        };

        status == 0
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            constants::{SECP256R1_GENERATOR, SECP256R1_ORDER},
            scalar::small_scalar,
        },
        solana_secp256r1::{
            group::{AffinePoint, ProjectivePoint},
            Endianness,
        },
    };

    fn decompress(
        point: &[u8; COMPRESSED_PUBKEY_SERIALIZED_SIZE],
    ) -> Option<[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]> {
        let mut output = MaybeUninit::uninit();
        // SAFETY: `output` is initialized when `decompress_into` returns `true`.
        decompress_into(point, &mut output).then(|| unsafe { output.assume_init() })
    }

    fn multiscalar_multiply_2(
        scalars: &[[u8; SCALAR_BYTES]; 2],
        points: &[[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]; 2],
    ) -> Option<[u8; UNCOMPRESSED_POINT_SERIALIZED_SIZE]> {
        let mut output = MaybeUninit::uninit();
        // SAFETY: `output` is initialized when `multiscalar_multiply_2_into`
        // returns `true`.
        multiscalar_multiply_2_into(scalars, points, &mut output)
            .then(|| unsafe { output.assume_init() })
    }

    #[test]
    fn test_generator_constant_matches_curve() {
        assert_eq!(
            SECP256R1_GENERATOR,
            AffinePoint::generator().to_uncompressed(Endianness::Big)
        );
    }

    #[test]
    fn test_decompress_round_trips_generator() {
        let compressed = AffinePoint::generator()
            .to_compressed(Endianness::Big)
            .unwrap();
        assert_eq!(decompress(&compressed), Some(SECP256R1_GENERATOR));
    }

    #[test]
    fn test_decompress_rejects_invalid_prefix() {
        let mut compressed = AffinePoint::generator()
            .to_compressed(Endianness::Big)
            .unwrap();
        compressed[0] = 0x04;
        assert_eq!(decompress(&compressed), None);
    }

    #[test]
    fn test_multiscalar_multiply_matches_multiply() {
        assert_eq!(
            multiscalar_multiply_2(
                &[small_scalar(2), small_scalar(3)],
                &[SECP256R1_GENERATOR, SECP256R1_GENERATOR],
            ),
            Some(
                ProjectivePoint::generator()
                    .mul_scalar_vartime(small_scalar(5))
                    .unwrap()
                    .to_uncompressed(Endianness::Big)
            )
        );
    }

    #[test]
    fn test_multiscalar_multiply_rejects_scalar_at_order() {
        assert_eq!(
            multiscalar_multiply_2(
                &[SECP256R1_ORDER, small_scalar(1)],
                &[SECP256R1_GENERATOR, SECP256R1_GENERATOR],
            ),
            None
        );
    }
}
