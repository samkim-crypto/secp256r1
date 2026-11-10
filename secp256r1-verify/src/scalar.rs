//! Arithmetic modulo the group order, which the curve syscalls do not provide.

use crate::constants::{SCALAR_BYTES, SECP256R1_ORDER};

/// Reduces an X-coordinate modulo the group order.
///
/// X-coordinates are below the field modulus `p`, and `p < 2N`, so one
/// subtraction is enough.
#[inline(always)]
pub(crate) fn reduce_mod_order(value: &mut [u8; SCALAR_BYTES]) {
    if *value >= SECP256R1_ORDER {
        let mut borrow = false;
        for (byte, order_byte) in value.iter_mut().rev().zip(SECP256R1_ORDER.iter().rev()) {
            let (difference, underflowed) = byte.overflowing_sub(*order_byte);
            let (difference, underflowed_borrow) = difference.overflowing_sub(u8::from(borrow));
            *byte = difference;
            borrow = underflowed || underflowed_borrow;
        }
    }
}

/// Replaces `[z, r]` with `[z/s, r/s]` modulo the group order.
///
/// `s` must be in `[1, N)`, so that it has an inverse.
#[inline(always)]
pub(crate) fn divide_by_s(scalars: &mut [[u8; SCALAR_BYTES]; 2], s: &[u8; SCALAR_BYTES]) {
    // By Fermat's little theorem, because `N` is prime.
    let s_inverse = big_mod_exp(&be_to_limbs(s), &ORDER_MINUS_TWO_LE);
    for scalar in scalars {
        let product = mul_wide(&be_to_limbs(scalar), &s_inverse);
        *scalar = limbs_to_be(&big_mod_exp(&product, &[1]));
    }
}

/// The group order as a little-endian integer, for `sol_big_mod_exp`.
static ORDER_LE: [u8; SCALAR_BYTES] = {
    let mut reversed = [0u8; SCALAR_BYTES];
    let mut index = 0;
    while index < SCALAR_BYTES {
        reversed[index] = SECP256R1_ORDER[SCALAR_BYTES - 1 - index];
        index += 1;
    }
    reversed
};

/// `N - 2` as a little-endian integer. The low byte of `N` is above 2, so the
/// subtraction does not borrow.
static ORDER_MINUS_TWO_LE: [u8; SCALAR_BYTES] = {
    let mut exponent = ORDER_LE;
    exponent[0] -= 2;
    exponent
};

/// Computes `base^exponent mod N`. On little-endian SBF, limbs ordered from
/// least significant are the little-endian integer the syscall expects.
#[inline(always)]
fn big_mod_exp(base: &[u32], exponent: &[u8]) -> [u32; 8] {
    #[cfg(not(target_os = "solana"))]
    {
        use solana_secp256r1::{scalar::Scalar, Endianness};

        let mut limb_radix = [0u8; SCALAR_BYTES];
        limb_radix[SCALAR_BYTES - 5] = 1;
        let limb_radix = Scalar::from_bytes_reduced(&limb_radix, Endianness::Big);

        let base = base.iter().rev().fold(Scalar::ZERO, |value, limb| {
            let mut limb_bytes = [0u8; SCALAR_BYTES];
            limb_bytes[SCALAR_BYTES - 4..].copy_from_slice(&limb.to_be_bytes());
            value * limb_radix + Scalar::from_bytes_reduced(&limb_bytes, Endianness::Big)
        });

        let mut result = Scalar::ONE;
        for byte in exponent.iter().rev() {
            for bit in (0..8).rev() {
                result = result.square();
                if (byte >> bit) & 1 == 1 {
                    result = result * base;
                }
            }
        }
        be_to_limbs(&result.to_be_bytes())
    }

    #[cfg(target_os = "solana")]
    {
        #[repr(C)]
        struct BigModExpParams {
            base: *const u8,
            base_len: u64,
            exponent: *const u8,
            exponent_len: u64,
            modulus: *const u8,
            modulus_len: u64,
        }

        let params = BigModExpParams {
            base: base.as_ptr().cast::<u8>(),
            base_len: core::mem::size_of_val(base) as u64,
            exponent: exponent.as_ptr(),
            exponent_len: exponent.len() as u64,
            modulus: ORDER_LE.as_ptr(),
            modulus_len: ORDER_LE.len() as u64,
        };
        let mut output = core::mem::MaybeUninit::<[u32; 8]>::uninit();

        // SAFETY: `params` describes three readable slices and the output has room
        // for a modulus-sized result. `N` is odd and greater than one, so the
        // syscall does not abort.
        unsafe {
            solana_define_syscall::definitions::sol_big_mod_exp(
                core::ptr::from_ref(&params).cast::<u8>(),
                output.as_mut_ptr().cast::<u8>(),
            );
            output.assume_init()
        }
    }
}

/// Splits a big-endian integer into 32-bit limbs, least significant first.
#[inline(always)]
fn be_to_limbs(bytes: &[u8; SCALAR_BYTES]) -> [u32; 8] {
    // Each range is exactly one limb long, so the conversions succeed.
    core::array::from_fn(|limb| {
        let start = (7 - limb) * 4;
        u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap())
    })
}

/// Joins 32-bit limbs, least significant first, into a big-endian integer.
#[inline(always)]
fn limbs_to_be(limbs: &[u32; 8]) -> [u8; SCALAR_BYTES] {
    let mut bytes = [0u8; SCALAR_BYTES];
    for (limb, value) in limbs.iter().enumerate() {
        let start = (7 - limb) * 4;
        bytes[start..start + 4].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

/// Computes the full 512-bit product of two 256-bit integers.
///
/// A `u128` product compiles to a software multiply on SBF. With 32-bit limbs,
/// every product and its carries fit in a `u64`:
/// `(2^32 - 1)^2 + 2 * (2^32 - 1)` is exactly `2^64 - 1`.
#[inline(always)]
fn mul_wide(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut product = [0u32; 16];
    for (i, &a_limb) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &b_limb) in b.iter().enumerate() {
            let total = u64::from(a_limb) * u64::from(b_limb) + u64::from(product[i + j]) + carry;
            product[i + j] = total as u32;
            carry = total >> 32;
        }
        product[i + 8] = carry as u32;
    }
    product
}

#[cfg(test)]
pub(crate) fn small_scalar(value: u8) -> [u8; SCALAR_BYTES] {
    let mut scalar = [0u8; SCALAR_BYTES];
    scalar[SCALAR_BYTES - 1] = value;
    scalar
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::constants::SECP256R1_HALF_ORDER,
        solana_secp256r1::{scalar::Scalar, Endianness},
    };

    #[test]
    fn test_reduce_mod_order_matches_scalar_field() {
        let mut order_minus_one = SECP256R1_ORDER;
        order_minus_one[SCALAR_BYTES - 1] -= 1;
        let mut order_plus_one = SECP256R1_ORDER;
        order_plus_one[SCALAR_BYTES - 1] += 1;

        for value in [
            [0; SCALAR_BYTES],
            SECP256R1_HALF_ORDER,
            order_minus_one,
            SECP256R1_ORDER,
            order_plus_one,
            [0xff; SCALAR_BYTES],
        ] {
            let mut reduced = value;
            reduce_mod_order(&mut reduced);
            assert_eq!(
                reduced,
                Scalar::from_bytes_reduced(&value, Endianness::Big).to_be_bytes()
            );
        }
    }

    #[test]
    fn test_divide_by_s_matches_scalar_field() {
        let mut order_minus_one = SECP256R1_ORDER;
        order_minus_one[SCALAR_BYTES - 1] -= 1;

        for s in [
            small_scalar(1),
            small_scalar(2),
            SECP256R1_HALF_ORDER,
            order_minus_one,
        ] {
            let s_inverse = Scalar::from_bytes_reduced(&s, Endianness::Big)
                .invert()
                .unwrap();

            for numerator in [
                [0u8; SCALAR_BYTES],
                small_scalar(7),
                SECP256R1_ORDER,
                [0xff; SCALAR_BYTES],
            ] {
                let mut scalars = [numerator, small_scalar(9)];
                divide_by_s(&mut scalars, &s);

                let expected = |value: &[u8; SCALAR_BYTES]| {
                    (Scalar::from_bytes_reduced(value, Endianness::Big) * s_inverse).to_be_bytes()
                };
                assert_eq!(scalars, [expected(&numerator), expected(&small_scalar(9))]);
            }
        }
    }

    #[test]
    fn test_mul_wide_matches_scalar_field() {
        let values = [
            [0u8; SCALAR_BYTES],
            small_scalar(1),
            SECP256R1_HALF_ORDER,
            SECP256R1_ORDER,
            [0xff; SCALAR_BYTES],
            [0x5a; SCALAR_BYTES],
        ];
        let two_to_256 =
            Scalar::from_bytes_reduced(&[0xff; SCALAR_BYTES], Endianness::Big) + Scalar::ONE;

        for a in &values {
            for b in &values {
                let product = mul_wide(&be_to_limbs(a), &be_to_limbs(b));
                let low = limbs_to_be(product[..8].try_into().unwrap());
                let high = limbs_to_be(product[8..].try_into().unwrap());

                let recombined = Scalar::from_bytes_reduced(&high, Endianness::Big) * two_to_256
                    + Scalar::from_bytes_reduced(&low, Endianness::Big);
                let direct = Scalar::from_bytes_reduced(a, Endianness::Big)
                    * Scalar::from_bytes_reduced(b, Endianness::Big);

                assert_eq!(recombined.to_be_bytes(), direct.to_be_bytes());
            }
        }
    }

    #[test]
    fn test_mul_wide_handles_largest_operands() {
        // (2^256 - 1)^2 = 2^512 - 2^257 + 1.
        let max = [u32::MAX; 8];
        let mut expected = [0u32; 16];
        expected[0] = 1;
        expected[8] = 0xffff_fffe;
        expected[9..].fill(u32::MAX);
        assert_eq!(mul_wide(&max, &max), expected);
    }

    #[test]
    fn test_limbs_round_trip() {
        let value: [u8; SCALAR_BYTES] = core::array::from_fn(|index| index as u8);
        let limbs = be_to_limbs(&value);
        assert_eq!(limbs[7], u32::from_be_bytes(value[..4].try_into().unwrap()));
        assert_eq!(limbs_to_be(&limbs), value);
    }
}
