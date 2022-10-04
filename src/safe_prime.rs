//! Generates cryptographically secure safe prime numbers.

use rand::rngs::OsRng;
use crypto_bigint::{UInt, Concat, Split};

use crate::common::MIN_BIT_LENGTH;
pub use crate::common::{
    gen_safe_prime as from_rng, is_safe_prime as check, is_safe_prime_baillie_psw as strong_check,
};
use crate::error::{Error, Result};

/// Constructs a new safe prime number with a size of `bit_length` bits.
///
/// This will initialize an `OsRng` instance and call the
/// `from_rng()` function.
///
/// Note: the `bit_length` MUST be at least 128-bits.
pub fn new<const N: usize, const W: usize>(bit_length: usize) -> Result<N>
    where
        UInt<N>: Concat<Output = UInt<W>>,
        UInt<W>: Split<Output = UInt<N>>,
{
    if bit_length < MIN_BIT_LENGTH {
        Err(Error::BitLength(bit_length))
    } else {
        let mut rng = OsRng::default();
        Ok(from_rng(bit_length, &mut rng)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{check, new, strong_check};
    use crypto_bigint::{UInt, Concat, Split};

    fn tests_for<const N: usize, const W: usize>()
        where
            UInt<N>: Concat<Output = UInt<W>>,
            UInt<W>: Split<Output = UInt<N>>,
    {
        let bits_options = [128, 256, 512, 1024].iter().filter(|n| **n <= N * 8);
        for bits in bits_options {
            let n: crypto_bigint::UInt<N> = new(*bits).unwrap();
            assert!(check(&n));
            assert!(strong_check(&n));
        }
    }

    #[test]
    fn tests() {
        tests_for::<1, 2>();
        tests_for::<4, 8>();
        tests_for::<8, 16>();
        tests_for::<16, 32>();
    }
}
