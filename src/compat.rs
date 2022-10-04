use core::ops::Rem;

use crypto_bigint::subtle::ConditionallySelectable;
use crypto_bigint::{Concat, RandomMod, Split, Zero};
use crypto_bigint::{Integer, NonZero, UInt};
use rand::{CryptoRng, RngCore};

pub fn is_one<T: Integer>(x: &T) -> bool {
    x == &T::ONE
}

// NonZero implements From for core's NonZero* types, but type inference can't
// handle it. Especially with references, which is how they are used in the
// code.
pub fn promote_corenz<const N: usize>(x: &core::num::NonZeroU32) -> NonZero<UInt<N>> {
    (*x).into()
}

type WUint<const N: usize> = <UInt<N> as Concat>::Output;

// NonZero doesn't implement From traits, and even if it did we would have to
// carry them around, which is a pain
pub fn promote_nz<const N: usize>(x: &NonZero<UInt<N>>) -> NonZero<WUint<N>>
where
    UInt<N>: Concat,
    WUint<N>: Zero,
    WUint<N>: ConditionallySelectable,
{
    let zero: UInt<N> = Zero::ZERO;
    let wide = zero.concat(x);
    NonZero::new(wide).unwrap()
}

/// Modular multiplication by widening. Not constant-time
pub fn mul_mod<const N: usize, const W: usize>(
    x: &UInt<N>,
    y: &UInt<N>,
    m: &NonZero<UInt<N>>,
) -> UInt<N>
where
    UInt<N>: crypto_bigint::Concat<Output = UInt<W>>,
    UInt<W>: crypto_bigint::Split<Output = UInt<N>>,
{
    let (lo, hi) = x.mul_wide(y);
    let wide: <UInt<N> as Concat>::Output = hi.concat(&lo);
    let m_wide: NonZero<UInt<W>> = promote_nz(m);
    let r: <UInt<N> as Concat>::Output = wide.rem(&m_wide);
    let (_hi, lo) = r.split();
    lo
}

/// Modulo exponentiation by squaring, textbook implementation
pub fn modpow<const N: usize, const W: usize>(
    x: UInt<N>,
    e: &UInt<N>,
    m: &NonZero<UInt<N>>,
) -> UInt<N>
where
    UInt<N>: crypto_bigint::Concat<Output = UInt<W>>,
    UInt<W>: crypto_bigint::Split<Output = UInt<N>>,
{
    if x == Zero::ZERO {
        x
    } else if *e == Zero::ZERO {
        Integer::ONE
    } else {
        let mut this_power = x.rem(m);
        let mut result: UInt<N> = Integer::ONE;
        for bit_index in 0..e.bits() {
            if is_bit_set(&e, bit_index) {
                result = mul_mod(&result, &this_power, m);
            }
            this_power = mul_mod(&this_power, &this_power, m);
        }
        result
    }
}

/// Generate biguint in in range low..high. Panics on incorrect range
pub fn gen_biguint_range<R: CryptoRng + RngCore, const N: usize>(
    rng: R,
    low: UInt<N>,
    high: UInt<N>,
) -> UInt<N> {
    match NonZero::new(high.saturating_sub(&low)).into() {
        Some(m) => UInt::<N>::random_mod(rng, &m).saturating_add(&low),
        None => panic!("Zero range"),
    }
}

/// Generate biguint with given bit size, i.e. bit indexed `bit_size` is set
pub fn gen_biguint_bits<R, const N: usize>(rng: R, bit_size: usize) -> UInt<N>
where
    R: CryptoRng + RngCore,
{
    let mask = UInt::<N>::ONE << (bit_size - 1);
    if mask == Zero::ZERO {
        panic!("too many bits for type");
    }
    let modulo = match NonZero::new(mask << 1).into() {
        Some(m) => m,
        None => NonZero::MAX,
    };
    UInt::random_mod(rng, &modulo) | mask
}

/// Checks if the i-th bit is set
#[inline]
fn is_bit_set<const N: usize>(x: &UInt<N>, i: usize) -> bool {
    if i >= x.bits() {
        return false;
    }
    let res = x >> i;
    res.is_odd().into()
}

#[cfg(test)]
pub fn from_str_radix<const N: usize>(s: &str, radix: usize) -> Option<UInt<N>> {
    fn from_digit(c: u64) -> Option<u64> {
        let zero = '0'.into();
        let nine = '9'.into();
        let al = 'a'.into();
        let au = 'A'.into();
        let zl = 'z'.into();
        let zu = 'Z'.into();
        if c >= zero && c <= nine {
            Some(c - zero)
        } else if c >= al && c <= zl {
            Some(c - al + 10)
        } else if c >= au && c <= zu {
            Some(c - au + 10)
        } else {
            None
        }
    }
    let mut r: UInt<N> = Zero::ZERO;
    let radix = radix as u64;
    for c in s.chars() {
        let c = from_digit(c.into())?;
        r = r.wrapping_mul(&radix.into());
        r = r.wrapping_add(&c.into());
    }
    Some(r)
}

#[cfg(test)]
mod test {
    use super::*;
    use crypto_bigint::U256;

    #[test]
    fn modpow_spec() {
        let x = from_str_radix::<4>("109BF050E8004F525", 16).unwrap();
        let e = from_str_radix::<4>("1F60DB8AD35B04936", 16).unwrap();
        let m = crypto_bigint::NonZero::new(from_str_radix::<4>("1F60DB8AD35B04937", 16).unwrap())
            .unwrap();
        let r = super::modpow(x, &e, &m);
        assert_eq!(r, crypto_bigint::Integer::ONE);
    }

    #[test]
    fn is_bit_set_spec() {
        let x: U256 = 0b1010111100000101_u64.into();
        assert!(is_bit_set(&x, 0));
        assert!(!is_bit_set(&x, 1));
        assert!(is_bit_set(&x, 2));
        assert!(!is_bit_set(&x, 3));
        assert!(!is_bit_set(&x, 4));
        assert!(!is_bit_set(&x, 5));
        assert!(!is_bit_set(&x, 6));
        assert!(!is_bit_set(&x, 7));
        assert!(is_bit_set(&x, 8));
        assert!(is_bit_set(&x, 9));
        assert!(is_bit_set(&x, 10));
        assert!(is_bit_set(&x, 11));
        assert!(!is_bit_set(&x, 12));
        assert!(is_bit_set(&x, 13));
        assert!(!is_bit_set(&x, 14));
        assert!(is_bit_set(&x, 15));
    }

    #[test]
    fn mod_spec() {
        let x: U256 = from_str_radix(
            "113910913923300788319699387848674650656041243163866388656000063249848353322899",
            10,
        )
        .unwrap();
        let three: NonZero<U256> = NonZero::new(3u32.into()).unwrap();
        let r: U256 = x % &three;
        assert_eq!(r, 2u32.into());
    }
}
