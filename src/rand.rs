use crypto_bigint::UInt;
use rand::{Rng, CryptoRng};

use crate::compat::gen_biguint_range;

/// Iterator to generate a given amount of random numbers. For convenience of
/// use with miller_rabin tests, you can also append a specified number at the
/// end of the generated stream.
pub struct Randoms<R, I> {
    appended: Option<I>,
    lower_limit: I,
    upper_limit: I,
    amount: usize,
    rng: R,
}

impl<const N: usize, R: Rng + CryptoRng> Randoms<R, UInt<N>> {
    pub fn new(lower_limit: UInt<N>, upper_limit: UInt<N>, amount: usize, rng: R) -> Self {
        Self {
            appended: None,
            lower_limit,
            upper_limit,
            amount,
            rng,
        }
    }

    /// Append the number at the end to appear as if it was generated. This
    /// doesn't affect stream length. Only one number can be appended,
    /// subsequent calls will replace the previously appended number.
    pub fn with_appended(mut self, x: UInt<N>) -> Self {
        self.appended = Some(x);
        self
    }

    fn gen_biguint(&mut self) -> UInt<N> {
        gen_biguint_range(&mut self.rng, self.lower_limit, self.upper_limit)
    }
}

impl<const N: usize, R: Rng + CryptoRng> Iterator for Randoms<R, UInt<N>> {
    type Item = UInt<N>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.amount == 0 {
            None
        } else if self.amount == 1 {
            let r = match core::mem::replace(&mut self.appended, None) {
                Some(x) => x,
                None => self.gen_biguint(),
            };
            self.amount -= 1;
            Some(r)
        } else {
            self.amount -= 1;
            Some(self.gen_biguint())
        }
    }
}

#[cfg(test)]
mod test {
    use super::Randoms;
    use crypto_bigint::U256;
    use rand::thread_rng;

    #[test]
    fn generate_amount_test() {
        let amount = 3;
        let rands = Randoms::new(0_u8.into(), 1_u8.into(), amount, thread_rng());
        let generated = rands.collect::<Vec<U256>>();
        assert_eq!(generated.len(), amount);

        let rands =
            Randoms::new(0_u8.into(), 1_u8.into(), amount, thread_rng()).with_appended(2_u8.into());
        let generated = rands.collect::<Vec<U256>>();
        assert_eq!(generated.len(), amount);
    }
}
