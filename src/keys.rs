//! The key pairs
use crate::BigInt;
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    CheckedAdd, CheckedMul, CheckedSub, NonZero, RandomMod,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct PublicKey {
    r: BigInt,
    n: BigInt,
    y: BigInt,
}

impl PublicKey {
    /// Instantiate an instance with no check
    pub fn new(r: BigInt, n: BigInt, y: BigInt) -> Self {
        return Self { r, n, y };
    }

    pub fn get_r(&self) -> &BigInt {
        &self.r
    }

    pub fn get_n(&self) -> &BigInt {
        &self.n
    }

    pub fn get_y(&self) -> &BigInt {
        &self.y
    }

    /// Return the multiplicative inverse of y
    pub fn invert_y(&self) -> BigInt {
        let (y_inv, invertible) = self.y.inv_mod(self.get_n());
        if invertible.into() {
            return y_inv;
        }
        panic!("y is not invertible");
    }

    /// Sample a random element from the multiplicative group Z/n
    pub fn sample_invertible(&self) -> BigInt {
        return KeyPair::sample_invertible(self.n);
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct SecretKey {
    phi: BigInt,
}

impl SecretKey {
    /// Instantiate an instance with no check
    pub fn new(phi: BigInt) -> Self {
        Self { phi }
    }

    pub fn get_phi(&self) -> &BigInt {
        &self.phi
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct KeyPair {
    pk: PublicKey,
    sk: SecretKey,
}

impl KeyPair {
    pub fn new(pk: PublicKey, sk: SecretKey) -> Self {
        Self { pk, sk }
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn get_sk(&self) -> &SecretKey {
        &self.sk
    }

    /// generate p according to the arithmetic sequence:
    /// p = r * r * x + b * r + 1
    fn generate_p(r: BigInt, xbound: BigInt, b: BigInt, safe: bool) -> BigInt {
        let x = BigInt::random_mod(&mut OsRng, &NonZero::new(xbound).unwrap());
        let rrx = r.checked_mul(&r).unwrap().checked_mul(&x).unwrap();
        let rb = r.checked_mul(&b).unwrap();
        let mut p = rrx
            .checked_add(&rb)
            .unwrap()
            .checked_add(&BigInt::ONE)
            .unwrap();
        let mut ready = {
            if safe {
                crypto_primes::is_safe_prime(&p)
            } else {
                crypto_primes::is_prime(&p)
            }
        };
        while !ready {
            let x = BigInt::random_mod(&mut OsRng, &NonZero::new(xbound).unwrap());
            let rrx = r.checked_mul(&r).unwrap().checked_mul(&x).unwrap();
            let rb = r.checked_mul(&b).unwrap();
            p = rrx
                .checked_add(&rb)
                .unwrap()
                .checked_add(&BigInt::ONE)
                .unwrap();
            ready = {
                if safe {
                    crypto_primes::is_safe_prime(&p)
                } else {
                    crypto_primes::is_prime(&p)
                }
            };
        }
        return p;
    }

    /// Generate q according to the arithmetic sequence:
    /// q = r * x + b
    fn generate_q(r: BigInt, xbound: BigInt, b: BigInt, safe: bool) -> BigInt {
        let x = BigInt::random_mod(&mut OsRng, &NonZero::new(xbound).unwrap());
        let mut q = r.checked_mul(&x).unwrap().checked_add(&b).unwrap();
        let mut ready = {
            if safe {
                crypto_primes::is_safe_prime(&q)
            } else {
                crypto_primes::is_prime(&q)
            }
        };
        while !ready {
            let x = BigInt::random_mod(&mut OsRng, &NonZero::new(xbound).unwrap());
            q = r.checked_mul(&x).unwrap().checked_add(&b).unwrap();
            ready = {
                if safe {
                    crypto_primes::is_safe_prime(&q)
                } else {
                    crypto_primes::is_prime(&q)
                }
            };
        }
        return q;
    }

    /// Sample from the multiplicative group (mod n)
    /// TODO: move this somewhere more accessible
    fn sample_invertible(modulus: BigInt) -> BigInt {
        loop {
            let y = BigInt::random_mod(&mut OsRng, &NonZero::new(modulus).unwrap());
            let (_, invertible) = y.inv_mod(&modulus);
            if invertible.into() {
                return y;
            }
        }
    }

    /// Sample a non-residue. A non-residue is an invertible element such that
    /// y^{phi/r} != 1 (mod n)
    fn sample_nonresidue(modulus: BigInt, r: BigInt, phi: BigInt) -> BigInt {
        let quotient = phi.checked_div(&r).unwrap();

        loop {
            let y = Self::sample_invertible(modulus);
            if DynResidue::new(&y, DynResidueParams::new(&modulus))
                .pow(&quotient)
                .retrieve()
                != BigInt::ONE
            {
                return y;
            }
        }
    }

    /// Given that (r, n, y) is prime consonance, we can use the secret key to efficiently find the
    /// r-th root of some r-th residue using the following relation:
    /// A * r + B * (phi / r) = 1,
    /// Notice that A is r's multiplicative inverse modulus (phi / r) and is dependent only on the
    /// keypair, so we can compute it ahead of time
    pub fn get_rth_root_exp(&self) -> BigInt {
        let r = self.pk.r;
        let phi = self.sk.phi;
        let phi_over_r = phi.checked_div(&r).unwrap();
        let (root_exp, is_invertible) = r.inv_mod(&phi_over_r);
        if is_invertible.into() {
            return root_exp;
        }
        panic!("r, phi/r not relatively prime");
    }

    /// Assuming that (r, n, y) is prime consonance, check that it is also perfect consonance.
    /// Perfect consonance is defined by two conditions:
    /// 1. r divides phi
    /// 2. r and phi/r are relatively prime
    pub fn check_perfect_consonance(&self) -> bool {
        let r = self.get_pk().get_r().clone();
        let phi = self.get_sk().get_phi();
        let divisible = phi % NonZero::new(r).unwrap() == BigInt::ZERO;
        let indivisible = (phi.checked_div(&r).unwrap()) % NonZero::new(r).unwrap() != BigInt::ZERO;
        return divisible && indivisible;
    }

    /// Generate a valid set of parameters such that (r, n, y) is perfectly consonant
    /// First generate r, then use arithmetic sequence to generate p, q:
    /// q = r * x + b
    /// p = (r ** 2) * x + br + 1
    ///
    /// the ring size is mostly dependent on the application (e.g. ring size must be no less than
    /// the number of voters), while the modulus size is the main security parameters. Both are
    /// measured in number of bits. Note that the modulus size will need to be significantly more
    /// than the ring size (duh).
    ///
    /// reference: 2 ** 33 ~= 8.58 billion, 2 ** 29 >= 300 million
    pub fn keygen(ring_size: usize, modulus_size: usize, safe: bool) -> Self {
        let r: BigInt = crypto_primes::generate_prime(Some(ring_size));
        let xbound = DynResidue::new(&BigInt::from_u8(2), DynResidueParams::new(&BigInt::MAX))
            .pow(&BigInt::from_u64(modulus_size as u64))
            .retrieve(); // x is the dominant term in the arithmetic sequence
                         // Generate the non-zero remainder in the arithmetic sequence
        let mut b: BigInt = BigInt::random_mod(&mut OsRng, &NonZero::new(r).unwrap());
        while b == BigInt::ZERO {
            b = BigInt::random_mod(&mut OsRng, &NonZero::new(r).unwrap());
        }

        let q = Self::generate_q(r, xbound, b, safe);
        let p = Self::generate_p(r, xbound, b, safe);

        // Compute n and phi
        let n = p.checked_mul(&q).unwrap();
        let phi = p
            .checked_sub(&BigInt::ONE)
            .unwrap()
            .checked_mul(&q.checked_sub(&BigInt::ONE).unwrap())
            .unwrap();
        let y = Self::sample_nonresidue(n, r, phi);

        return Self::new(PublicKey::new(r, n, y), SecretKey::new(phi));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const RINGSIZE: usize = 16;
    const MODSIZE: usize = 64;
    const SAFEPRIME: bool = false;

    #[test]
    fn test_perfect_keygen() {
        let keypair = KeyPair::keygen(RINGSIZE, MODSIZE, SAFEPRIME);
        assert!(keypair.check_perfect_consonance());
    }
}
