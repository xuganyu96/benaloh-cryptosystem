//! The key pairs
use crate::{
    arithmetics::{self, GroupModulus, OpaqueResidue, RingModulus},
    BigInt, LIMBS,
};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    CheckedAdd, CheckedMul, CheckedSub, NonZero, RandomMod,
};

/// The public key includes the ring size r, and group modulus n, and the residue class
/// discriminator y. In this implementation, a public key is always a perfect consonance, meaning
/// 1. r divides phi
/// 2. r and phi/r are relatively prime
/// 3. r is a prime number
/// 4. y is an invertible element but not an r-th residue
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct PublicKey {
    r: RingModulus,

    n: GroupModulus,

    /// y is an element of the multiplicative group Z/n, but with the type DynResidue instead of a
    /// naked BigInt
    /// TODO: replace this with OpaqueResidue
    y: OpaqueResidue,
}

impl PublicKey {
    /// Instantiate an instance with no check
    pub fn new(r: RingModulus, n: GroupModulus, y: OpaqueResidue) -> Self {
        return Self { r, n, y };
    }

    pub fn get_r(&self) -> &RingModulus {
        &self.r
    }

    pub fn get_n(&self) -> &GroupModulus {
        &self.n
    }

    pub fn get_y(&self) -> &DynResidue<LIMBS> {
        &self.y
    }

    /// Return the multiplicative inverse of y. This inverse should always exist y is sampled from
    /// the multiplicative group
    pub fn invert_y(&self) -> OpaqueResidue {
        return self.y.invert();
    }

    /// Sample a random element from the multiplicative group Z/n
    pub fn sample_invertible(&self) -> DynResidue<LIMBS> {
        return arithmetics::sample_invertible(self.get_n().to_dyn_residue_params());
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
    fn generate_p(r: &BigInt, xbound: BigInt, b: BigInt, safe: bool) -> BigInt {
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
    fn generate_q(r: &BigInt, xbound: BigInt, b: BigInt, safe: bool) -> BigInt {
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

    /// Sample a non-residue. A non-residue is an invertible element such that
    /// y^{phi/r} != 1 (mod n)
    fn sample_nonresidue(modulus: &GroupModulus, r: &BigInt, phi: &BigInt) -> OpaqueResidue {
        let quotient = phi.checked_div(r).unwrap();
        let modulus = modulus.to_dyn_residue_params();

        loop {
            let y = arithmetics::sample_invertible(modulus);
            if y.pow(&quotient).retrieve() != BigInt::ONE {
                return OpaqueResidue::new(y);
            }
        }
    }

    /// Assuming that (r, n, y) is prime consonance, check that it is also perfect consonance.
    /// Perfect consonance is defined by two conditions:
    /// 1. r divides phi
    /// 2. r and phi/r are relatively prime
    pub fn check_perfect_consonance(&self) -> bool {
        let r = self.get_pk().get_r().modulus().clone();
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
    pub fn keygen(ring_size: usize, group_size: usize, safe: bool) -> Self {
        let r: BigInt = crypto_primes::generate_prime(Some(ring_size));
        let r = RingModulus::new(DynResidueParams::new(&r));
        let xbound = DynResidue::new(&BigInt::from_u8(2), DynResidueParams::new(&BigInt::MAX))
            .pow(&BigInt::from_u64(group_size as u64))
            .retrieve(); // x is the dominant term in the arithmetic sequence
                         // Generate the non-zero remainder in the arithmetic sequence

        // Generate the remainder term "b"
        let mut b = r.sample();
        while b.retrieve() == BigInt::ZERO {
            b = r.sample();
        }
        let b = b.retrieve();

        let q = Self::generate_q(r.modulus(), xbound, b, safe);
        let p = Self::generate_p(r.modulus(), xbound, b, safe);

        // Compute n and phi
        let n = GroupModulus::from_uint(&p.checked_mul(&q).unwrap());
        let phi = p
            .checked_sub(&BigInt::ONE)
            .unwrap()
            .checked_mul(&q.checked_sub(&BigInt::ONE).unwrap())
            .unwrap();
        let y = Self::sample_nonresidue(&n, r.modulus(), &phi);

        return Self::new(PublicKey::new(r, n, y), SecretKey::new(phi));
    }

    /// A convenience method for computing the quantity phi/r (over the integers).
    /// This quantity is guaranteed to be well-defined because this key pair generation ensures
    /// that (r, n, y) is a perfect consonance
    pub fn phi_over_r(&self) -> BigInt {
        let phi = self.get_sk().get_phi();
        let r = self.get_pk().get_r().modulus();
        return phi.checked_div(r).unwrap();
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
