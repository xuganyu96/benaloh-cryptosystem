//! Convenience functions for arithmetics
use crate::{
    keys::{KeyPair, PublicKey},
    BigInt,
};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    CheckedAdd, CheckedMul, NonZero, RandomMod,
};

/// The principle unit of arithmetic in Benaloh's cryptosystem.
/// A residue is an element of the multiplicative group Z/n, but because the triplet (r, n, y) is
/// perfect consonance, every element has unique representation:
/// w = y^cx^r
/// for some 0 <= c < r and some x in Z/n.
///
/// NOTE: this is basically a "transparent" ciphertext. We will probably need a opaque ciphertext
#[derive(Debug, Eq, PartialEq)]
pub struct HigherResidue {
    /// The value itself
    val: BigInt,

    /// The residue class, that this value belongs to
    rc: BigInt,

    /// The witness, which is an r-th root of val * (y ** rc) (mod n)
    witness: BigInt,

    /// A copy of the ambient primes (r, n, y)
    /// TODO: convert this into a reference to reduce copying
    ambience: PublicKey,
}

impl HigherResidue {
    pub fn new(val: BigInt, rc: BigInt, witness: BigInt, ambience: &PublicKey) -> Self {
        let ambience = ambience.clone();
        return Self {
            val,
            rc,
            witness,
            ambience,
        };
    }

    /// Decompose an opaque value into its residual representation (c, x)
    /// Such decomposition is equivalent to decrypting a ciphertext, hence the requirement for a
    /// complete keypair instead of just the public key
    ///
    /// The decomposition takes advantage of the fact that raising a r-th residue to the power of
    /// (phi/n) gives 1 (mod n) by Euler's theorem. From here, we can use a brute-force discrete
    /// log algorithm to find the value of the residue class. Finally, onec the residue class is
    /// found, we can recover the witness.
    pub fn decompose(val: BigInt, keypair: &KeyPair) -> Self {
        let phi_over_r = keypair
            .get_sk()
            .get_phi()
            .checked_div(keypair.get_pk().get_r())
            .unwrap();
        let n = DynResidueParams::new(keypair.get_pk().get_n());
        let y_to_phi_over_r = DynResidue::new(keypair.get_pk().get_y(), n)
            .pow(&phi_over_r)
            .retrieve();
        let val_to_phi_over_r = DynResidue::new(&val, n).pow(&phi_over_r).retrieve();
        let rc = discrete_log(
            &y_to_phi_over_r,
            &val_to_phi_over_r,
            keypair.get_pk().get_r(),
            keypair.get_pk().get_n(),
        )
        .unwrap();
        let witness = DynResidue::new(&keypair.get_pk().invert_y(), n)
            .pow(&rc)
            .retrieve();
        let witness = val.checked_mul(&witness).unwrap();
        let witness = rth_root(witness, keypair).unwrap();

        return Self::new(val, rc, witness, keypair.get_pk());
    }

    /// Construct a higher residue from its decomposition
    pub fn compose(rc: BigInt, witness: BigInt, ambience: &PublicKey) -> Self {
        let n = DynResidueParams::new(ambience.get_n());
        let z = DynResidue::new(&witness, n) // z is (x ** r)
            .pow(ambience.get_r());
        let val = DynResidue::new(ambience.get_y(), n)
            .pow(&rc)
            .mul(&z)
            .retrieve();
        return Self::new(val, rc, witness, ambience);
    }

    /// Return a reference to the element itself
    pub fn get_val(&self) -> &BigInt {
        return &self.val;
    }

    /// Return a reference to the residue class
    pub fn get_rc(&self) -> &BigInt {
        return &self.rc;
    }

    /// Return a reference to the witness
    pub fn get_witness(&self) -> &BigInt {
        return &self.witness;
    }

    /// Return a reference to the ambience public key
    pub fn get_ambience(&self) -> &PublicKey {
        return &self.ambience;
    }

    /// Generate a random member of Z_n, including its decomposition
    pub fn random(ambience: &PublicKey) -> Self {
        let r = NonZero::new(ambience.get_r().clone()).unwrap();
        let c = BigInt::random_mod(&mut OsRng, &r);
        let x = ambience.sample_invertible();
        return Self::compose(c, x, ambience);
    }
}

/// Find the r-th root of z under (mod n). If the root exists, return a root, else return None
/// The root is found using the relation:
///
/// Ar + B(phi/r) = 1
///
/// Note that this relationship only holds if the PublicKey is perfectly consonant.
/// Also note that this can also be used to check that something is an r-th residue
pub fn rth_root(z: BigInt, keypair: &KeyPair) -> Option<BigInt> {
    let root_exp = keypair.get_rth_root_exp();
    let root = DynResidue::new(&z, DynResidueParams::new(keypair.get_pk().get_n())).pow(&root_exp);
    if root.pow(keypair.get_pk().get_r()).retrieve() == z {
        return Some(root.retrieve());
    }
    return None;
}

/// Brute-force discrete log given that the base has small order under the modulus.
/// If no discrete log can be found, return None;
pub fn discrete_log(
    base: &BigInt,
    target: &BigInt,
    order: &BigInt,
    modulus: &BigInt,
) -> Option<BigInt> {
    let mut exp = BigInt::ZERO;
    let modulus = DynResidueParams::new(modulus);
    let base = DynResidue::new(base, modulus);
    let target = DynResidue::new(target, modulus);

    while exp < *order {
        if base.pow(&exp) == target {
            return Some(exp);
        }
        exp = exp.checked_add(&BigInt::ONE).unwrap();
    }
    return None;
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{rand_core::OsRng, NonZero, RandomMod};

    use super::*;
    const RINGSIZE: usize = 16;
    const MODSIZE: usize = 64;
    const SAFEPRIME: bool = false;

    /// Test computing r-th root by checking that the residue class RC[0] has roots while
    /// all other classes have no roots
    #[test]
    fn test_rth_root() {
        let keypair = KeyPair::keygen(RINGSIZE, MODSIZE, SAFEPRIME);
        let root = rth_root(BigInt::ONE, &keypair); // 1 is always an r-th residue
        assert!(root.is_some());

        // y^e for 1 <= e < r is never an r-th residue
        for _ in 1..100 {
            let e = BigInt::random_mod(
                &mut OsRng,
                &NonZero::new(*keypair.get_pk().get_r()).unwrap(),
            );
            if e == BigInt::ZERO {
                continue;
            }
            let base = DynResidue::new(
                keypair.get_pk().get_y(),
                DynResidueParams::new(keypair.get_pk().get_n()),
            );
            let nonresidue = base.pow(&e);
            let nonroot = rth_root(nonresidue.retrieve(), &keypair);
            assert!(nonroot.is_none());
        }
    }
}
