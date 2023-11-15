//! Convenience functions for arithmetics
use crate::{
    keys::{KeyPair, PublicKey},
    BigInt, LIMBS,
};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    CheckedAdd, Random,
};

/// A clear residue contains the value and its decomposition into the residue class and witness
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ClearResidue {
    /// The value itself, as an invertible number (mod n)
    val: DynResidue<LIMBS>,

    /// The residue class that this value belongs to, unique up to (mod r)
    rc: DynResidue<LIMBS>,

    /// The r-th root of val * (y ** -rc); the "x" in w = (y ** c) * (x ** r).
    /// An invertible integer under (mod n)
    witness: DynResidue<LIMBS>,

    /// A copy of the ambient primes (r, n, y)
    /// TODO: convert this into a reference to reduce copying
    ambience: PublicKey,
}

impl ClearResidue {
    pub fn new(
        val: DynResidue<LIMBS>,
        rc: DynResidue<LIMBS>,
        witness: DynResidue<LIMBS>,
        ambience: &PublicKey,
    ) -> Self {
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
    pub fn decompose(val: DynResidue<LIMBS>, keypair: &KeyPair) -> Self {
        let phi_over_r = keypair
            .get_sk()
            .get_phi()
            .checked_div(keypair.get_pk().get_r())
            .unwrap();
        let y_to_phi_over_r = keypair.get_pk().get_y().pow(&phi_over_r).retrieve();
        let val_to_phi_over_r = val.pow(&phi_over_r).retrieve();
        let rc = discrete_log(
            &y_to_phi_over_r,
            &val_to_phi_over_r,
            keypair.get_pk().get_r(),
            keypair.get_pk().get_n(),
        )
        .unwrap();
        let rc = DynResidue::new(&rc, DynResidueParams::new(keypair.get_pk().get_r()));
        let witness = keypair.get_pk().invert_y().unwrap().pow(&rc.retrieve());
        let witness = val.mul(&witness);
        let witness = rth_root(
            witness,
            keypair.get_pk().get_r(),
            keypair.get_sk().get_phi(),
        )
        .unwrap();

        return Self::new(val, rc, witness, keypair.get_pk());
    }

    /// Construct a higher residue from its decomposition
    pub fn compose(
        rc: DynResidue<LIMBS>,
        witness: DynResidue<LIMBS>,
        ambience: &PublicKey,
    ) -> Self {
        let z = witness // z is (x ** r)
            .pow(ambience.get_r());
        let val = ambience.get_y().pow(&rc.retrieve()).mul(&z);
        return Self::new(val, rc, witness, ambience);
    }

    /// Return a reference to the element itself
    pub fn get_val(&self) -> &DynResidue<LIMBS> {
        return &self.val;
    }

    /// Return a reference to the residue class
    pub fn get_rc(&self) -> &DynResidue<LIMBS> {
        return &self.rc;
    }

    /// Return a reference to the witness
    pub fn get_witness(&self) -> &DynResidue<LIMBS> {
        return &self.witness;
    }

    /// Return a reference to the ambience public key
    pub fn get_ambience(&self) -> &PublicKey {
        return &self.ambience;
    }

    /// Generate a random member of Z_n, including its decomposition
    pub fn random(class: Option<DynResidue<LIMBS>>, ambience: &PublicKey) -> Self {
        let r = DynResidueParams::new(ambience.get_r());
        let c = match class {
            Some(class) => class,
            None => DynResidue::new(&BigInt::random(&mut OsRng), r),
        };
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
pub fn rth_root(z: DynResidue<LIMBS>, r: &BigInt, phi: &BigInt) -> Option<DynResidue<LIMBS>> {
    let phi_over_r = phi.checked_div(&r).unwrap();
    let (root_exp, r_invertible) = r.inv_mod(&phi_over_r);
    let r_invertible: bool = r_invertible.into();
    if !r_invertible {
        panic!("r and phi/r not relatively prime");
    }
    let root = z.pow(&root_exp);
    if root.pow(r) == z {
        return Some(root);
    }
    return None;
}

/// Sample a random element from the multiplicative group Z/n
pub fn sample_invertible(modulus: DynResidueParams<LIMBS>) -> DynResidue<LIMBS> {
    loop {
        let val = DynResidue::new(&BigInt::random(&mut OsRng), modulus);
        let (_, invertible) = val.invert();
        if invertible.into() {
            return val;
        }
    }
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
        let one = DynResidue::new(
            &BigInt::ONE,
            DynResidueParams::new(keypair.get_pk().get_n()),
        );
        // 1 is always an r-th residue
        let root = rth_root(one, keypair.get_pk().get_r(), keypair.get_sk().get_phi());
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
            let nonresidue = keypair.get_pk().get_y().pow(&e);
            let nonroot = rth_root(
                nonresidue,
                keypair.get_pk().get_r(),
                keypair.get_sk().get_phi(),
            );
            assert!(nonroot.is_none());
        }
    }
}
