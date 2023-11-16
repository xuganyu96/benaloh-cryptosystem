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
use std::ops::{Add, Deref, Mul, Neg};

/// A ring modulus defines the integer ring (mod r). Integer addition and multiplication are
/// defined. Not all integers are invertible. Ring modulus is usually used as exponents,
/// such as residue classes
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct RingModulus(DynResidueParams<LIMBS>);

impl Deref for RingModulus {
    type Target = DynResidueParams<LIMBS>;

    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}

impl RingModulus {
    /// Clone the inner dynamic residue parameter
    pub fn to_dyn_residue_params(&self) -> DynResidueParams<LIMBS> {
        return self.0.clone();
    }

    /// Clone the inner big integer
    pub fn to_uint(&self) -> BigInt {
        return self.0.modulus().clone();
    }

    /// Sample a random element in the integer ring
    pub fn sample(&self) -> DynResidue<LIMBS> {
        return DynResidue::new(&BigInt::random(&mut OsRng), self.to_dyn_residue_params());
    }

    pub fn new(modulus: DynResidueParams<LIMBS>) -> Self {
        return Self(modulus);
    }
}

/// A group modulus defines the multiplicative group Z/n of invertible elements.
/// With group modulus, multiplication is the only defined operation. All elements are invertible
/// so we can sample from them
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct GroupModulus(DynResidueParams<LIMBS>);

impl Deref for GroupModulus {
    type Target = DynResidueParams<LIMBS>;

    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}

impl GroupModulus {
    /// Clone the inner dynamic residue parameter
    pub fn to_dyn_residue_params(&self) -> DynResidueParams<LIMBS> {
        return self.0.clone();
    }

    /// Clone the inner big integer
    pub fn to_uint(&self) -> BigInt {
        return self.0.modulus().clone();
    }

    /// Sample a random invertible element
    pub fn sample(&self) -> DynResidue<LIMBS> {
        loop {
            let val = DynResidue::new(&BigInt::random(&mut OsRng), self.to_dyn_residue_params());
            let (_, invertible) = val.invert();
            if invertible.into() {
                return val;
            }
        }
    }

    pub fn new(modulus: DynResidueParams<LIMBS>) -> Self {
        return Self(modulus);
    }

    pub fn from_uint(modulus: &BigInt) -> Self {
        return Self(DynResidueParams::new(modulus));
    }
}

/// A residue class is an element of the integer ring Z/r
#[derive(Debug, Copy, Clone)]
pub struct ResidueClass(DynResidue<LIMBS>);

impl PartialEq for ResidueClass {
    fn eq(&self, other: &Self) -> bool {
        self.0.retrieve() == other.0.retrieve()
    }
}

impl Eq for ResidueClass {}

impl Deref for ResidueClass {
    type Target = DynResidue<LIMBS>;

    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}

impl Neg for ResidueClass {
    type Output = ResidueClass;

    fn neg(self) -> Self::Output {
        return Self::new(-self.0);
    }
}

impl ResidueClass {
    pub fn new(class: DynResidue<LIMBS>) -> Self {
        return Self(class);
    }

    pub fn zero(params: DynResidueParams<LIMBS>) -> Self {
        return Self::new(DynResidue::new(&BigInt::ZERO, params));
    }

    pub fn one(params: DynResidueParams<LIMBS>) -> Self {
        return Self::new(DynResidue::new(&BigInt::ONE, params));
    }

    pub fn from_be_bytes(bytes: &[u8], modulus: &RingModulus) -> Self {
        let val = BigInt::from_be_slice(bytes);
        let residue = DynResidue::new(&val, modulus.to_dyn_residue_params());
        return Self::new(residue);
    }

    pub fn get_residue(&self) -> &DynResidue<LIMBS> {
        return &self.0;
    }

    pub fn clone_residue(&self) -> DynResidue<LIMBS> {
        return self.0.clone();
    }
}

impl Mul<ResidueClass> for ResidueClass {
    type Output = ResidueClass;

    fn mul(self, rhs: ResidueClass) -> Self::Output {
        let product = self.0.mul(rhs.0);
        return Self::new(product);
    }
}

impl Add<ResidueClass> for ResidueClass {
    type Output = ResidueClass;

    fn add(self, rhs: ResidueClass) -> Self::Output {
        return Self::new(self.0.add(rhs.0));
    }
}

/// An opaque residue is an element of the multiplicative group Z/n with no further information
/// such as the decomposition. Ciphertexts are opaque residues
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct OpaqueResidue(DynResidue<LIMBS>);

impl Deref for OpaqueResidue {
    type Target = DynResidue<LIMBS>;

    fn deref(&self) -> &Self::Target {
        return &self.0;
    }
}

impl Mul<OpaqueResidue> for OpaqueResidue {
    type Output = OpaqueResidue;

    fn mul(self, rhs: OpaqueResidue) -> Self::Output {
        return OpaqueResidue::new(self.0.mul(rhs.0));
    }
}

impl OpaqueResidue {
    pub fn new(residue: DynResidue<LIMBS>) -> Self {
        return Self(residue);
    }

    pub fn get_residue(&self) -> &DynResidue<LIMBS> {
        return &self.0;
    }

    pub fn clone_residue(&self) -> DynResidue<LIMBS> {
        return self.0.clone();
    }

    pub fn pow(&self, exponent: &ResidueClass) -> Self {
        return Self::new(self.0.pow(&exponent.retrieve()));
    }

    /// A wrapper around DynResidue::invert. Will exhibit undefined behavior if not invertible
    pub fn invert(&self) -> Self {
        let (inverse, _) = self.0.invert();
        return Self::new(inverse);
    }
}

/// A clear residue contains the value and its decomposition into the residue class and witness
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ClearResidue {
    /// The value itself, as an invertible number (mod n)
    val: OpaqueResidue,

    /// The residue class that this value belongs to, unique up to (mod r)
    rc: ResidueClass,

    /// The r-th root of val * (y ** -rc); the "x" in w = (y ** c) * (x ** r).
    /// An invertible integer under (mod n)
    witness: OpaqueResidue,

    /// A copy of the ambient primes (r, n, y)
    /// TODO: convert this into a reference to reduce copying
    ambience: PublicKey,
}

impl Mul<ClearResidue> for ClearResidue {
    type Output = ClearResidue;

    fn mul(self, rhs: ClearResidue) -> Self::Output {
        let val = self.clone_val() * rhs.clone_val();
        let rc = self.clone_rc() + rhs.clone_rc();
        let witness = self.clone_witness() * rhs.clone_witness();

        return Self::new(val, rc, witness, self.get_ambience());
    }
}

impl ClearResidue {
    pub fn new(
        val: OpaqueResidue,
        rc: ResidueClass,
        witness: OpaqueResidue,
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

    pub fn is_exact_residue(&self) -> bool {
        return self.get_rc().retrieve() == BigInt::ZERO;
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
        let phi_over_r = keypair.phi_over_r();
        let y_to_phi_over_r = keypair.get_pk().get_y().pow(&phi_over_r).retrieve();
        let val_to_phi_over_r = val.pow(&phi_over_r).retrieve();
        let rc = discrete_log(
            &y_to_phi_over_r,
            &val_to_phi_over_r,
            keypair.get_pk().get_r().modulus(),
            keypair.get_pk().get_n().modulus(),
        )
        .unwrap();
        let rc = ResidueClass::new(DynResidue::new(
            &rc,
            keypair.get_pk().get_r().to_dyn_residue_params(),
        ));
        let witness = keypair.get_pk().invert_y().pow(&rc);
        let witness = OpaqueResidue::new(val).mul(witness);
        let witness = rth_root(
            witness.clone_residue(),
            keypair.get_pk().get_r().modulus(),
            keypair.get_sk().get_phi(),
        )
        .unwrap();
        let witness = OpaqueResidue::new(witness);

        return Self::new(OpaqueResidue::new(val), rc, witness, keypair.get_pk());
    }

    /// Construct a higher residue from its decomposition
    pub fn compose(
        rc: DynResidue<LIMBS>,
        witness: DynResidue<LIMBS>,
        ambience: &PublicKey,
    ) -> Self {
        let z = witness // z is (x ** r)
            .pow(ambience.get_r().modulus());
        let val = OpaqueResidue::new(ambience.get_y().pow(&rc.retrieve()).mul(&z));
        let rc = ResidueClass::new(rc);
        let witness = OpaqueResidue::new(witness);
        return Self::new(val, rc, witness, ambience);
    }

    /// Raise a residue to the power of the residue class
    pub fn pow(&self, exponent: &ResidueClass) -> Self {
        let val = self.get_val().pow(exponent);
        let witness = self.get_witness().pow(exponent);
        let rc = self.clone_rc() * exponent.clone();

        return Self::new(val, rc, witness, self.get_ambience());
    }

    /// Return a reference to the element itself
    pub fn get_val(&self) -> &OpaqueResidue {
        return &self.val;
    }

    /// Clone the opaque value
    pub fn clone_val(&self) -> OpaqueResidue {
        return self.val.clone();
    }

    /// Return a reference to the residue class
    pub fn get_rc(&self) -> &ResidueClass {
        return &self.rc;
    }

    /// Return a copy to the residue class
    pub fn clone_rc(&self) -> ResidueClass {
        return self.rc.clone();
    }

    /// Return a reference to the witness
    pub fn get_witness(&self) -> &OpaqueResidue {
        return &self.witness;
    }

    /// Clone the witness
    pub fn clone_witness(&self) -> OpaqueResidue {
        return self.witness.clone();
    }

    /// Return a reference to the ambience public key
    pub fn get_ambience(&self) -> &PublicKey {
        return &self.ambience;
    }

    /// Generate a random member of Z_n, including its decomposition
    pub fn random(class: Option<DynResidue<LIMBS>>, ambience: &PublicKey) -> Self {
        let c = match class {
            Some(class) => class,
            None => ambience.get_r().sample(),
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
            keypair.get_pk().get_n().to_dyn_residue_params(),
        );
        // 1 is always an r-th residue
        let root = rth_root(
            one,
            keypair.get_pk().get_r().modulus(),
            keypair.get_sk().get_phi(),
        );
        assert!(root.is_some());

        // y^e for 1 <= e < r is never an r-th residue
        for _ in 1..100 {
            let e = BigInt::random_mod(
                &mut OsRng,
                &NonZero::new(keypair.get_pk().get_r().modulus().clone()).unwrap(),
            );
            if e == BigInt::ZERO {
                continue;
            }
            let nonresidue = keypair.get_pk().get_y().pow(&e);
            let nonroot = rth_root(
                nonresidue,
                keypair.get_pk().get_r().modulus(),
                keypair.get_sk().get_phi(),
            );
            assert!(nonroot.is_none());
        }
    }
}
