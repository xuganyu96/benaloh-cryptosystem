//! Various interactive proofs
use crate::{keys::KeyPair, BigInt};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};

/// Find the r-th root of z under (mod n). If the root exists, return a root, else return None
/// The root is found using the relation:
///
/// Ar + B(phi/r) = 1
///
/// Note that this relationship only holds if the PublicKey is perfectly consonant
pub fn rth_root(z: BigInt, keypair: KeyPair) -> Option<BigInt> {
    let root_exp = keypair.get_rth_root_exp();
    let root = DynResidue::new(&z, DynResidueParams::new(keypair.get_pk().get_n())).pow(&root_exp);
    if root.pow(keypair.get_pk().get_r()).retrieve() == z {
        return Some(root.retrieve());
    }
    return None;
}

/// Data used for proving that the prover knows the residue class of the statement
/// statement: w = (y^c)(x^r)
/// commit: w' = (y^c')(x'^r)
/// challenge: b = (0, 1, 2, 3, ..., r-1)
/// response: c' + bc
/// verify: ww'y^(-response) is an r-th residue
pub struct ProofOfResidueClass;

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
        let root = rth_root(BigInt::ONE, keypair); // 1 is always an r-th residue
        assert!(root.is_some());

        // y^e for 1 <= e < r is never an r-th residue
        let e = BigInt::random_mod(
            &mut OsRng,
            &NonZero::new(*keypair.get_pk().get_r()).unwrap(),
        );
        let base = DynResidue::new(
            keypair.get_pk().get_y(),
            DynResidueParams::new(keypair.get_pk().get_n()),
        );
        let nonresidue = base.pow(&e);
        let nonroot = rth_root(nonresidue.retrieve(), keypair);
        assert!(nonroot.is_none());
    }
}
