//! Various interactive proofs
use crate::{BigInt, keys::PublicKey};


/// Find the r-th root of z under (mod n). If the root exists, return a root, else return None
/// The root is found using the relation:
///
/// Ar + B(phi/r) = 1
///
/// Note that this relationship only holds if the PublicKey is perfectly consonant
fn rth_root(z: BigInt, pk: PublicKey) -> Option<BigInt> {
    todo!();
}

/// Data used for proving that the prover knows the residue class of the statement
/// statement: w = (y^c)(x^r)
/// commit: w' = (y^c')(x'^r)
/// challenge: b = (0, 1, 2, 3, ..., r-1)
/// response: c' + bc
/// verify: ww'y^(-response) is an r-th residue
pub struct ProofOfResidueClass;
