//! Proof of residue class decidability
//! This is the second half of the proof that (r, n, y) are consonant. In this half of the proof
//! the government demonstrates that it can correctly identify the residue class of the challenge
//! higher residue. Unfortunately we don't have a good way to convert this proof into a sigma
//! protocol so the entire implementation is custom
//!
//! TODO: Increase the confidence of each proof by using a larger commit

use crate::{
    arithmetics::ClearResidue,
    keys::{KeyPair, PublicKey},
    BigInt,
};

/// The challenge ciphertext is a transparent high residue (where the residue class is known).
pub struct Challenge {
    challenge: ClearResidue,
}

impl Challenge {
    pub fn new(challenge: ClearResidue) -> Self {
        return Self { challenge };
    }

    pub fn generate(pk: &PublicKey) -> Self {
        let challenge = ClearResidue::random(None, pk);
        return Self::new(challenge);
    }

    pub fn get_challenge(&self) -> &ClearResidue {
        return &self.challenge;
    }

    /// Verify that the response is the correct residue class. This function assumes that the
    /// response is an integer mod r
    pub fn verify(&self, response: &BigInt) -> bool {
        return self.challenge.get_rc().retrieve() == *response;
    }
}

/// The prover possesses the keypair, which is used to decompose the challenge ciphertext into the
/// residue class and the witness
pub struct Proof;

impl Proof {
    pub fn respond(challenge: &Challenge, keypair: &KeyPair) -> BigInt {
        let challenge = challenge.get_challenge().get_val();
        let decomp = ClearResidue::decompose(challenge.clone(), &keypair);
        return decomp.get_rc().retrieve();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Check that an honest prover can pass an honest verification
    #[test]
    fn test_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let challenge = Challenge::generate(keypair.get_pk());
        assert!(challenge.verify(&Proof::respond(&challenge, &keypair)));
    }
}
