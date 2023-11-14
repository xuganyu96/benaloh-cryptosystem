//! This is the first of the two interactive proofs used for challenging the validity fo the
//! parameters, where the voter proves to the government that the voter knows the residue class of
//! the challenge ciphertext. This proof is needed before the government proceeds to show the
//! validity of the parameters by correctly determining the residue class
//! statement: w = (y^c)(x^r)
//! commit: w' = (y^c')(x'^r)
//! challenge: b <- 0..r
//! response: c' + bc
//! verify: w^bw'y^(c' + bc) is an r-th residue
//!
//! TODO: Increase the confidence of each proof by using a larger commit

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    rand_core::OsRng,
    CheckedAdd, CheckedMul, NonZero, RandomMod,
};

use crate::{
    arithmetics::{rth_root, HigherResidue},
    keys::KeyPair,
    BigInt,
};

/// The data used by the prover
#[derive(Debug, Eq, PartialEq)]
pub struct Proof {
    statement: HigherResidue,
    commit: HigherResidue,
}

impl Proof {
    /// Convenience function for instantiating an instance
    pub fn new(statement: HigherResidue, commit: HigherResidue) -> Self {
        return Self { statement, commit };
    }

    pub fn get_statement(&self) -> &HigherResidue {
        return &self.statement;
    }

    pub fn get_commit(&self) -> &HigherResidue {
        return &self.commit;
    }

    /// Instantiate with a statement alone. The commit will be randomly generated
    pub fn from_statement(statement: HigherResidue) -> Self {
        let commit = HigherResidue::random(None, statement.get_ambience());
        return Self::new(statement, commit);
    }

    /// Generate a new instance of a commit and replace the old commit
    pub fn refresh_commit(&mut self) {
        let commit = HigherResidue::random(None, self.get_statement().get_ambience());
        self.commit = commit;
    }

    /// Respond to a challenge
    pub fn respond(&self, challenge: &Challenge) -> BigInt {
        let c_prime = self.commit.get_rc();
        let c_true = self.statement.get_rc();
        return c_prime
            .checked_add(&c_true.checked_mul(challenge.get_challenge()).unwrap())
            .unwrap();
    }
}

/// The data used by the verifier
#[derive(Debug, Eq, PartialEq)]
pub struct Challenge {
    /// The challenge "b", an element of the integer ring Z/r
    challenge: BigInt,

    /// In the context of this proof, the verifier needs the secret key (particularly phi) to
    /// decide whether the response leads to a valid r-th residue
    /// TODO: Turn this into a reference to reduce copying
    keypair: KeyPair,
}

impl Challenge {
    pub fn new(challenge: BigInt, keypair: KeyPair) -> Self {
        return Self { challenge, keypair };
    }

    /// Generate a random challenge
    pub fn generate(keypair: KeyPair) -> Self {
        let r = NonZero::new(keypair.get_pk().get_r().clone()).unwrap();
        let challenge = BigInt::random_mod(&mut OsRng, &r);

        return Self::new(challenge, keypair);
    }

    /// Get a copy of the challenge
    pub fn get_challenge(&self) -> &BigInt {
        return &self.challenge;
    }

    /// Return true iff the response is valid
    /// The response is valid for the proof if and only if:
    /// (statement) * (commit) / (y ** response) is an r-th residue
    pub fn verify(&self, proof: &Proof, response: &BigInt) -> bool {
        let n = DynResidueParams::new(self.keypair.get_pk().get_n());
        let y_inv = DynResidue::new(&self.keypair.get_pk().invert_y(), n);
        let statement = DynResidue::new(proof.get_statement().get_val(), n);
        let commit = DynResidue::new(proof.get_commit().get_val(), n);
        let witness = statement
            .pow(self.get_challenge())
            .mul(&commit)
            .mul(&y_inv.pow(response))
            .retrieve();
        return rth_root(witness, &self.keypair).is_some();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a honest verifier can verify an honest prover
    #[test]
    fn test_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let proof = Proof::from_statement(HigherResidue::random(None, keypair.get_pk()));
        let challenge = Challenge::generate(keypair.clone());
        assert!(challenge.verify(&proof, &proof.respond(&challenge)));
    }
}
