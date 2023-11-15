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
    NonZero, RandomMod,
};

use crate::{
    arithmetics::{rth_root, ClearResidue},
    keys::KeyPair,
    BigInt, LIMBS,
};

/// The data used by the prover
#[derive(Debug, Eq, PartialEq)]
pub struct Proof {
    statement: ClearResidue,
    commit: ClearResidue,
}

impl Proof {
    /// Convenience function for instantiating an instance
    pub fn new(statement: ClearResidue, commit: ClearResidue) -> Self {
        return Self { statement, commit };
    }

    pub fn get_statement(&self) -> &ClearResidue {
        return &self.statement;
    }

    pub fn get_commit(&self) -> &ClearResidue {
        return &self.commit;
    }

    /// Instantiate with a statement alone. The commit will be randomly generated
    pub fn from_statement(statement: ClearResidue) -> Self {
        let commit = ClearResidue::random(None, statement.get_ambience());
        return Self::new(statement, commit);
    }

    /// Generate a new instance of a commit and replace the old commit
    pub fn refresh_commit(&mut self) {
        let commit = ClearResidue::random(None, self.get_statement().get_ambience());
        self.commit = commit;
    }

    /// Respond to a challenge
    pub fn respond(&self, challenge: &Challenge) -> DynResidue<LIMBS> {
        let c_prime = self.commit.get_rc();
        let c_true = self.statement.get_rc();
        return c_prime.add(&c_true.mul(challenge.get_challenge()));
    }
}

/// The data used by the verifier
#[derive(Debug, Eq, PartialEq)]
pub struct Challenge {
    /// The challenge "b", an element of the integer ring Z/r
    challenge: DynResidue<LIMBS>,

    /// In the context of this proof, the verifier needs the secret key (particularly phi) to
    /// decide whether the response leads to a valid r-th residue
    /// TODO: Turn this into a reference to reduce copying
    keypair: KeyPair,
}

impl Challenge {
    pub fn new(challenge: DynResidue<LIMBS>, keypair: KeyPair) -> Self {
        return Self { challenge, keypair };
    }

    /// Generate a random challenge
    pub fn generate(keypair: &KeyPair) -> Self {
        let r = NonZero::new(keypair.get_pk().get_r().clone()).unwrap();
        let challenge = BigInt::random_mod(&mut OsRng, &r);
        let challenge =
            DynResidue::new(&challenge, DynResidueParams::new(keypair.get_pk().get_r()));

        return Self::new(challenge, keypair.clone());
    }

    /// Get a copy of the challenge
    pub fn get_challenge(&self) -> &DynResidue<LIMBS> {
        return &self.challenge;
    }

    /// Return true iff the response is valid
    /// The response is valid for the proof if and only if:
    /// (statement) * (commit) / (y ** response) is an r-th residue
    pub fn verify(&self, proof: &Proof, response: &DynResidue<LIMBS>) -> bool {
        let y_inv = &self.keypair.get_pk().invert_y().unwrap();
        let statement = proof.get_statement().get_val();
        let commit = proof.get_commit().get_val();
        let witness = statement
            .pow(&self.get_challenge().retrieve())
            .mul(&commit)
            .mul(&y_inv.pow(&response.retrieve()));
        return rth_root(
            witness,
            self.keypair.get_pk().get_r(),
            self.keypair.get_sk().get_phi(),
        )
        .is_some();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a honest verifier can verify an honest prover
    #[test]
    fn test_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let proof = Proof::from_statement(ClearResidue::random(None, keypair.get_pk()));
        let challenge = Challenge::generate(&keypair);
        assert!(challenge.verify(&proof, &proof.respond(&challenge)));
    }
}
