//! Proof of valid parameter (r, n, y), which includes the following steps:
//! 1. Voter generates some random element from the a random residue class
//! 2. Voter provides a proof that it knows the residue class of the challenge ciphertext
//! 3. Government validates the proof; if the proof is invalid, the procedure is aborted
//! 4. Government decomposes the challenge ciphertext and returns the residue class
//! 5. Voter validates that the returned residue class matches the true residue class
use crate::{
    arithmetics::{ClearResidue, OpaqueResidue, ResidueClass},
    keys::{KeyPair, PublicKey},
};
use crypto_bigint::Encoding;
use sha3::{Digest, Sha3_256};

/// The voter's copy of the challenge with answers included
pub struct ClearChallenge {
    /// Each challenge contains many challenge ciphertexts. The number of challenge ciphertexts
    /// is determined by the desired level of confidence.
    challenges: Vec<OpaqueResidue>,
    answers: Vec<ClearResidue>,
    proofs: Vec<VoterProof>,
}

impl ClearChallenge {
    /// Generate a random set of challenge ciphertexts. The number of challenge ciphertexts is
    /// determined by the confidence parameter. Higher confidence parameter means more
    /// challenge ciphertext will be generated.
    pub fn generate(pk: &PublicKey, confidence: usize) -> Self {
        let answers = (0..confidence)
            .map(|_| {
                return ClearResidue::random(None, pk);
            })
            .collect::<Vec<ClearResidue>>();
        let challenges = answers
            .iter()
            .map(|clear| {
                return OpaqueResidue::new(clear.get_val().get_residue().clone());
            })
            .collect::<Vec<OpaqueResidue>>();
        let proofs = answers
            .iter()
            .map(|clear| {
                return VoterProof::from_statement(&clear, pk);
            })
            .collect::<Vec<VoterProof>>();
        return Self {
            challenges,
            answers,
            proofs,
        };
    }

    pub fn get_answers(&self) -> &[ClearResidue] {
        return &self.answers;
    }

    /// Convert the voter's copy of the challenge into the government's copy of the challenge.
    /// All data will be cloned (in practical context data will be transmitted across a network
    /// so cloning is inevitable anyways), although the answers will not be cloned.
    pub fn obscure(&self) -> OpaqueChallenge {
        let challenges = self.challenges.clone();
        let proofs = self.proofs.clone();
        return OpaqueChallenge::new(challenges, proofs);
    }
}

/// The government's copy of the challenge, with answers not included
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct OpaqueChallenge {
    challenges: Vec<OpaqueResidue>,
    proofs: Vec<VoterProof>,
}

impl OpaqueChallenge {
    pub fn new(challenges: Vec<OpaqueResidue>, proofs: Vec<VoterProof>) -> Self {
        return Self { challenges, proofs };
    }

    pub fn get_challenges(&self) -> &[OpaqueResidue] {
        return &self.challenges;
    }

    /// Return True iff all of the proofs can be verified
    pub fn verify_proofs(&self, keypair: &KeyPair) -> bool {
        return self.proofs.iter().all(|proof| {
            return proof.verify(&keypair);
        });
    }
}

/// Voter's proof of knowledge, adapted to be offline using Fiat-Shamir
/// The statement is an opaque residue: w = (y ** c)(x ** r)
/// The commitment is an opaque residue: w' = (y ** c')(x' ** r)
/// The challenge b is obtained by hashing the commit into an element from the ring Z/r
/// The response is c' + bc
///
/// To verify that the response is valid, compute w'(w ** b)((y ** -1) ** (c' + bc)) and check
/// that the result is an r-th residue. Checking that the result is an r-th residue is possible
/// because the verifier is the government, who has the secret key
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct VoterProof {
    /// The opaque residue that the voter claims to know the residue class of
    statement: OpaqueResidue,

    /// The opaque residue that is used as the commitment
    commitment: OpaqueResidue,

    challenge: ResidueClass,

    response: ResidueClass,
}

impl VoterProof {
    /// Construct the proof from the statement. Note that an honest prover should possess the
    /// secret knowledge (of the residue class), so even though the output of the proof will
    /// obscure the residue class of the statement, the construction requires a clear residue.
    pub fn from_statement(statement: &ClearResidue, pk: &PublicKey) -> Self {
        let commitment = Self::generate_commitment(pk);
        let challenge = Self::generate_challenge(commitment.get_val(), pk);
        let response = Self::respond(statement, &commitment, &challenge);
        return Self {
            statement: statement.clone_val(),
            commitment: commitment.clone_val(),
            challenge,
            response,
        };
    }

    /// Generate the opaque residue as the commitment. This method is called by the prover, so
    /// the prover knows the residue class of the commitment. The transcript (the proof
    /// struct itself) will not reveal the residue class of the commitment
    fn generate_commitment(pk: &PublicKey) -> ClearResidue {
        return ClearResidue::random(None, pk);
    }

    /// Hash the commitment into the challenge
    fn generate_challenge(commitment: &OpaqueResidue, pk: &PublicKey) -> ResidueClass {
        let mut hasher = Sha3_256::new();
        hasher.update(commitment.retrieve().to_be_bytes());
        let hash: Vec<u8> = hasher.finalize().to_vec();
        let challenge = ResidueClass::from_be_bytes(&hash, pk.get_r());
        return challenge;
    }

    /// Compute the response based on the statement, commitment, and the challenge
    /// The response takes the form (c' + b * c)
    fn respond(
        statement: &ClearResidue,
        commitment: &ClearResidue,
        challenge: &ResidueClass,
    ) -> ResidueClass {
        return statement.clone_rc() * challenge.clone() + commitment.clone_rc();
    }

    /// Given a public transcript of the proof, check whether the proof is valid
    /// Verification uses the the fact that if the prover is honest, then the following
    /// quantity is an r-th residue
    /// v = (commit * statement ** challenge) * ((y ** -1) ** response)
    /// To verify something to be an r-th residue, the secret key is needed, which is okay
    /// because the government indeed has the secret key
    pub fn verify(&self, keypair: &KeyPair) -> bool {
        // z should be an r-th residue
        let z = self.commitment
            * self.statement.pow(&self.challenge)
            * keypair.get_pk().invert_y().pow(&self.response);
        let z = ClearResidue::decompose(z.clone_residue(), keypair);
        return z.is_exact_residue();
    }
}

/// The government's proof of being able to identify the residue class
pub struct GovernmentProof {
    statement: PublicKey,
    challenge: OpaqueChallenge,
    response: Option<Vec<ClearResidue>>,
}

impl GovernmentProof {
    pub fn new(
        statement: PublicKey,
        challenge: OpaqueChallenge,
        response: Option<Vec<ClearResidue>>,
    ) -> Self {
        return Self {
            statement,
            challenge,
            response,
        };
    }

    /// if the voter's proofs are valid, then decompose the opaque residue in the challenges
    /// if any of the voter's proofs is invalid, return nothing
    pub fn respond(challenge: &OpaqueChallenge, keypair: &KeyPair) -> Self {
        if !challenge.verify_proofs(keypair) {
            return Self::new(keypair.get_pk().clone(), challenge.clone(), None);
        }

        let answers = challenge
            .get_challenges()
            .iter()
            .map(|opaque| {
                return ClearResidue::decompose(opaque.clone_residue(), keypair);
            })
            .collect::<Vec<ClearResidue>>();
        return Self::new(keypair.get_pk().clone(), challenge.clone(), Some(answers));
    }

    pub fn verify(&self, answers: &[ClearResidue]) -> bool {
        match &self.response {
            None => todo!("How to verify if proof fails?"),
            Some(decryptions) => {
                if decryptions.len() != answers.len() {
                    return false;
                } else {
                    return decryptions
                        .iter()
                        .zip(answers.iter())
                        .all(|(decrypt, answer)| decrypt.get_rc() == answer.get_rc());
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_proofs() {
        let keypair = KeyPair::keygen(16, 64, false);
        let voter_challenge = ClearChallenge::generate(keypair.get_pk(), 64);
        let opaque_challenge = voter_challenge.obscure();
        assert!(opaque_challenge.verify_proofs(&keypair));
    }

    /// An honest voter should be able to generate a verifiable VoterProof
    #[test]
    fn test_voter_proof_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let statement = ClearResidue::random(None, keypair.get_pk());
        let proof = VoterProof::from_statement(&statement, keypair.get_pk());
        assert!(proof.verify(&keypair));
    }

    /// Test that a pair of honest voter and government can verify each other's proofs
    #[test]
    fn test_gov_proof_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let voter_challenge = ClearChallenge::generate(keypair.get_pk(), 16);
        let opaque_challenge = voter_challenge.obscure();
        let gov_proof = GovernmentProof::respond(&opaque_challenge, &keypair);
        assert!(gov_proof.verify(voter_challenge.get_answers()));
    }
}
