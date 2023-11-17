//! Interactive proof that the ballot is in RC[0] or RC[1].
//! In fact, there is nothing special about RC[0] or RC[1], so this implementation is for proving
//! that the ciphertext is in one of the specified residue class
//!
//! The statement of the proof is a single higher residue. The prover wants to convince the
//! verifier that the statement belongs to one of the specified residue classes.
//!
//! The commit is a "capsule" that contains many elements each belonging to a unique residue
//! class, though which element belonging to which class is obscured.
//!
//! The challenge is a selection of the subset of the capsules. For capsule in the subset,
//! the prover needs to reveal the individual decomposition of the capsule; for capsules not
//! selected in the subset, an appropriate element within the capsule is selected to demonstrate
//! the residue class of the ciphertext
use crate::{
    arithmetics::{ClearResidue, OpaqueResidue, ResidueClass, RingModulus},
    keys::PublicKey,
    BigInt,
};
use crypto_bigint::{modular::runtime_mod::DynResidue, rand_core::OsRng, Encoding};
use rand::seq::SliceRandom;
use sha3::{Digest, Sha3_256};

/// The choice of using SHA-256 decides that the confidence level has to be 256
/// In a more robust setting we should have dynamic confidence level
pub const CONFIDENCE: usize = 256;

/// Use this function to generate the 2-array of residue classes RC[0] and RC[1]
pub fn zero_or_one(modulus: &RingModulus) -> [ResidueClass; 2] {
    let one = ResidueClass::new(DynResidue::new(
        &BigInt::ONE,
        modulus.to_dyn_residue_params(),
    ));
    let zero = ResidueClass::new(DynResidue::new(
        &BigInt::ZERO,
        modulus.to_dyn_residue_params(),
    ));
    return [one, zero];
}

/// Proof that the ballot belongs to one of the pre-specified residue classes without revealing
/// which specific class. In a simple election, we prove that the ballot belongs to either
/// RC[0] or RC[1]
pub struct BallotProof {
    pub statement: OpaqueResidue,

    pub commitment: Vec<OpaqueCapsule>,

    pub challenge: Vec<bool>,

    pub response: Vec<Response>,
}

impl BallotProof {
    pub fn new(
        statement: OpaqueResidue,
        commitment: Vec<OpaqueCapsule>,
        challenge: Vec<bool>,
        response: Vec<Response>,
    ) -> Self {
        return Self {
            statement,
            commitment,
            challenge,
            response,
        };
    }

    /// Produce a proof that the statement is in one of the specified residue classes
    pub fn from_statement(
        statement: &ClearResidue,
        classes: &[ResidueClass],
        pk: &PublicKey,
    ) -> Self {
        let answers = (0..CONFIDENCE)
            .map(|_| ClearCapsule::generate(classes, pk))
            .collect::<Vec<ClearCapsule>>();
        let commitment = answers
            .iter()
            .map(|clear| clear.obscure())
            .collect::<Vec<OpaqueCapsule>>();
        let challenge = Self::generate_challenge(&commitment);
        let response = Self::respond(statement, &answers, &challenge, pk);

        return Self::new(statement.clone_val(), commitment, challenge, response);
    }

    fn generate_challenge(commitment: &[OpaqueCapsule]) -> Vec<bool> {
        let mut hasher = Sha3_256::new();

        for capsule in commitment {
            for residue in capsule.get_elements() {
                hasher.update(residue.retrieve().to_be_bytes());
            }
        }

        let hash: Vec<u8> = hasher.finalize().to_vec();
        let mut challenge = vec![true; 256];
        for (i, byte) in hash.iter().enumerate() {
            for j in 0..u8::BITS {
                let loc = i * 8 + j as usize;
                let mask = 0b1000_0000u8 >> j;
                if mask & byte == 0 {
                    challenge[loc] = false;
                } else {
                    challenge[loc] = true;
                }
            }
        }

        return challenge;
    }

    fn respond(
        statement: &ClearResidue,
        commitment: &[ClearCapsule],
        challenge: &[bool],
        pk: &PublicKey,
    ) -> Vec<Response> {
        if challenge.len() != commitment.len() {
            panic!("Challenge and commitment not equal in length");
        }

        let mut responses = vec![];
        for (i, open_capsule) in challenge.iter().enumerate() {
            if *open_capsule {
                let clear_capsule = commitment.get(i).unwrap().clone();
                let response = Response::OpenCapsule(clear_capsule);
                responses.push(response);
            } else {
                responses.push(Response::ConsumeCapsule(
                    commitment.get(i).unwrap().consume(statement, pk),
                ));
            }
        }
        return responses;
    }

    /// Verify a single response. If the response is "open capsule", then check that the
    /// values of the opened capsule match exactly with the values of the commitment capsules.
    /// if the response is "consume capsule", then use the response to reconstruct the element
    /// from the capsule, and check that such an element indeed exists.
    fn verify_response(
        statement: &OpaqueResidue,
        commitment: &OpaqueCapsule,
        response: &Response,
    ) -> bool {
        match response {
            Response::ConsumeCapsule(quotient) => {
                let reconstructed = statement.clone() * quotient.clone_val();
                let has_match = commitment
                    .get_elements()
                    .iter()
                    .any(|elem| *elem == reconstructed);
                if !has_match {
                    panic!("Consume capsule failed to verify");
                }
                return has_match;
            }
            Response::OpenCapsule(open_cap) => {
                if commitment.get_elements().len() != open_cap.get_elements().len() {
                    return false;
                }
                return commitment
                    .get_elements()
                    .iter()
                    .zip(open_cap.get_elements().iter())
                    .all(|(commit_elem, open_elem)| {
                        return commit_elem == open_elem.get_val();
                    });
            }
        }
    }

    /// Verify the proof
    pub fn verify(&self) -> bool {
        if self.commitment.len() != self.challenge.len() {
            return false;
        }
        if self.commitment.len() != self.response.len() {
            return false;
        }

        return self
            .commitment
            .iter()
            .zip(self.response.iter())
            .all(|(commitment, response)| {
                return Self::verify_response(&self.statement, commitment, response);
            });
    }
}

/// Each closed capsule contains one random element from each of the specified residue
/// classes, but we don't know which one is which
pub struct OpaqueCapsule {
    elements: Vec<OpaqueResidue>,
}

impl OpaqueCapsule {
    pub fn new(elements: Vec<OpaqueResidue>) -> Self {
        return Self { elements };
    }

    pub fn get_elements(&self) -> &[OpaqueResidue] {
        return &self.elements;
    }
}

/// Each opened capsule reveals the residue class that each element belongs to
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ClearCapsule {
    elements: Vec<ClearResidue>,
}

impl ClearCapsule {
    pub fn new(elements: Vec<ClearResidue>) -> Self {
        return Self { elements };
    }

    pub fn get_elements(&self) -> &[ClearResidue] {
        return &self.elements;
    }

    pub fn generate(classes: &[ResidueClass], pk: &PublicKey) -> Self {
        let mut elements = classes
            .iter()
            .map(|rc| ClearResidue::random(Some(rc.clone_residue()), pk))
            .collect::<Vec<ClearResidue>>();
        elements.shuffle(&mut OsRng);
        return Self::new(elements);
    }

    pub fn obscure(&self) -> OpaqueCapsule {
        let elements = self
            .elements
            .iter()
            .map(|clear| clear.clone_val())
            .collect::<Vec<OpaqueResidue>>();
        return OpaqueCapsule::new(elements);
    }

    /// If the capsule is not selected to be opened, it will be consumed alongside the
    /// statement to show that the statement has the same residue class as one of its
    /// elements.
    ///
    /// If two elements w, w' have the same residue class, then w' * w^(-1) is an r-th
    /// residue. So the returned value will be a decomposition of the value.
    pub fn consume(&self, statement: &ClearResidue, pk: &PublicKey) -> ClearResidue {
        for element in self.elements.iter() {
            if element.get_rc() == statement.get_rc() {
                // there is no straightforward way to invert a clear residue without
                // the secret key, so we compute the response from the decomposition
                let witness = element.clone_witness() * (statement.clone_witness().invert());
                let zero = DynResidue::new(&BigInt::ZERO, pk.get_r().to_dyn_residue_params());
                return ClearResidue::compose(zero, witness.get_residue().clone(), pk);
            }
        }
        panic!("Capsule does not have matching element");
    }
}

/// Depending on whether the capsule is chosen, you either "open the capsule"
/// and reveal which element belongs to which residue class, or "consume the capsule" and
/// show the decomposition of (statement / capsule)
pub enum Response {
    OpenCapsule(ClearCapsule),
    ConsumeCapsule(ClearResidue),
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{rand_core::OsRng, Random};

    use super::*;
    use crate::keys::KeyPair;

    #[test]
    fn test_consume_capsule() {
        let keypair = KeyPair::keygen(16, 64, false);
        let residue_class = DynResidue::new(
            &BigInt::random(&mut OsRng),
            keypair.get_pk().get_r().to_dyn_residue_params(),
        );
        let statement = ClearResidue::random(Some(residue_class), keypair.get_pk());
        let element = ClearResidue::random(Some(residue_class), keypair.get_pk());
        let capsule = ClearCapsule::new(vec![element]);
        let response = capsule.consume(&statement, keypair.get_pk());
        assert!(response.is_exact_residue());
    }

    /// Test that honest prover can prove to an honest verifier
    #[test]
    fn test_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let one = DynResidue::new(
            &BigInt::ONE,
            keypair.get_pk().get_r().to_dyn_residue_params(),
        );
        let statement = ClearResidue::random(Some(one), keypair.get_pk());
        let proof = BallotProof::from_statement(
            &statement,
            &zero_or_one(keypair.get_pk().get_r()),
            keypair.get_pk(),
        );
        assert!(proof.verify());
    }
}
