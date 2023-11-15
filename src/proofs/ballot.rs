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
use crate::{LIMBS, arithmetics::HigherResidue};
use crypto_bigint::{modular::runtime_mod::{DynResidue, DynResidueParams}, Encoding};
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sha3::{Digest, Sha3_256};

pub struct Proof {
    statement: HigherResidue,
    
    /// The commit is a list of capsules. There is no need to maintain a separate variable about
    /// the confidence level because the length of the commitment is exactly that
    commitment: Vec<Capsule>,
}


impl Proof {
    pub fn new(statement: HigherResidue, commitment: Vec<Capsule>) -> Self {
        return Self { statement, commitment };
    }

    pub fn get_statement(&self) -> &HigherResidue {
        return &self.statement;
    }

    pub fn get_commitment(&self) -> &[Capsule] {
        return &self.commitment;
    }

    /// Return the confidence in the proof (the probability that a dishonest prover fails to fool
    /// an honest verifier), expresssed in the number of bits. The actual probability is
    /// (1 - 2 ** bits)
    pub fn get_confidence_bits(&self) -> usize {
        return self.get_commitment().len();
    }

    /// Instantiate from a statement and generate the commitment, which is a vector of capsules.
    /// Each capsule contains one element from each of the input classes. The number of capsules in
    /// the commit is given by the confidence.
    pub fn generate_commitment(
        statement: &HigherResidue, 
        classes: &[DynResidue<LIMBS>],
        confidence: usize,
    ) -> Vec<Capsule> {
        let mut capsules = vec![];
        
        for _ in 0..confidence {
            let mut capsule = Capsule::new();
            for rc in classes {
                let x = statement.get_ambience().sample_invertible();
                let elem = HigherResidue::compose(rc.retrieve(), x, statement.get_ambience());
                capsule.append(elem);
            }
            capsule.shuffle();
            capsules.push(capsule);
        }

        return capsules;
    }

    /// Hash the list of capsules into a single bit sequence
    pub fn generate_challenge(commitment: &[Capsule]) -> Vec<bool> {
        let mut hasher = Sha3_256::new();
        for capsule in commitment {
            for residue in capsule.get_content() {
                hasher.update(&residue.get_val().to_be_bytes());
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

    /// Iterate through the challenges and build response accordingly
    pub fn respond(
        statement: &HigherResidue,
        commitment: &[Capsule],
        challenge: &[bool],
    ) -> Vec<Response> {
        if challenge.len() != commitment.len() {
            panic!("Challenge and commit not equal in length");
        }

        let mut responses = vec![];
        for (i, open_capsule) in challenge.iter().enumerate() {
            let capsule = commitment.get(i).unwrap();
            if *open_capsule {
                responses.push(capsule.open());
            } else {
                responses.push(capsule.decompose(statement));
            }
        }

        return responses;
    }

    /// Validate an opened capsule
    pub fn validate_open_capsule(
        commitment: &Capsule,
        response: &[HigherResidue],
    ) -> bool {
        if commitment.get_content().len() != response.len() {
            return false;
        }
        return commitment.get_content().iter().zip(response.iter())
            .all(|(a, b)| a == b);
    }

    /// Validate a closed capsule
    pub fn validate_closed_capsule(
        statement: &HigherResidue,
        commitment: &Capsule,
        response: &DynResidue<LIMBS>,  // x^{-1}alpha
    ) -> bool {
        let reconstructed_commit = DynResidue::new(
            statement.get_val(),
            DynResidueParams::new(statement.get_ambience().get_n())
        ).mul(
            &response.pow(statement.get_ambience().get_r())
        ).retrieve();

        return commitment.get_content()
            .iter()
            .any(|elem| {
                return elem.get_val() == &reconstructed_commit;
            });
    }

    pub fn validate_response(
        statement: &HigherResidue,
        commitment: &[Capsule],
        responses: &[Response],
    ) -> bool {
        if commitment.len() != responses.len() {
            return false;
        }
        return commitment.iter().zip(responses.iter())
            .all(|(capsule, response)| {
                return match response {
                    Response::OpenCapsule(opened_capsule) => {
                        Self::validate_open_capsule(capsule, opened_capsule)
                    },
                    Response::DecompWitness(residue) => {
                        Self::validate_closed_capsule(statement, capsule, residue)
                    },
                };
            });
    }
}

/// Each capsule contains a number of elements each from a distinct residue class
pub struct Capsule {
    content: Vec<HigherResidue>,
}

impl Capsule {
    /// Start with an empty capsule
    pub fn new() -> Self {
        return Self { content: vec![] };
    }


    /// Reveal the content of the capsule
    pub fn get_content(&self) -> &[HigherResidue] {
        return &self.content;
    }

    /// Append a new element
    pub fn append(&mut self, elem: HigherResidue) {
        self.content.push(elem);
    }

    /// Shuffle the order of the content
    pub fn shuffle(&mut self) {
        self.content.shuffle(&mut OsRng);
    }

    pub fn open(&self) -> Response {
        let mut residues = vec![];
        residues.extend_from_slice(self.get_content());
        return Response::OpenCapsule(residues);
    }

    pub fn decompose(&self, statement: &HigherResidue) -> Response {
        let (x_inv, _) = statement.get_witness().inv_mod(statement.get_ambience().get_n());

        for elem in self.get_content() {
            if elem.get_rc() == statement.get_rc() {
                let n = DynResidueParams::new(statement.get_ambience().get_n());
                let x_inv = DynResidue::new(&x_inv, n);
                let witness = DynResidue::new(elem.get_witness(), n);
                return Response::DecompWitness(x_inv.mul(&witness));
            }
        }

        panic!("Capsule does not contain matching residue");
    }
}

/// If the challenge is 0, then the capsule opened. If the challenge is 1, then the element in the
/// capsule with the same residue is combined with the statement, then decomposed, and the
/// decomposition is the response
pub enum Response {
    OpenCapsule(Vec<HigherResidue>),
    DecompWitness(DynResidue<LIMBS>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BigInt, keys::KeyPair};

    #[test]
    fn test_correctness() {
        let keypair = KeyPair::keygen(16, 64, false);
        let statement = HigherResidue::random(Some(BigInt::ONE), keypair.get_pk());
        let n = DynResidueParams::new(keypair.get_pk().get_n());
        let zero = DynResidue::new(&BigInt::ZERO, n);
        let one = DynResidue::new(&BigInt::ONE, n);
        let classes = vec![zero, one];
        let confidence = 256usize;
        let commitment = Proof::generate_commitment(&statement, &classes, confidence);
        let challenge = Proof::generate_challenge(&commitment);
        let response = Proof::respond(&statement, &commitment, &challenge);
        let validated = Proof::validate_response(&statement, &commitment, &response);
        assert!(validated);
    }
}
