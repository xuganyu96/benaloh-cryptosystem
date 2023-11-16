//! A sample election procedure

use benaloh_cryptosystem::arithmetics::OpaqueResidue;
use benaloh_cryptosystem::{arithmetics::ClearResidue, keys::KeyPair, proofs, BigInt};
use crypto_bigint::modular::runtime_mod::DynResidue;
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{NonZero, RandomMod};

const RING_BITS: usize = 16;
const MODULUS_BITS: usize = 64;
const SAFE: bool = false;

const PARAMS_CHALLENGE_ROUNDS: usize = 10;
const VOTERS: usize = 10;
const BALLOT_VALIDITY_CONFIDENCE_BITS: usize = 256;

fn main() {
    let keypair = KeyPair::keygen(RING_BITS, MODULUS_BITS, SAFE);

    // challenge the validity of the parameters (r, n, y)
    for _ in 0..PARAMS_CHALLENGE_ROUNDS {
        // Voter generates some challenge ciphertext then proves that the residue class is known
        let voter_statement = ClearResidue::random(None, keypair.get_pk());
        let voter_proof = proofs::rc::Proof::from_statement(voter_statement.clone());
        let voter_challenge = proofs::rc::Challenge::generate(&keypair);
        let voter_response = voter_proof.respond(&voter_challenge);
        if !voter_challenge.verify(&voter_proof, &voter_response) {
            panic!("Voter failed to prove knowledge of residue class");
        }

        // Government demonstrates correct identification of residue class
        let gov_challenge = proofs::decide::Challenge::new(voter_statement);
        let gov_response = proofs::decide::Proof::respond(&gov_challenge, &keypair);
        if !gov_challenge.verify(&gov_response) {
            panic!("Government failed to identify residue class of");
        }
    }

    // Generate the ballots, and for each time,
    let n = keypair.get_pk().get_n().to_dyn_residue_params();
    let r = keypair.get_pk().get_r().to_dyn_residue_params();
    let mut ballots: Vec<OpaqueResidue> = vec![];
    let mut true_tally = DynResidue::new(&BigInt::ZERO, r);
    let valid_residue_classes = vec![
        DynResidue::new(&BigInt::ZERO, n),
        DynResidue::new(&BigInt::ONE, n),
    ];
    for _ in 0..VOTERS {
        let two = NonZero::new(BigInt::from_u8(2)).unwrap();
        let vote = DynResidue::new(&BigInt::random_mod(&mut OsRng, &two), r);
        let ballot = ClearResidue::random(Some(vote), keypair.get_pk());

        // Prove that the ballot is indeed either 0 or 1
        let commitment = proofs::ballot::Proof::generate_commitment(
            &ballot,
            &valid_residue_classes,
            BALLOT_VALIDITY_CONFIDENCE_BITS,
        );
        let challenge = proofs::ballot::Proof::generate_challenge(&commitment);
        let response = proofs::ballot::Proof::respond(&ballot, &commitment, &challenge);
        let validated = proofs::ballot::Proof::verify(&ballot, &commitment, &response);
        if !validated {
            panic!("Ballot's residue class cannot be validated");
        }

        // Keep track of the true ballots later for verification
        ballots.push(ballot.clone_val());
        true_tally = true_tally.add(&vote);
    }

    // Tally the ballots and release a proof
    let mut product = DynResidue::new(&BigInt::ONE, n);
    for ballot in ballots {
        product = product.mul(&ballot);
    }
    let decryption = ClearResidue::decompose(product, &keypair);
    if decryption.get_rc().retrieve() != true_tally.retrieve() {
        panic!("the final tally is incorrect!");
    }
    // Prove that (product * (y ** -tally)) is an r-th residue
    let statement = ClearResidue::decompose(
        product.mul(&keypair.get_pk().invert_y().pow(decryption.get_rc())),
        &keypair,
    );
    let commitment = proofs::tally::Proof::generate_commitment(n, keypair.get_pk());
    let challenge =
        proofs::tally::Proof::generate_challenge(&commitment, keypair.get_pk().get_r().modulus());
    let response = proofs::tally::Proof::respond(&statement, &commitment, &challenge);
    let validated = proofs::tally::Proof::verify(
        &statement,
        &commitment,
        &challenge,
        &response,
        keypair.get_pk(),
    );
    if !validated {
        panic!("The residue class of the tally failed to be verified");
    }
    println!("The election is a success!");
}
