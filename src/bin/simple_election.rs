//! A sample election procedure

use benaloh_cryptosystem::{
    arithmetics::{ClearResidue, OpaqueResidue},
    keys::KeyPair,
    proofs, BigInt, GROUPSIZE, LIMBS, RINGSIZE,
};
use crypto_bigint::modular::runtime_mod::DynResidue;
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{NonZero, RandomMod};

const PARAMS_CHALLENGE_ROUNDS: usize = 10;
const VOTERS: usize = 1000;

/// Generate the keypair
fn keygen(ring_size: usize, group_size: usize, safe_prime: bool) -> KeyPair {
    let keypair = KeyPair::keygen(ring_size, group_size, safe_prime);
    println!("Keypair generated");

    return keypair;
}

/// challenge the validity of the parameters (r, n, y)
/// For each of the challenge round, a challenge ciphertext (including the voter's proof) is
/// randomly generated. The government then uses the secret key to decrypt the challenge and
/// produces the residue class
fn challenge_consonance(rounds: usize, keypair: &KeyPair) {
    for round in 0..rounds {
        print!("Consonance challenge round {round}/{rounds}...  ");
        let challenge = proofs::consonance::ClearChallenge::generate(keypair.get_pk(), 1);
        let opaque = challenge.obscure();
        let gov_proof = proofs::consonance::GovernmentProof::respond(&opaque, &keypair);
        challenge.verify_gov_proof(&gov_proof);
        println!("Challenge successful!");
    }
}

/// Generate the ballots. Each ballot is a random encryption of 0 or 1.
/// At each ballot, a proof of ballot's validity is generated and verified.
/// The true ballot count is also kept for verification purpose.
fn generate_ballots(keypair: &KeyPair, count: usize) -> (Vec<OpaqueResidue>, DynResidue<LIMBS>) {
    let r = keypair.get_pk().get_r().to_dyn_residue_params();
    let mut ballots: Vec<OpaqueResidue> = vec![]; // the set of ballots
                                                  // The true tally count, used to verify that the decryption is correct later
    let mut true_tally = DynResidue::new(&BigInt::ZERO, r);
    println!("Generating {count} ballots");
    for i in 0..count {
        let two = NonZero::new(BigInt::from_u8(2)).unwrap();
        let vote = DynResidue::new(
            &BigInt::random_mod(&mut OsRng, &two),
            keypair.get_pk().get_r().to_dyn_residue_params(),
        );
        let ballot = ClearResidue::random(Some(vote), keypair.get_pk());

        let proof = proofs::ballot::BallotProof::from_statement(
            &ballot,
            &proofs::ballot::zero_or_one(&keypair.get_pk().get_r()),
            keypair.get_pk(),
        );
        if !proof.verify() {
            panic!("Ballot's residue class cannot be validated");
        }

        if (i + 1) % (count / 10) == 0 {
            println!("{}/{} ballots generated and verified", i + 1, count);
        }

        ballots.push(ballot.clone_val());
        true_tally = true_tally.add(&vote);
    }
    println!("{count} ballots generated and verified");

    return (ballots, true_tally);
}

/// Collect the ballots and compute the final tally. After the finally tally is computed, a
/// proof is released and verified.
/// Finally, the collected tally is verified against the true tally
fn tally(keypair: &KeyPair, ballots: &[OpaqueResidue], true_tally: &DynResidue<LIMBS>) {
    let mut product = DynResidue::new(
        &BigInt::ONE,
        keypair.get_pk().get_n().to_dyn_residue_params(),
    );
    for ballot in ballots {
        product = product.mul(&ballot);
    }
    let decryption = ClearResidue::decompose(product, &keypair);
    let statement = ClearResidue::decompose(
        product.mul(&keypair.get_pk().invert_y().pow(decryption.get_rc())),
        &keypair,
    );
    let proof = proofs::tally::TallyProof::from_statement(statement, 1, keypair.get_pk());
    if !proof.verify() {
        panic!("The residue class of the tally failed to be verified");
    } else {
        println!("decryption proof verified");
    }

    if decryption.get_rc().retrieve() != true_tally.retrieve() {
        panic!("the final tally is incorrect!");
    } else {
        println!("The final tally is correct");
    }
}

fn main() {
    let keypair = keygen(RINGSIZE, GROUPSIZE, false);
    challenge_consonance(PARAMS_CHALLENGE_ROUNDS, &keypair);
    let (ballots, true_tally) = generate_ballots(&keypair, VOTERS);
    tally(&keypair, &ballots, &true_tally);
    println!("The election is a success!");
}
