use benaloh_cryptosystem::{proofs::ballot::Proof, arithmetics::HigherResidue, keys::KeyPair, BigInt};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};

fn main() {
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
    println!("{validated}");
}
