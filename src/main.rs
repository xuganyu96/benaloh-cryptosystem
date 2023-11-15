//! Useful scratchpad
use benaloh_cryptosystem::{
    arithmetics::ClearResidue, keys::KeyPair, proofs::ballot::Proof, BigInt,
};
use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};

#[allow(unused_variables)]
fn main() {
    let keypair = KeyPair::keygen(16, 64, false);
    let one = DynResidue::new(
        &BigInt::ONE,
        DynResidueParams::new(keypair.get_pk().get_r()),
    );
    let statement = ClearResidue::random(Some(one), keypair.get_pk());
    let n = DynResidueParams::new(keypair.get_pk().get_n());
    let zero = DynResidue::new(&BigInt::ZERO, n);
    let one = DynResidue::new(&BigInt::ONE, n);
    let classes = vec![zero, one];
    let confidence = 256usize;
    let commitment = Proof::generate_commitment(&statement, &classes, confidence);
    for capsule in commitment.iter() {
        for elem in capsule.get_content() {
            println!("{:?}", elem.get_rc().retrieve());
        }
    }
    let challenge = Proof::generate_challenge(&commitment);
    let response = Proof::respond(&statement, &commitment, &challenge);
    let validated = Proof::validate_response(&statement, &commitment, &response);
}
