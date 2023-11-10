use benaloh_cryptosystem::keys::KeyPair;


fn main() {
    let keypair = KeyPair::keygen(16, 96, false);
    assert!(keypair.check_perfect_consonance());
}
