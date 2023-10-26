# Benaloh cryptosystem
A Rust implementation of [Josh Benaloh's cryptosystem](https://en.wikipedia.org/wiki/Benaloh_cryptosystem)

- [PhD thesis](https://www.microsoft.com/en-us/research/wp-content/uploads/1987/01/thesis.pdf)

What's next: a PoC
- ✅ Working with large numbers
- ✅ Generate ambient primes
    - ✅ Generate large primes $p, q$
    - ✅ Generate block size and large primes $p, q, r$ that form valid ambient primes
- ✅ Generate key pair
    - ✅ Multiply large primes
    - ✅ **Generate random element from $\mathbb{Z}_n^*$**
    - ✅ `modexp` for verifying that the generated $y$ is valid
- 🚧 Encryption and decryption
    - ✅ Generating random element from the multiplicative group and `modexp` can be reused 
    - ✅ `modmul` for multiplying two large numbers under modulo
    - ✅ Discrete log using brute-force
    - 🚧 Discrete log using baby-step-giant-step
    - 🚧 Discrete log using [Hensel's lifting lemma](#discrete-log-using-hensels-lifting-lemma)

Goals
- [x] Correctness of the cryptosystem
- [ ] Pivot into a verifiable electronic voting scheme
    - [ ] 
- [ ] (Bonus) write a Python front-end

## Documentation
- [Election encryption algorithm](./docs/election-encryption-algo.md)
- [Naive election procedure and problems](./docs/naive-election.md)