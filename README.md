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
- [ ] Verify homomorphism
- [ ] (Bonus) Pivot into a verifiable electronic voting scheme
- [ ] (Bonus) write a Python front-end

## Components
### PGen
1. Generate a random block size $r \leftarrow \mathbb{Z}$
2. Generate random large primes $p, q$ such that
    - $r \mid (p-1)$
    - $\text{gcd}(r, \frac{p-1}{r}) = 1$
    - $\text{gcd}(r, q-1) = 1$

### KeyGen
1. Compute $n \leftarrow p \cdot q$ and $\phi = (p-1)(q-1)$
2. Generate some $y \leftarrow \mathbb{Z}_n^*$ such that $y^\frac{\phi}{r} \not\equiv 1 \mod n$
3. Set $x \leftarrow y^\frac{\phi}{r} \mod n$

$$
\begin{aligned}
\text{pk} &= (n, r, y) \\
\text{sk} &= (p, q, x)
\end{aligned}
$$

Note: if $r$ is itself a prime number, then there is no additional concern. if $r$ is composite, then the condition on $y$ needs to be changed to $y^\frac{\phi}{p_i} \not\equiv 1 \mod n$ for all prime factorization $p_i$ of $r$

### Encryption and decryption
The message space is the integer ring $\mathbb{Z}_r$. To encrypt a message $m \leftarrow \mathbb{Z}_r$:

1. Uniformly sample $u \leftarrow \mathbb{Z}_n^*$
2. Compute ciphertext $c \leftarrow y^mu^r \mod n$

To decrypt a ciphertext $c$

1. Compute $a \leftarrow c^\frac{\phi}{r} \mod n$
2. Find an exponent $m$ such that $x^m = a \mod n$. $m$ is the plaintext
    - Can use brute-force
    - Should try a more [efficient algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step)

## Implementation
### Discrete log using Hensel's lifting lemma
When the ring modulo $r$ is a prime, there is no better algorithm for finding discrete logarithm than brute-force. There are two issues with using brute-force dlog:

1. **Performance**: Time complexity scales exponentially with the number of bits of $r$ (baby-step-giant-step only provides a square root reduction, so it's still exponential)
2. **Security**: having a scaling time complexity leaves the implementation vulnerable to side-channel attack

Observe that $r$ does not have to be prime; instead, it can be a power of a single prime (and definition of $y$ needs to be adjusted accordingly). If $r$ is the power of a single prime, then we can apply [Hensel's lifting lemma](https://en.wikipedia.org/wiki/Hensel%27s_lemma) to compute discrete log in polynomial time (credits: Youcef Mukrani).

### Constant-time discrete log
Do note that in the context of RSA, constant-time exponentiation is constant with respect to the secret exponent $d$ instead of being constant with respect to everything. In a similar manner, the brute-force discrete log will be constant time with respect to the plaintext $m$. It will not be constant time with respect to the block size $r$.

This means that if I stick with a brute-force discrete log, then I need to iterate through all values in the integer ring $\mathbb{Z}_r$ even if a match has been found. This will be an effective way of preventing timing attacks that can tell the plaintext based on how many exponentiations are done.