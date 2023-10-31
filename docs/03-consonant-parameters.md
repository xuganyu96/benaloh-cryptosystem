# Proof of consonant parameters
A second issue with the naive election scheme is that the government can generate dishonest parameters. Recall that the government proves to the voter that each vote $\omega \equiv y^mz \mod n$ is decrypted correctly to $m$ by showing that $\omega \cdot y^{-m} \mod n$ is an r-th residue. However, if the parameters are generated incorrectly, such as when $r$ and $\phi$ are relatively prime, then the government will be able to claim arbitrary decryption because every element in $\mathbb{Z}_n^*$ is an r-th residue. Therefore, it is important that the government proves to the voters that the parameters are generated correctly.

## Consonance of parameters
(how do I introduce the concept of consonance?)

There are a few important results that can be derived from the consonance properties:

1. if $(r, n, y)$ are consonant, then there are exactly $r$ distinct residue classes
1. if $r, n, y$ are consonant, then $\gcd(r, \phi) = r$

## Interactive proof of consonance
A naive interactive proof of consonance is for the government to demonstrate that there are indeed $r$ distinct residue classes. This works because the order of $(r, n, y)$ divides $r$, meaning that if there are fewer than $r$ distinct residue classes, then there are at most $\frac{r}{2}$ residue classes. Each voter can thus generate some random ciphertexts and ask the government to decrypt: if the parameters are honest, then the government will be able to decrypt all the time; if the parameters are dishonest, then the government will have at most $\frac{1}{2}$ chance of correctly guessing the underlying ciphertext.

However, this naive interactvie proof is not zero-knowledge, because a dishonest voter can use an honest government as a decryption oracle in this interactive proof to obtain undue information. Benaloh proposed that a second interactive proof be used to show that the voter actually knows the plaintext.

**Sigma protocol for proving knowledge of plaintext**:

- Statement: $\omega = y^cz$ for some $c \in \mathbb{Z}_r$ and $z \in \mathbb{Z}_n^r$
- Commitment: $\omega^\prime = y^{c^\prime}z^\prime$ for some $c^\prime \in \mathbb{Z}_r$ and $z^\prime \leftarrow \mathbb{Z}_n^r$
- Challenge: $b \leftarrow \mathbb{Z}_r$
- Response: $c^\prime + bc$

The government then verifies the response by checking if $\omega^b\omega^\prime \cdot y^{-(c^\prime+bc)}$ is an r-th residue, which can be done because the government has the secret key $\phi$. Correctness is trivial.

This interactive proof is sound. Suppose we have a knowledge extract who can issue a second challenge $b^\prime$ for the same commit $\omega^\prime$, then the knowledge extractor can obtain $c^\prime + bc$ and $c^\prime + b^\prime c$. From here we can obtain $c$:

$$
c = \frac{(c^\prime + bc) - (c^\prime + b^\prime c)}{b - b^\prime}
$$

This interactive proof is also zero-knowledge against an honest government. Suppose we have a simulator who can revise its commit based on the challenge, then the simulator can produce a valid transcript without knowing the value of the witness $c$:

1. Sample some random $c^* \leftarrow \mathbb{Z}_r$
1. Sample some random $z^* \leftarrow \mathbb{Z}_n^r$
1. Suppose the challenge is $b \leftarrow \mathbb{Z}_r$
1. The transcript is as follows:
    - Commit: $z^*y^{c^*}\omega^{-b}$
    - Challenge: $b$
    - Response: $c^*$

Thus we have a zero-knowledge proof that the voter is honest and not trying to use an honest government as a decryption oracle.

## Improved interactive proof
While the two-phase interactive proof described above works, it is not ideal for several reasons:

1. There are **two** proofs to do instead of a single proof
2. The actual proof of consonance is not a sigma protocol, so it is hard to demonstrate soundness and zero-knowledge
3. The baseline confidence is $1 - \frac{1}{2}$ which is not enough; we wish the baseline confidence to be $1 - \frac{1}{r}$ so we can prove using fewer interactions

