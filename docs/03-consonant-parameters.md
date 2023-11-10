# Proof of consonant parameters
The government needs to prove to the voters that the parameters are generated correctly. This is important because dishonest parameters can be used to claim arbitrary tally. In the original thesis, this proof is achieved through two interactive proofs: first the voter proves to the government that the voter has a ciphertext that the voter knows the message to, then the government proves to the voter that it can correctly decrypt the ciphertext. In this section, we will review the proofs, and provide some improvements that reduce the interactivity of the procedure

## Dishonest parameters
Recall from previous section that decryption is the process of recovering the residue class $\text{RC}[c]$ of the ciphertext, and the government proves to the voter that the decryption is indeed correct by showing that $\omega \cdot y^{-c} \in \mathbb{Z}_n^r$. However, if the parameters are generated dishonestly, then the government will be able to claim arbitrary decryption $c$ and still prove that $\omega y^{-c}$ is an r-th residue. For example, if $\gcd(r, \phi(n)) = 1$, then there exists solution to the diophantine equation $s \cdot r + t \cdot \phi(n) = 1$, and $z^s$ is such that $(z^s)^r = z$, meaning that **all elements of $\mathbb{Z}_n^*$ are r-th residue: $\mathbb{Z}_n^* = \mathbb{Z}_n^r$**. 

## Interactive proof of honest parameter
The proof of honest parameter comes from the mathematical fact that given the triplet $(r, n, y)$, there are exactly $m$ distinct (and thus disjoint) residue classes, where $m$ is the smallest positive integer such that $y^m$ is an r-th residue (also called the norm of the triplet), and $m$ is necessarily a divisor of $r$.

This means that if the parameters are dishonest, then $m < r$, and by divisibility we know $m \leq r/2$, so there are at most $r/2$ distinct residue classes. If the voter can supply a ciphertext, then the chance of correct decryption cannot exceed 50%. In other words, voter can challenge the validity of the parameters by asking the government to show that it can decrypt ciphertext correctly. We call this the proof of consonance.

However, this interactive proof alone comes with the problem that dishonest voter can trick an honest government into decrypting arbitrary ciphertexts, so a second proof (we will call proof of residue class) is needed to show that the voter knows the residue class of the challenge ciphertext before the government can decrypt the challenge ciphertext.

## Improvements
The first improvement comes from re-formulating the proof of knowing residue class into a sigma protocol, then apply the Fiat-Shamir transformation to make it into a non-interactive proof.

* **statement**: $\omega = y^cz$ for some secret $c \in \mathbb{Z}_r$ and secret $z \in \mathbb{Z}_n^r$
* **commit**: $\omega^\prime = y^{c^\prime}z^\prime$ for some secret $c^\prime \leftarrow \mathbb{Z}_r$ and $z^\prime \leftarrow \mathbb{Z}_n^r$
- **challenge**: $b = H(\omega^\prime)$ where $H: \mathbb{Z}_n^* \rightarrow \mathbb{Z}_r$ is a hash function
- **response**: $c^\prime + bc \mod r$
- **verification**: $\omega\omega^\prime y^{-(c^\prime + bc)}$ is an r-th residue

Note that the verification can be efficiently computed because the verifier (the government) has the secret key $\phi(n)$. Assuming that the parameters are generated correctly and the triplet $(r, n, y)$ is indeed consonant, then $\gcd(r, \phi(n)) = r$, meaning that the verifier can solve the diophantine equation $s \cdot r + t \cdot \frac{\phi}{r} = 1$. If the quantity $z^* = \omega\omega^\prime y^{-(c^\prime + bc)}$ is indeed an r-th residue then $(z^*)^s$ should be an r-th root.

The soundness of this proof can be shown through the knowledge extractor: given two distinct challenge $b_1, b_2$ and their corresponding responses $c^\prime + b_1c$, $c^\prime + b_2c$, we can recover the witness:

$$
c = \frac{(c^\prime + b_2c) - (c^\prime + b_1c)}{b_2 - b_1}
$$

The zero-knowledge property can be shown through a simulator: assuming that the verifier is honest and chooses its challenge independent of the commit, then the simulator can provide a transcript by fixing a response and computing the corresponding commit:

$$
\omega \cdot \text{commit} \cdot y^{-\text{resp}} \equiv z \mod n
$$

where $z$ is some randomly sampled r-th residue.

Assuming that the parameters are honest, the probability that the prover can fool the verifier is $\frac{1}{r}$, and we can increase the size of the commit and challenge to achieve arbitrary level of confidence that the voter indeed knows the residue class of the challenge ciphertext.