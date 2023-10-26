# r-th residue proof
Recall from the naive election that the product of each voter's ciphertext is a itself a valid ciphertext that belongs to the residue class $RC\lbrack m \rbrack$ where $m$ is the sum of all individual votes.

$$
\begin{aligned}
\Omega = \prod w_i = y^{\sum m_i}{(\prod x_i)}^r
\end{aligned}
$$

The government can then use the secret key $\phi$ to decrypt by determining the residue class of $\Omega$, but after producing the tally $m$, the government needs to show taht $m$ is indeed the correct residue class by showing that $\Omega$ can be expressed in the form:

$$
\Omega = y^mz
$$

For some r-adic residue $z \in \mathbb{Z}_n^r$. This is equivalent to showing that $z \leftarrow \Omega \cdot (y^m)^{-1} \mod n$ is an r-adic residue.

A naive way to show r-adic residue is to show one of its roots. However, this is an unsuitable strategy because it is giving away too much information. For the remainder of this section, we first describe an attack in which the last voter use public ciphertexts to compute a poisoned ciphertext that can be used to break the election encryption, then we describe an interactive proof protocol with which the government can prove that $\Omega(y^m)^{-1}$ is indeed an r-adic residue without giving away any additional information

## Last voter attack
Compute the inverse of the product of all prior votes

## Interactive proof that $z \in \mathbb{Z}_n^r$
Suppose that the prover has some $z \in \mathbb{Z}_n^r$ and some $x \in \mathbb{Z}_n^*$ such that $z = x^r$. the prover wants to prove to the verifier that $z$ is indeed an r-adic residue, but does not want to reveal any additional information. This can be achieved through an interactive zero-knowledge proof in which the prover generates a random pair $z_i, x_i \in \mathbb{Z}_n^*$ such that $z_i = x_i^r$. the verifier then flips a coin $b \leftarrow \{0,1\}$: if $b = 0$, the prover shows $x_i$, otherwise the prover reveals $x_ix$

**statement**: $z \in \mathbb{Z}_n^r$

**commitment**: $z^\prime \in \mathbb{Z}_n^r$

**challenge**: $b \leftarrow \{0,1\}$

**response**: $x^\prime x^b$

**verification**: proof is valid if and only if $(x^\prime x^b)^r = z^\prime z^b$

A dishonest prover can guess the challenge ahead of time and fool an honest verifier if the guess is correct. Thus the baseline probability of forgeability is 0.5. We can then ask to run the proof $N$ times so that the confidence in the validity of proof is $1 - 2^{-N}$.

## More effective interactive proof
We can in fact extend the original interactive proof to have a larger "challenge space." In other words, the challenge $b$ is sampled from $\mathbb{Z}_r$ instead of $\{0, 1\}$. With everything else remaining the same, correctness can be trivially proved.

### Zero-knowledge property
We prove ZKP by showing that a simulator who knows the challenge $b \leftarrow \mathbb{Z}_r$ ahead of time can produce a transcript of proving $z \in \mathbb{Z}_n^r$ without knowing $x$. This is possible because we know the verification:

$$
\operatorname{response}^r \equiv \operatorname{commit} \cdot z^b \mod n
$$

so if we know $b$ ahead of time, we can pick some response and compute the commit from that. For example:

1. **response**: some randomly sampled $x^\prime \leftarrow \mathbb{Z}_n^*$
1. **commit**: $z^\prime z^{-b}$, where $z^\prime \leftarrow {x^\prime}^r$

Do note that **this only works with honest verifier who samples $b$ independent of the commit or statement**.

### Soundness
we prove soundness using a knowledge extractor. Suppose that there are two randomly sampled but distinct challenges $b_1, b_2 \in \mathbb{Z}_r, b_1 \neq b_2$, then the extractor will obtain $x^\prime x^{b_1}$ and $x^\prime x^{b_2}$. From here the extractor can compute $y = x^{b_2 - b_1}$ by dividing the two responses

Because $b_2 - b_1$ is not zero and $r$ is a prime numnber, the two values are necessarily co-prime. Therefore there exists integers $s, t$ such that

$$
s \cdot (b_2 - b_1) + t \cdot r = 1
$$

This implies that

$$
x^{s \cdot (b_2 - b_1) + t \cdot r} \equiv x \mod n
$$

Notice on the LHS, $x^{b_2 - b_1}$ is known, and $x^r = z$ is also known, so the LHS can be expressed using values that the extractor can obtain:

$$
y^s \cdot z^t \equiv x \mod n
$$

From here the extractor can recover $x$ $\blacksquare$