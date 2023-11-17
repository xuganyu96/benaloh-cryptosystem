- [Introduction](#verifiable-secret-ballot-election)
- [Homomorphic encryption scheme](#homomorphic-encryption-scheme)
- [Naive election scheme](#a-naive-election-scheme)
    - [Last voter's attack](#the-last-voters-attack)
    - [Invalid ballot](#invalid-ballot)
    - [Corrupt parameters](#invalid-parameters)
    - [Simple election scheme](#a-simple-election-scheme)
- [Implementation](#implementation)
    - [Sizes of parameters](#sizes-of-the-parameters)
    - [Generating perfect consonance](#generating-perfect-consonance)
    - [Hash function](#hash-functions)
- [What's next](#whats-next)
    - [A better election scheme](#a-better-election-scheme)
    - [Better implementation](#better-implementation)
- [References](#references)


# Verifiable secret-ballot election
In his 1987 PhD thesis "[verifiable secret-ballot election](https://www.microsoft.com/en-us/research/wp-content/uploads/1987/01/thesis.pdf)", Josh Benaloh described a public-key cryptosystem whose homomorphic properties makes it suitable for being adapted into a secret-ballot election scheme. This project is an attempt at implementing the cryptosystem and the election scheme using the Rust programming language.

In addition to the homomorphic encryption scheme, Benaloh also described a number of interactive proofs that can be used to ensure that the various parties (mostly the election authority and the voters) can prove to each other that they are behaving in accordance with the protocol. In this project, a few improvements are made to these interactive proofs, including applying Fiat-Shamir transformation and increasing the confidence of the proof.

In this write-up, we will first summarize the public-key cryptosystem and describe a naive election scheme. Then we will motivate the interactive proofs by describing a few ways in which dishonest party can corrupt the result or breach privacy. Finally, we will present the interactive proofs that can be used to detect and prevent the bad actions.

# Homomorphic encryption scheme
The encryption scheme contains five main components: parameter generation, key generation, encryption, ciphertext aggregation, and decryption.

1. $(r, n, y) \leftarrow \mathop{\text{PGen}}(1^\lambda)$, where
    - $r$ is a prime number
    - $n = pq$ is the product of two prime numbers
    - $r \mid p-1$, $r \nmid \frac{p-1}{r}$, $r \nmid (q-1)$
    - $y \in \mathbb{Z}_n^*$ and $y^\frac{\phi}{r} \not\equiv 1 \mod n$, where $\phi = \phi(n)$ is the Euler totient function.
2. $\mathop{\text{KeyGen}}$ trivially uses the generated parameters: the public key is the triplet $(r, n, y)$. The secret key is the Euler's tuotient's $\phi(n)$
3. To encrypt a message $m \in \mathbb{Z}_r$, sample a random element $x \leftarrow \mathbb{Z}_n^*$ and compute the quantity $c = y^mx^r \mod n$. $c \in \mathbb{Z}_n$ is the ciphertext.
4. To decrypt the ciphertext, first raise it to the power of $\frac{\phi}{r}$, then solve the discrete log problem $c^\frac{\phi}{r} \equiv (y^\frac{\phi}{r})^m \mod n$ with respect to $m$

In Benaloh's thesis, the triplet $(r, n, y)$ that satisfies the conditions in the parameter generation is called the "perfect (prime) consonance". With a perfect prime consonance prime, every element $z \in \mathbb{Z}_n^*$ has a unique decomposition

$$
z = y^cx^r
$$

For some $c \in \mathbb{Z}_r$ in the integer ring $\mod r$ and some $x \in \mathbb{Z}_n^*$. The number $c \in \mathbb{Z}_r$ is called the residue class of the element $z$, and the number $x$ is called the witness.

From a high level, the IND-CPA security of this scheme is conditioned on the conjectured hardness of distinguishing higher residuosity, which itself is a generalization of the conjectured hardness of distinguishing quadratic residue from quadratic non-residue.

This cryptosystem exhibits homomorphic properties, where the residue class of the product of two ciphertexts is exactly the sum of the residue classes of the individual ciphertexts. This property allows this cryptosystem to be adapted into a secret-ballot election scheme: each voter encrypts the vote ("no" or "yes", encoded as 0 and 1 respectively) and publishes teh ciphertext, then the election authority collects all ciphertexts, compute their product, and decrypt the product to reveal the final tally.

# A naive election scheme
Here we describe a naive election scheme based on the cryptosystem described above and its homomorphic properties.

1. The election authority generates the parameters $(r, n, y)$ and the secret key $\phi$, then publishes the public key $(r, n, y)$.
2. Each registered voter encrypts either $0$ or $1$ $w_i = y^c_ix_i^r$ (respectively encoding a "no" vote and a "yes" vote), then publishes the ciphertext $w$. The voter keeps a record of the decomposition.
3. After all voters have published their ciphertexts, the election authority computes the product of all ciphertexts $w = \prod_{i \in \text{voters}} w_i$, then uses the secret key to decide the residue class $c$. Based on the homomorphic property of the cryptosystem, we know $c = \sum_{i \in \text{voters}} c_i$ is the sum of all votes and thus the number of "yes" votes.
4. The election authority publishes the final tally by showing the decomposition of the product of the ciphertexts.

Already, this election has the very desirable combination of confidentiality and verifiability: each opaque ballot does not reveal any information about the vote that each voter casts, but because all individual ciphertexts are public, anyone can compute the product of the ciphertexts and verify that the final decomposition is correct, thus verifying the final tally to be legitimate.

Unfortunately, this naive scheme also suffers from many problems that can happen when one or the other parties acts dishonestly. Here are three of them and how they are addressed using zero-knowledge proof.

## The last voter's attack
Recall from basic number theory that, given a pair of non-trivial square root of some element $x \in \mathbb{Z}_n^*$, there is a non-negligible chance that $n$ can be factored. Similarly, given two distinct r-th root of some element $x \in \mathbb{Z}_n^*$, there is also a non-negligible chance of factoring $n$. This means that if someone other than the election official can obtain such distinct root, he/she can compute the secret key $\phi$ and thus be able to see the vote of other voters, thus breaching the confidentiality.

Unfortunately, with the naive election scheme, the last voter can manipulate his vote in such a way that he/she can obtain two distinct r-th root. One of the r-th root is randomly generated $x^\prime \leftarrow \mathbb{Z}_n^*$, and the last voter can compute the multiplicative inverse of the product of all other ciphertexts, then generate the following ciphertext:

$$
w_\text{last} = (\prod_\text{all other voters}w_i)^{-1}(x_\text{last})^r
$$

When an honest election officials compute the product of all ciphertext, they will end up with

$$
\begin{aligned}
\prod_\text{all voters}w_i &= (\prod_\text{all other voters}w_i)^{-1} \cdot w_\text{last} \\
&= x_\text{last}^r
\end{aligned}
$$

From here, when the election officials release the decomposition, they will end up releasing a second r-th root of $(x_\text{last})^r$. Since $x_\text{last}$ is randomly sampled and each r-th residue has exactly $r$ distinct roots under the perfect consonance, the chance that the two roots are distinct is $\frac{r-1}{r}$, which is non-negligible. The honesty of the election officials here is important because dishonest officials can simply decrypt the individual votes and will be able to find out that the last vote is invalid.

One way to mitigate the last voter's attack is to simply not release the decomposition of the final product. However, without release the decomposition, the election officials need to find another way to convince the public that the announced tally is correct. This can be done because under perfect consonance, two elements $w_1, w_2 \in \mathbb{Z}_n^*$ belong to the same residue class if and only if $w_1w_2^{-1}$ is an r-th residue, which means that the government can prove that the final product belongs to residue class $c$ by proving that $wy^{-c}$ is an r-th residue.

Here a zero-knowledge proof can be used to prove that $wy^{-c}$ is r-th residue without revealing additional information. The core idea of the proof is that the election officials first produce a second r-th residue $z^\prime = {x^\prime}^r$, which we will call the "commitment". The voter then challenges the election officials with a random coin flip: if tail comes up, the election officials release the decomposition of the commitment; if head comes up, the election officials release the decomposition of the product $zz^\prime$. Once the decomposition is released, it is easy to verify that the decomposition is legitimate: the voter raises the decomposition to the r-th power and check equality with the corresponding quantity. It should be easy to see that an honest election official can prove to an honest voter.

If the election officials are dishonest (say they want to claim a bogus tally $c^\prime$ and try to convince the voter that $wy^{-c^\prime}$ is an r-th residue even though it is not), they can only cheat the proof by guessing the challenge ahead of time: if they know the challenge to ask for the decomposition fo the commitment, then they produce a legitimate r-th residue for the commitment; if they know the challenge to ask for the decomposition of the product, then they produce an equally bogus commitment such that the product $wy^{c^\prime} \cdot z'$ is an r-th residue. This means that dishonest election officials have a 50% chance of cheating the proof in a single run, and honest voters can increase their confidence in the proof by repeatedly running it. We will also present an improvement at the end of this section that reduces of chance of cheating from 50% to $\frac{1}{r}$. On the other hand, this proof can be proved to leak no other information. This is true because $z'$ and $zz'$ are a statistically random elements that the voters themselves could have generated anyways.

Notice that the proof requires interaction between the election officials and the voters. In practice this could mean that the election officials will need to run a server that accepts random challenges from voters, and that voters need to actively generate challenges and verify the results. It's not hard to see that the interactivity can be cumbersome and costly, and it would be desirable if the election officials can simply publish a non-interactive proof that does not require input from the voters. This can be done using the [Fiat-Shamir transformation](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic), which replaces the randomly generated and interactive challenge with a hash function that maps the commitment into the challenge. In theory, we model the hash function as a random oracle, so we get to eliminate the interactivity while the challenge remains "random". In practice, we can use a strong hash function that is as close to "random oracle" as possible, such as SHA-3.

Here is the sigma-protocol for the proof of r-th residue:

- **statement**: $z$, where $z = x^r$ is an r-th residue
- **commitment**: $z'$, where $z' = {x'}^r$ is a randomly sampled r-th residue
- **challenge**: $b = H(z')$, where $H: \mathbb{Z}_n^* \rightarrow \mathbb{Z}_r$ is a hash function
- **response**: $x'x^b$
- **verification**: Check equality $(x'x^b)^r \equiv z'z^b$

## Invalid ballot
Dishonest voters can also try to corrupt the result of the election by encrypting other values than 0 or 1, so it is important to have some way to check that each ciphertext indeed belongs to either residue classs 0 or 1 without revealing other information. Similar to the proof of valid tally, an interactive proof (that is later converted to non-interactive proof via Fiat-Shamir) can be used to by the voters to convince the election officials that the their ballots are indeed valid.

The voter demonstrates that the residue class of the ciphertext is either 0 or 1 by presenting a "capsule" that contains two elements each being a random sample from the residue class 0 and 1 respectively, without revealing each capsule element belongs to which class. Again the election officials challenge with a coin flip: if tail comes up, the voter "opens the capsule" by revealing which capsule element belongs to which residue class through their decomposition; if the head comes up, the voter "consumes the capsule" by revealing the decomposition of $ww'^{-1}$, where $w$ is the ciphertext, and the $w'$ is the capsule element with the same residue class as the ciphertext.

Similar to the r-th residue proof, the voter can only cheat the proof by guessing the challenge ahead of time, and the election officials can require the voter to generate more capsules to repeat proofs, thus increasing the confidence. Finally, we can replace the challenge with a hash of the capsule(s), so the voter can non-interactively demonstrate the validity of the ballot.

- **statement**: $w$, where $w = y^cx^r$ and $c \in \{0, 1\}$
- **commitment**: $\{(u, v)\}_{i=1}^N$, where within each pair one of them is $a_i^r$ and the other is $yb_i^r$, but we don't know which is which
- **challenge**: $H: Z_n^* \times Z_n^* \rightarrow \{0, 1\}$, which takes a commitment and returns a coin toss
- **response**: if $H(\text{commitment}_i) = 0$, return $(a_i, b_i)$ in the order of the individual element in order. If $H(\text{commitment}_i) = 1$, return $x^{-1}z$, where $z = a$ if $c = 0$ and $z = b$ if $c = 1$.
- **verify**: if $H(\text{commitment}_i) = 0$, check that each decomposition is correct. if $H(\text{commitment}_i) = 1$, check that $w \cdot \text{response}^r$ is equal to one of the capsule element

## Invalid parameters
Dishonest election officials can generate incorrect parameters that allow the election officials to claim incorrect tally and still produce valid proof. For example, if $r, \phi$ are relatively prime instead of $\gcd(r, \phi) = r$, then all elements of $Z_n^*$ are r-th residue, and the election officials can demonstrate $wy^{-c}$ to be an r-th residue for arbitrary $c$.

A solution to this is an interactive proof in which the election officials demonstrate that they can correctly identify the residue class of randomly generated ciphertexts. In other words, voters first generate random elements from random residue class, then ask the election officials to identify the residue class. If the parameters are generated incorrectly, then there are fewer residue classes than $r$; in fact, it can be shown that the number of distinct residue classes must divide $r$, so if we set $r$ to be prime, then dishonest parameters correspond to only one residue class, and the election officials will only have $\frac{1}{r}$ probability of correctly guessing the residue class.

The problem with the solution above is that dishonest voter can take advantage of an honest election authority and challenge the authority to decrypt ciphertexts that the voter did not generate himself. To mitigate the possibility of the election authority unwillingly becoming a decryption oracle, the challenge ciphertext must also be accompanied by a proof that the voter already knows the residue class of the challenge ciphertext. Such proof follows the classic Fiat-Shamir transformation:

- **statement**: $w \in \mathbb{Z}_n^*$ where $w = y^cx^r$
- **commitment**: $w' \in \mathbb{Z}_n^*$ where $w' = y^{c'}{x'}^r$
- **challenge**: $b \leftarrow H(w')$, where $H: \mathbb{Z}_n^* \rightarrow \mathbb{Z}_r$ is a hash function
- **response**: $c' + bc$
- **verification**: $ww'y^{-(c' + bc)}$ is an r-th residue, which can be done because the verifier is the election authority, who has the secret key $\phi$

Unfortuantely, the proof that there are $r$ distinct residue class has no straightforward non-interactivity conversion. This remains the only proof that has to be interactive.

1. Voter generates a random ciphertext $w = y^cx^r$ and produces a proof as described above
2. Election authority verifies voter's proof, then uses the secret key to decrypt $w$
3. Election authority sends the decryption to the voter, and the voter verifies that the decryption is correct
4. Repeat step 1-3 many times to increase the confidence of the proof

## A simple election scheme
We now incorporate the four proofs described above into the naive election scheme and present a simple election scheme:

1. Election authority generates the key pair and publishes the public key
2. Voters submit challenge ciphertexts to election authority and verify that the authority can correctly identify the residue classes
3. Voters compute their ballots, including the proof of ballot validity, and publishes both the secret ballot and the proof
4. Election authority verifies all ballot proofs and compute the product of all ciphertexts
5. Election authority computes the residue class of the product as the final tally, then repleases the proof of r-th residue

# Implementation
This repository includes a Rust implementation of the cryptosystem, the interactive/non-interactive proofs, and a simulated election. I suggest beginnning with the [simulated election](./src/bin/simple_election.rs). The cryptosystem library is organized as follows:

- [arithmetics.rs](src/arithmetics.rs) contains transparent and opaque representation of higher residue, corresponding to plaintext and ciphertexts respectively
- [keys.rs](src/keys.rs) contains the methods used to generate the triplet $(r, n, y)$ and the key pair
- [proofs](src/proofs/mod.rs) contains sub-modules each implementing a proof
    - [consonance.rs](src/proofs/consonance.rs) implements the proof of triplet consonance, which includes "voter demonstrates knowledge of residue class" and "election authority demonstrates residue class"
    - [ballot.rs](src/proofs/ballot.rs) implements the proof that the ballot is valid
    - [tally.rs](src/proofs/tally.rs) implements the proof that $wy^{-c}$ is an r-th residue

To run the simple election:

```bash
cargo run --bin simple_election
```

To run tests

```bash
cargo test
```

Add `--profile release` or tweak the ring/group/BigInt sizes to tune performance (large ring/group/BigInt sizes can slow down performance substantially).

## Sizes of the parameters
In the context of the election scheme, $r$ should be chosen according to the approximate number of voter sizes. For reference, a 30-bit $r$ can accommodate more than 1 billion voters. However, we should choose $r$ to be as small as possible since the decryption involves a step of solving discrete log with the solution being unique up to $r$; for a constant time guaratee, we will probably want to iterate through all $r$ possible values, so large values of $r$ will make decryption slow.

The size of $p, q$ decides the security of the cryptosystem, and I think typical RSA security levels should be sufficient.

## Generating perfect consonance
While generating the $r$ in the triplet $(r, n, y)$ is straightforward, generating the primes $p, q$ such that $(r, n, y)$ is a perfect consonance is non trivial. In Benaloh's thesis, an arithmetic sequence is used to generate $p, q$ such that $\gcd(r, \phi) = r$. Specifically:

- $p = r^2x + rb + 1$
- $q = rx + b + 1$

where $b$ is randomly sampled from $\{1, 2, \ldots, r-1\}$ (in other words $b$ is a random non-trivial remainder), and $x$ is simply a random integer. It can be shown that because prime numbers are abundant, prime numbers are also abundant alongside the arithmetic sequences above, so we can generate them efficiently.

However, knowing $p-1$ and/or $q-1$ being smooth makes factoring $n$ easier, it might be advantageous to further restrict $p, q$ to also be safe primes (Sophie-Germain primes). Unfortunately, this probably impossible with $p$ because $r \mid (p-1)$.

## Hash functions
In each of the non-interactive proof, the hash function is implemented using SHA3-256. Where the output is an integer, the 256-bit output is interpreted as a big-endian representation, which is okay since $r$ will likely only take 30-40 bits, so a 256-bit pseudorandom output will not harm the level of entropy.

In the ballot proof where the challenge is "choosing subset", an optimization is performed where the hash is computed over all 256 capsules, and each of the 256 bits of the hash represents whether the corresponding capsule is to be opened or consumed.

# What's next
## A better election scheme
At this moment, there is a glaring issue with the simple election scheme, which is the existence of a single election authority who can decrypt any ciphertext. Even if we trust the intention of the election authority (which is a BIG if), the existence of a single master key leaves a big target to be stolen, lost, or otherwise grossly mismanaged.

Benaloh did propose in the second half of the thesis the scheme of homomorphic secret sharing, which breaks up the single decryption key into many pieces to be managed by many election authority so that no such "single master key" needs to be maintained. Unfortunately I ran out of time and would have to come back to it.

## Better implementation
Performance is also a major issue of this implementation. On an M1 MacBook Air, the election scheme is simulated with a 16-bit $r$, 64-bit $p, q$, and it is already slowing down significantly. In a real election, say with the population of the United States (around 300 mil), we will need $r$ to be at least 30-bits, and RSA levels of security will require $p, q$ to be around 1024 bits, and the current level of performance, including the brute-force discrete log used in the decryption, is definitely not sufficient.

# References
- [(Benaloh, '87) Verifiable secret-ballot election](https://www.microsoft.com/en-us/research/wp-content/uploads/1987/01/thesis.pdf)