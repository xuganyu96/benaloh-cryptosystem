# Naive election procedure and problems
We first describe a naive election procedure using the [election encryption algorithm](./election-encryption-algo.md) alone, then we will list five problems with the naive procedure.

## The procedure
1. The moderator generates the key pair $\text{pk} = (r, n, y)$ and $\text{sk} = (x, \phi)$. The public key is published.
2. Each voter chooses plaintext $m_i \leftarrow \{0, 1\}$, then performs the encryption using the published public key: $c_i \leftarrow y^mu^r \mod n$ for some randomly sampled $u \leftarrow \mathbb{Z}_n^*$. Each ciphertext $c_i$ is published.
3. The moderator computes the product of all ciphertexts $W = \prod c_i \mod n$, then decrypts the result. The decryption is the sum of all votes $\text{Dec}(\text{sk}, \prod c_i) = \sum m_i$, hence the tally.

## Problem 1: corrupt parameters
There is currently no guarantee that the parameters are generated correctly. When the parameters are not generated correctly, the tally can become corrupted.

For example, suppose instead of having $\gcd(r, \phi) = r$ we have $\gcd(r, \phi) = 1$, then all elements of $\mathbb{Z}_n^*$ are $r^\text{th}$ residue.

**proof**: Because $\gcd(r, \phi) = 1$, there exists integers $s, t$ such that $s \cdot r + t \cdot \phi = 1$, which means that $y^{sr + t\phi} \equiv y \mod n$. However, we can manipulate the LHS:

$$
\begin{aligned}
y^{sr + t\phi} &\equiv y^{sr}{(y^\phi)}^t \mod n \\
&\equiv (y^s)^r \mod n
\end{aligned}
$$

So $y \equiv (y^s)^r \mod n$, which implies that $y$ is an r-residue.

Recall that ciphertexts of different plaintexts are distinguished by the residue class that the ciphertext belongs to. When $\gcd(r, \phi) = 1$, all ciphertexts belong to the residue class $\text{RC}[0]$, so there is no distinction between ciphertext distribution across different plaintexts.

**Conclusion**: the moderator needs to be able to prove to the voters that the parameters are indeed valid, but the moderator does not want to expose $\phi(n)$ or leak other information that might help factor $n$

## Problem 2: invalid vote
A misbehaving voter might choose $m > 1$, which can mess up the tally.

## Problem 3: 