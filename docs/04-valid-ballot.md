# Proof of valid ballot
The final interactive proof is for showing that each voter's ballot is valid. In the context of the secret-ballot election, a voter's ballot is defined by a ciphertext $\omega = y^mx^r$ for some $m \in \mathbb{Z}_r$ and some $x \in \mathbb{Z}_n^*$, and the ballot is valid iff $m \in \{0, 1\}$ (in other words, each voter can only be "yes" or "no"). Dishonest voter can instead encrypt a larger number and skew the result of the tally, so we want to be able to show that the ballot is indeed valid, although we don't want to reveal any other information (e.g. the actual vote).

This interactive proof uses a "capsule" for the commitment. A capsule contains tuples of data of certain form, but the order of the data is scrambled so outside observer does not know which piece of data is of which form. Depending on the challenge, the prover either reveals the specific form of each piece of data in the commit, or uses the commitment to demonstrate something about the statement.

- **statement**: $\omega = y^mx^r$, where $m \in \{0, 1\}$
- **commitment**: $(u, v) \in \mathbb{Z}_n^* \times\mathbb{Z}_n^*$, where one of them a random r-th residue (aka a random member of the residue class $0$) $a^r$ and the other is a random member of the residue class of $1$: $yb^r$, but we don't know which is which. This is called the capsule
- **challenge**: The verifier flips a coin: $b \leftarrow \{0, 1\}$
- **response**:  
if $b = 0$, then output $(a, b)$, which reveals the specific form of the capsule  
if $b = 1$ and $c = 0$, then output $x^{-1}a$  
if $b = 1$ and $c = 1$, then output $x^{-1}b$
- **verification**:  
if $b = 0$, then check that $a^r$ and $yb^r$ indeed correspond to the two values in the commitment.  
if $b = 1$, then compute $\omega \cdot \text{response}^r$ and check that the result matches either $u$ or $v$.

From a high level, this proof works by demonstrating that the ballot (aka the statement) is the in the same residue class as the commitment, where the commitment only contains members from the valid residue classes. The commitment has to be honest because there is a chance that the prover needs to demonstrate the content of the commitment, and if the commitment is honest, then the prover can demonstrate the validity of the residue class by showing that the statement and one of the commitment differ by an r-th residue, which itself can be demonstrated by showing an r-th root.

## Proof of soundness
Soundness can be proved using a knowledge extractor. In the context of this proof since the there are only two possible values for the commit, the knowledge obtains both the content of the capsule $a, b$ as well as a response $\rho$. From here we can compute $\omega \cdot \rho^r$ and check: if $\omega \cdot \rho^r$ matches $a^r$ then we know $m = 0$ and if $\omega \cdot \rho^r$ matches $yb^r$ then we know $m = 1$. Hence we have recovered the values of $m$.

## Proof of zero-knowledge
Zero-knowledge property can be demonstrated using a simulator. The simulator has no special knowledge of the statement, so its statement is a random element $\omega \in \mathbb{Z}_n^*$ with an unknown residue class. The simulator then generates $a, b$ and output $(u, v)$ as usual. Upon receiving the challenge $b$, the simulator rewinds the verifier by giving it a different set of commitment:

1. If the challenge is $b = 0$, then the commit stays as it is, and the response remains as it is
2. If the challenge is $b = 1$, first sample a random element $x \leftarrow \mathbb{Z}_n^*$, then compute $u = \omega \cdot x^r$. Output $(u, v)$ as the new commit, where $v$ can be a random element. Finally, output $x$ as the response. This ensures that the verification algorithm will pass.