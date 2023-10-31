# Josh Benaloh's verifiable secret-ballot election scheme
In 1987, Josh Benaloh (a senior cryptography at Microsoft Research) described in his doctoral dissertation an electronic voting scheme that uses cryptographic constructions with homomorphic properties to achieve what could only be described as "dark magic" by someone without a cryptography background. The 1987 electronic voting scheme enjoys some particularly desirable characteristics:

- Every voter's ballot is cryptographically secured
- Every voter's ballot can be mathematically proven to have been counted
- Many more

This project aims to provide a more digestable recap (suitable for undergraduate-level of mathematics) of the 1987 dissertation alongside a number of improvements that are made possible by development in cryptography after 1987, including the Fiat-Shamir heuristics that can convert several of the iteracitve proofs into non-interactive proofs for efficiency gains.

This write-up reorganizes the original dissertation so that we open with a naive voting scheme (so it's more engaging), then proceed to identify various problems with the voting scheme that then is each addressed. Mathematical rigor will only be introduced as necessary so as to keep the material easily digestable and highly motvated.

**Table of content**

1. [A naive electronic voting scheme](./01-naive-election.md)
2. [Malicious last voter](./02-r-th-residue-proof.md)
3. [Dishonest parameters](./03-consonant-parameters.md)