# Generate ambient primes
The `crypto-bigint` crate is used for providing large integer arithmetics.

- [crates.io](https://crates.io/crates/crypto-bigint)
- [docs.rs](https://docs.rs/crypto-bigint/latest/crypto_bigint/)

The `crypto-prime` crate is used to perform primality test

## A naive PGen that doesn't work
- Generate p, q, r as random primes using prime-crypto
- Compute $(p - 1) \mod r$. If the modulo is 0, then $r$ divides $p - 1$

This scheme doesn't work since blindly generating random $r$ is not likely to give a divisor. However, the code snippet is useful for illustrating how arithmetics work in `crypto-bigint`

```rust
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::{Checked, NonZero, U256};
use crypto_primes;

fn main() {
    let p: U256 = crypto_primes::generate_safe_prime_with_rng(&mut OsRng, Some(256));
    let mut r: U256;
    let mut remainder: U256 = U256::ONE;

    while remainder != U256::ZERO {
        r = crypto_primes::generate_prime_with_rng(&mut OsRng, Some(32));
        // Check that r divides (p - 1)
        remainder =
            (Checked::new(p) - Checked::new(U256::ONE)).0.unwrap() % NonZero::new(r).unwrap();
        println!("remainder is {remainder}");
    }
}
```

## A correct way of PGen
1. First generate random prime $r$
1. randomly select $b \leftarrow \{2, 3, \ldots, r-1\}$
1. randomly select $q$ from the sequence $rx + b$ (for some random $x$)
1. randomly select $p$ from the sequence $r^2x + br + 1$

For when you are sampling for $p, q$, if the sample is not prime (using primality test) or is not large enough, then simply reject the sample and try again

```rust
use crypto_bigint::{rand_core::OsRng, Checked, NonZero, RandomMod, U256};
use crypto_primes;

/// Generate ambient prime p, q, r such that
/// 1. r divides (p-1)
/// 2. gcd(r, (p-1)/r) is 1
/// 3. gcd(r, q-1) is 1
fn main() {
    let r: U256 = crypto_primes::generate_prime(Some(32));
    println!("r is {r}");

    let b = generate_b(&NonZero::new(r).unwrap());
    println!("b is {b}");

    let q = generate_q(r, b);
    println!("q is {q}");

    let p = generate_p(r, b);
    println!("p is {p}");

    if validate_ambient_primes(p, q, r) {
        println!("Valid ambient primes!");
    }
}

/// Generate a random b such that b >= 2 and b <= r-1
fn generate_b(r: &NonZero<U256>) -> U256 {
    loop {
        let b = U256::random_mod(&mut OsRng, r);
        if b >= U256::from_u8(2) {
            return b;
        }
    }
}

/// Generate some q using the arithmetic sequence (rx + b)
fn generate_q(r: U256, b: U256) -> U256 {
    let r = Checked::new(r);
    let b = Checked::new(b);

    loop {
        let size = U256::from_u32(u32::MAX);
        let x = U256::random_mod(&mut OsRng, &NonZero::new(size).unwrap());
        let x = Checked::new(x);
        let q = (x * r + b).0.unwrap();
        if crypto_primes::is_prime(&q) {
            return q;
        }
    }
}

/// Generate some p using the arithmetic sequence (r^2x + br + 1)
fn generate_p(r: U256, b: U256) -> U256 {
    let r = Checked::new(r);
    let b = Checked::new(b);

    loop {
        let size = U256::from_u32(u32::MAX);
        let x = U256::random_mod(&mut OsRng, &NonZero::new(size).unwrap());
        let x = Checked::new(x);
        let p = (x * r * r + r * b + Checked::new(U256::ONE)).0.unwrap();
        if crypto_primes::is_prime(&p) {
            return p;
        }
    }
}

/// Check the three conditions
fn validate_ambient_primes(p: U256, q: U256, r: U256) -> bool {
    let r_nz = NonZero::new(r).unwrap();
    // sub_mod assumes the operands to be smaller than the modulo
    if (p % r_nz).sub_mod(&U256::ONE, &r) != U256::ZERO {
        return false;
    }

    let (r_sq, _) = r.square_wide();
    let r_sq_nz = NonZero::new(r_sq).unwrap();
    if (p % r_sq_nz).sub_mod(&U256::ONE, &r_sq) == U256::ZERO {
        return false;
    }

    if (q % r_nz).sub_mod(&U256::ONE, &r) == U256::ZERO {
        return false;
    }

    return true;
}

```