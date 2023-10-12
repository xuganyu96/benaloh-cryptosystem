//! Proof-of-concept implementation
use crypto_bigint::{rand_core::OsRng, Checked, CheckedMul, CheckedSub, NonZero, RandomMod, U512, CheckedAdd};
use crypto_primes;
use std::process;

struct PublicKey {
    /// The multiplicative modulo, n = pq
    n: U512,

    /// The base that will be raised to the power of the plaintext
    y: U512,

    /// The ring modulo
    r: U512,
}

impl PublicKey {
    fn new(n: U512, y: U512, r: U512) -> Self {
        return Self { n, y, r };
    }
}

struct SecretKey {
    /// The Euler totient of the multiplicative modulo
    phi: U512,

    /// The decryption base
    x: U512,
}

impl SecretKey {
    fn new(phi: U512, x: U512) -> Self {
        return Self { phi, x };
    }
}

/// The ambient primes p, q, r
struct Params {
    p: U512,
    q: U512,
    r: U512,
}

impl Params {
    /// Generate a random b such that b >= 2 and b <= r-1
    fn generate_b(r: &NonZero<U512>) -> U512 {
        loop {
            let b = U512::random_mod(&mut OsRng, r);
            if b >= U512::from_u8(2) {
                return b;
            }
        }
    }

    /// Generate some q using the arithmetic sequence (rx + b)
    fn generate_q(r: U512, b: U512) -> U512 {
        let r = Checked::new(r);
        let b = Checked::new(b);

        loop {
            let size = U512::from_u32(u32::MAX);
            let x = U512::random_mod(&mut OsRng, &NonZero::new(size).unwrap());
            let x = Checked::new(x);
            let q = (x * r + b).0.unwrap();
            if crypto_primes::is_prime(&q) {
                return q;
            }
        }
    }

    /// Generate some p using the arithmetic sequence (r^2x + br + 1)
    fn generate_p(r: U512, b: U512) -> U512 {
        let r = Checked::new(r);
        let b = Checked::new(b);

        loop {
            let size = U512::from_u32(u32::MAX);
            let x = U512::random_mod(&mut OsRng, &NonZero::new(size).unwrap());
            let x = Checked::new(x);
            let p = (x * r * r + r * b + Checked::new(U512::ONE)).0.unwrap();
            if crypto_primes::is_prime(&p) {
                return p;
            }
        }
    }

    /// Check the three conditions
    fn validate_ambient_primes(p: U512, q: U512, r: U512) -> bool {
        let r_nz = NonZero::new(r).unwrap();
        // sub_mod assumes the operands to be smaller than the modulo
        if (p % r_nz).sub_mod(&U512::ONE, &r) != U512::ZERO {
            return false;
        }

        let (r_sq, _) = r.square_wide();
        let r_sq_nz = NonZero::new(r_sq).unwrap();
        if (p % r_sq_nz).sub_mod(&U512::ONE, &r_sq) == U512::ZERO {
            return false;
        }

        if (q % r_nz).sub_mod(&U512::ONE, &r) == U512::ZERO {
            return false;
        }

        return true;
    }

    fn generate(size: usize) -> Self {
        let r: U512 = crypto_primes::generate_prime(Some(size));
        let b = Self::generate_b(&NonZero::new(r).unwrap());
        let q = Self::generate_q(r, b);
        let p = Self::generate_p(r, b);

        if !Self::validate_ambient_primes(p, q, r) {
            panic!("PGen failed; please investigate");
        }
        return Self { p, q, r };
    }
}

/// Generate ambient prime p, q, r such that
/// 1. r divides (p-1)
/// 2. gcd(r, (p-1)/r) is 1
/// 3. gcd(r, q-1) is 1
#[allow(unused_variables)]
fn main() {
    let params = Params::generate(8);

    let (n, phi) = compute_n_phi(params.p, params.q);
    let (y, x) = generate_y_x(phi, params.r, n);
    // NOTE: up to here we have the key pairs:
    let pk = PublicKey::new(n, y, params.r);
    let sk = SecretKey::new(phi, x);

    let plaintext = U512::random_mod(&mut OsRng, &NonZero::new(params.r).unwrap());
    let ciphertext = encrypt(&pk, plaintext);
    let decryption = decrypt(&pk, &sk, ciphertext);

    if decryption == plaintext {
        println!("Decryption is correct");
        process::exit(0);
    } else {
        eprintln!("Decryption is {decryption}, plaintext is {plaintext}");
        process::exit(1);
    }
}



/// Compute n <- p * q and phi <- (p-1)(q-1)
fn compute_n_phi(p: U512, q: U512) -> (U512, U512) {
    let p = Checked::new(p);
    let q = Checked::new(q);
    let n = (p * q).0.unwrap();
    let phi = ((p - Checked::new(U512::ONE)) * (q - Checked::new(U512::ONE)))
        .0
        .unwrap();
    return (n, phi);
}

/// Sample an element from the multiplicative group Z_n
fn sample_multgroup(n: NonZero<U512>) -> (U512, U512) {
    loop {
        let y: U512 = U512::random_mod(&mut OsRng, &n);
        let (inverse, choice) = y.inv_mod(&n);
        let choice: bool = choice.into();
        if choice {
            return (inverse, y);
        }
    }
}

/// Naive implementation of modexp, not constant time; not suitable for production
fn vartime_modexp(base: U512, pow: U512, modulo: NonZero<U512>) -> U512 {
    if pow == U512::ZERO {
        return U512::ONE;
    }
    let two = U512::from_u8(2);
    let is_odd_pow = (pow % NonZero::new(two).unwrap()) == U512::ONE;

    if is_odd_pow {
        let halfpow = pow
            .checked_sub(&U512::ONE)
            .unwrap()
            .checked_div(&two)
            .unwrap();
        let (modsquare, _) = vartime_modexp(base, halfpow, modulo).square_wide();
        let modsquare = modsquare % modulo;
        return base.checked_mul(&modsquare).unwrap() % modulo;
    }
    let halfpow = pow.checked_div(&two).unwrap();
    let (modsquare, _) = vartime_modexp(base, halfpow, modulo).square_wide();
    let modsquare = modsquare % modulo;
    return modsquare;
}

/// Sample a valid y such that Y^(phi/r) != 1 (mod n)
fn generate_y_x(phi: U512, r: U512, n: U512) -> (U512, U512) {
    loop {
        let (y, _) = sample_multgroup(NonZero::new(n).unwrap());
        let pow = phi.checked_div(&r).unwrap();
        let x = vartime_modexp(y, pow, NonZero::new(n).unwrap());
        if x != U512::ONE {
            return (y, x);
        }
    }
}

/// Encrypt the message m under the public key (n, y, r)
fn encrypt(pk: &PublicKey, pt: U512) -> U512 {
    let n = NonZero::new(pk.n).unwrap();
    let (u, _) = sample_multgroup(n);
    let ur = vartime_modexp(u, pk.r, n);
    let ym = vartime_modexp(pk.y, pt, n);

    return ym.checked_mul(&ur).unwrap();
}

/// A brute-force discete log, assuming that target is indeed some power of base
fn discrete_log(base: U512, target: U512, modulo: NonZero<U512>, order: U512) -> U512 {
    let mut exp: U512 = U512::ZERO;
    while vartime_modexp(base, exp, modulo) != target {
        if exp >= order {
            panic!("discrete log failed; exponent exceeded order of base");
        }
        exp = exp.checked_add(&U512::ONE).unwrap();
    }

    return exp;
}

/// Decryption, involving some kind of discrete log
fn decrypt(pk: &PublicKey, sk: &SecretKey, ct: U512) -> U512 {
    let n = NonZero::new(pk.n).unwrap();
    let pow = sk.phi.checked_div(&pk.r).unwrap();
    let a = vartime_modexp(ct, pow, n);
    let m = discrete_log(sk.x, a, n, pk.r);
    return m;
}
