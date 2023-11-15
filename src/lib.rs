//! Libraries for higher residue arithmetics
//!
//! - [x] Parameter generation
//!     - [x] Generate random prime r
//!     - [x] Generate related prime p, q and compute n, phi
//!     - [x] Generate y
//! - [x] Parameter challenge
//! - [ ] Encryption
//! - [x] Ballot validity challenge
//! - [ ] Tally and decryption
//! - [ ] Tally challenge
use crypto_bigint::Uint;

/// Use the same big integer type everywhere
pub const LIMBS: usize = 4; // 4 words each 64 bits, a total of 256 bits
pub type BigInt = Uint<LIMBS>;

pub mod arithmetics;
pub mod keys;
pub mod proofs;
