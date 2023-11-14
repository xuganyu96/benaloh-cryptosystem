//! Libraries for higher residue arithmetics
//!
//! - [ ] Parameter generation
//!     - [ ] Generate random prime r
//!     - [ ] Generate related prime p, q and compute n, phi
//!     - [ ] Generate y
//! - [ ] Parameter challenge
//! - [ ] Encryption
//! - [ ] Ballot validity challenge
//! - [ ] Tally and decryption
//! - [ ] Tally challenge
use crypto_bigint::Uint;

/// Use the same big integer type everywhere
const LIMBS: usize = 4; // 4 words each 64 bits, a total of 256 bits
pub type BigInt = Uint<LIMBS>;

pub mod arithmetics;
pub mod keys;
pub mod proofs;
