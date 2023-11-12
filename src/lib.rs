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
use crypto_bigint::U256;

/// Use the same big integer type everywhere
type BigInt = U256;

pub mod keys;
pub mod proofs;
