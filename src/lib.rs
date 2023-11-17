//! Libraries for higher residue arithmetics
use crypto_bigint::Uint;

/// Use the same big integer type everywhere
pub const LIMBS: usize = 256 / 64; // 8 words each 64 bits, a total of 512 bits
pub type BigInt = Uint<LIMBS>;

pub const RINGSIZE: usize = 16;
pub const GROUPSIZE: usize = 64;

pub mod arithmetics;
pub mod keys;
pub mod proofs;
