//! A number of proofs used to show that the government and the voters are acting in accordance to
//! protocol at various stages of the election. There are three main areas:

pub mod decide; // prove that residue class can be correctly decided
pub mod rc; // prove that the residue class known
pub mod tally;

pub mod ballot;
pub mod consonance;
