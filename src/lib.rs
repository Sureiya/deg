//! DeG: a Datalog-with-certificates proof language and checker for game
//! client/server reverse engineering.
//!
//! The public surface is intentionally small:
//!
//! * [`parser`] / [`ast`] — the surface language;
//! * [`semantic`] — model indexing and static validation;
//! * [`evidence`] — artifact-grounded evidence evaluators;
//! * [`facts`] — the negation-free derivation engine and strength lattice;
//! * [`kernel`] — proofs, claims, conflicts, obligations, and sealing.

pub mod artifact;
pub mod ast;
pub mod cli;
pub mod evidence;
pub mod ext;
pub mod facts;
pub mod json;
pub mod kernel;
pub mod lexer;
pub mod parser;
pub mod pcap;
pub mod pe;
pub mod port;
pub mod prng;
pub mod report;
pub mod semantic;
pub mod sha256;
pub mod stats;
pub mod stdlib;
pub mod strength;
pub mod value;
pub mod x86;
