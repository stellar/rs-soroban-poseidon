//! Poseidon and Poseidon2 cryptographic hash functions for Soroban smart contracts.
//!
//! This crate provides implementations of the Poseidon and Poseidon2 hash functions
//! for use in Soroban smart contracts. These hash functions are commonly used in
//! zero-knowledge proof systems.
//!
//! # Supported Fields
//!
//! Both Poseidon and Poseidon2 support:
//! - **BN254**: The scalar field of the BN254 (alt_bn128) curve
//! - **BLS12-381**: The scalar field of the BLS12-381 curve
//!
//! # Example
//!
//! ```ignore
//! use soroban_sdk::{Env, Symbol, vec, U256, bytesn};
//! use soroban_poseidon::poseidon::{PoseidonConfig, hash};
//!
//! let env = Env::default();
//! let field = Symbol::new(&env, "BN254");
//! let inputs = vec![&env,
//!     U256::from_be_bytes(&env, &bytesn!(&env, 0x0000000000000000000000000000000000000000000000000000000000000001).into()),
//!     U256::from_be_bytes(&env, &bytesn!(&env, 0x0000000000000000000000000000000000000000000000000000000000000002).into()),
//! ];
//! let config = PoseidonConfig::new(&env, field, inputs.len() as u32);
//! let result = hash(&env, &inputs, config);
//! ```

#![no_std]

pub mod poseidon;
pub mod poseidon2;

#[cfg(test)]
mod tests;

// Re-export main types for convenience
pub use poseidon::{hash as poseidon_hash, PoseidonConfig, PoseidonSponge};
pub use poseidon2::{hash as poseidon2_hash, Poseidon2Config, Poseidon2Sponge};
