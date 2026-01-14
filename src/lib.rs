#![no_std]

use soroban_sdk::{crypto::{BnScalar,  bls12_381::Fr as BlsScalar}, symbol_short, Env, Symbol, Vec, U256};

pub mod poseidon;
pub mod poseidon2;

#[cfg(test)]
mod tests;

// Re-export main types for convenience
pub use poseidon::{PoseidonConfig, PoseidonSponge};
pub use poseidon2::{Poseidon2Config, Poseidon2Sponge};


pub trait Field {
    fn symbol() -> Symbol;
}

impl Field for BnScalar {
    fn symbol() -> Symbol {
        symbol_short!("BN254")
    }
}

impl Field for BlsScalar {
    fn symbol() -> Symbol {
        symbol_short!("BLS12_381")
    }
}

/// Computes a Poseidon hash matching circom's
/// [implementation](https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/circuits/poseidon.circom)
/// for input lengths up to 5 (`t ≤ 6`).
///
/// Internally it picks the state size `t` to match the input length, i.e.
/// `t = N + 1` (rate = N, capacity = 1). For example, hashing 2 elements
/// uses t=3.
///
/// Note: use [`poseidon_sponge::hash`] with a pre-constructed
/// [`PoseidonConfig`] directly if:
/// - You want to repeatedly hash with the same input size. Pre-constructing
///   the config saves the cost of re-initialization.
/// - You want to hash larger input sizes. The sponge will repeatedly
///   permute and absorb until the entire input is consumed. This is a valid
///   (and secure) sponge operation, even though it may not match circom's
///   output, which always picks a larger state size (N+1) to hash inputs in
///   one shot (up to t=17). If you need parameter support for larger `t`,
///   please file an issue.
pub fn poseidon_hash<const T: u32, F: Field>(env: &Env, inputs: &Vec<U256>) -> U256 
where
    PoseidonSponge<T, F>: PoseidonConfig<T, F>,
{
    let mut sponge = PoseidonSponge::<T, F>::new(env);
    sponge.hash(inputs)
}

/// Computes a Poseidon2 hash matching noir's
/// [implementation](https://github.com/noir-lang/noir/blob/abfee1f54b20984172ba23482f4af160395cfba5/noir_stdlib/src/hash/poseidon2.nr).
///
/// Internally it always initializes the state with `t = 4`, regardless of
/// input length. It alternates between absorbing and permuting until all
/// input elements are consumed.
///
/// Note: use [`poseidon2_sponge::hash`] with a pre-constructed
/// [`Poseidon2Config`] directly if:
/// - You need to hash multiple times. Pre-constructing the config saves the
///   cost of re-initialization.
/// - You want to use a different state size (`t ≤ 4`).
pub fn poseidon2_hash(env: &Env, field_type: Symbol, inputs: &Vec<U256>) -> U256 {
    const INTERNAL_RATE: u32 = 3;
    let config = Poseidon2Config::new(env, field_type, INTERNAL_RATE);
    poseidon2::hash(env, inputs, config)
}