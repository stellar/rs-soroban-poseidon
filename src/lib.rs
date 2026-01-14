#![no_std]

use soroban_sdk::{
    crypto::{bls12_381::Fr as BlsScalar, BnScalar},
    symbol_short, Env, Symbol, Vec, U256,
};

pub mod poseidon;
pub mod poseidon2;

#[cfg(test)]
mod tests;

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
/// [implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom).
///
/// # Type Parameters
///
/// - `T`: State size. Must be ≥ `inputs.len() + 1` (rate = T-1, capacity = 1).
/// - `F`: Field type. Use [`BnScalar`] for BN254 or [`BlsScalar`] for BLS12-381.
///
/// # Supported Configurations
///
/// - BN254: `T` ∈ {2, 3, 4, 5, 6} (i.e., 1–5 inputs)
/// - BLS12-381: `T` ∈ {2, 3, 4, 5, 6} (i.e., 1–5 inputs)
///
/// # Example
///
/// ```
/// use soroban_sdk::{bytesn, crypto::BnScalar, vec, Env, U256};
/// use soroban_poseidon::poseidon_hash;
///
/// let env = Env::default();
///
/// // Hash two field elements (t=3)
/// let inputs = vec![
///     &env,
///     U256::from_u32(&env, 1),
///     U256::from_u32(&env, 2),
/// ];
/// let hash = poseidon_hash::<3, BnScalar>(&env, &inputs);
///
/// // Matches circom's Poseidon([1, 2])
/// let expected = U256::from_be_bytes(
///     &env,
///     &bytesn!(&env, 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a).into(),
/// );
/// assert_eq!(hash, expected);
/// ```
///
/// # Repeated Hashing
///
/// For repeated hashing, create a [`PoseidonSponge`] once and call
/// `compute_hash()` multiple times. This reuses the pre-initialized parameters
/// (MDS matrix and round constants), but each hash computation is independent,
/// i.e. the sponge state is reset between calls:
///
/// ```
/// # use soroban_sdk::{crypto::BnScalar, vec, Env, U256};
/// # use soroban_poseidon::PoseidonSponge;
/// # let env = Env::default();
/// let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
///
/// let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
/// let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];
///
/// let h1 = sponge.compute_hash(&inputs1); // fresh hash
/// let h2 = sponge.compute_hash(&inputs2); // another fresh hash (state was reset)
/// ```
pub fn poseidon_hash<const T: u32, F: Field>(env: &Env, inputs: &Vec<U256>) -> U256
where
    PoseidonSponge<T, F>: PoseidonConfig<T, F>,
{
    let mut sponge = PoseidonSponge::<T, F>::new(env);
    sponge.compute_hash(inputs)
}

/// Computes a Poseidon2 hash matching noir's
/// [implementation](https://github.com/noir-lang/noir/blob/master/noir_stdlib/src/hash/poseidon2.nr).
///
/// # Type Parameters
///
/// - `T`: State size. Must be ≥ `inputs.len() + 1`. Common usage is `T=4`
///   (rate=3) matching noir's default.
/// - `F`: Field type. Use [`BnScalar`] for BN254 or [`BlsScalar`] for
///   BLS12-381.
///
/// # Supported Configurations
///
/// - BN254: `T` ∈ {2, 3, 4} (i.e., rate = 1, 2, or 3)
/// - BLS12-381: `T` ∈ {2, 3, 4} (i.e., rate = 1, 2, or 3)
///
/// # Capacity Initialization
///
/// The capacity element is initialized to `inputs.len() << 64`, matching noir's
/// Poseidon2 implementation.
///
/// # Example
///
/// ```
/// use soroban_sdk::{crypto::BnScalar, vec, Env, U256};
/// use soroban_poseidon::poseidon2_hash;
///
/// let env = Env::default();
///
/// // Hash three field elements (t=4, rate=3)
/// let inputs = vec![
///     &env,
///     U256::from_u32(&env, 1),
///     U256::from_u32(&env, 2),
///     U256::from_u32(&env, 3),
/// ];
/// let hash = poseidon2_hash::<4, BnScalar>(&env, &inputs);
/// ```
///
/// # Repeated Hashing
///
/// For repeated hashing, create a [`Poseidon2Sponge`] once and call
/// `compute_hash()` multiple times. This reuses the pre-initialized parameters
/// (diagonal matrix and round constants), but each hash computation is
/// independent, i.e. the sponge state is reset between calls:
///
/// ```
/// # use soroban_sdk::{crypto::BnScalar, vec, Env, U256};
/// # use soroban_poseidon::Poseidon2Sponge;
/// # let env = Env::default();
/// let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
///
/// let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
/// let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];
///
/// let h1 = sponge.compute_hash(&inputs1); // fresh hash
/// let h2 = sponge.compute_hash(&inputs2); // another fresh hash (state was reset)
/// ```
pub fn poseidon2_hash<const T: u32, F: Field>(env: &Env, inputs: &Vec<U256>) -> U256
where
    Poseidon2Sponge<T, F>: Poseidon2Config<T, F>,
{
    let mut sponge = Poseidon2Sponge::<T, F>::new(env);
    sponge.compute_hash(inputs)
}
