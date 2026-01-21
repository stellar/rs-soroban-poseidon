#![no_std]

use soroban_poseidon::{poseidon2_hash, Poseidon2Sponge};
use soroban_sdk::{contract, contractimpl, crypto::BnScalar, vec, Env, U256};

#[contract]
pub struct Poseidon2Contract;

#[contractimpl]
impl Poseidon2Contract {
    /// Computes a Poseidon2 hash of [a, b] using the top-level function.
    /// Uses t=3 (rate=2) to hash 2 inputs.
    pub fn hash_two(env: Env, a: U256, b: U256) -> U256 {
        let inputs = vec![&env, a, b];
        poseidon2_hash::<3, BnScalar>(&env, &inputs)
    }

    /// Computes a Poseidon2 hash of [a, b] using the sponge directly.
    pub fn hash_two_sponge(env: Env, a: U256, b: U256) -> U256 {
        let mut sponge = Poseidon2Sponge::<3, BnScalar>::new(&env);
        let inputs = vec![&env, a, b];
        sponge.compute_hash(&inputs)
    }

    /// Hash with t=4 (rate=3) for 3 inputs.
    pub fn hash_three(env: Env, a: U256, b: U256, c: U256) -> U256 {
        let inputs = vec![&env, a, b, c];
        poseidon2_hash::<4, BnScalar>(&env, &inputs)
    }
}

#[cfg(test)]
mod test {
    use soroban_sdk::{Env, U256};

    use crate::{Poseidon2Contract, Poseidon2ContractClient};

    #[test]
    fn test_hash_two() {
        let env = Env::default();
        let contract_id = env.register(Poseidon2Contract, ());
        let client = Poseidon2ContractClient::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);

        let hash = client.hash_two(&a, &b);

        // hash([2, 1]) should be different (Poseidon2 is not commutative)
        let hash_reversed = client.hash_two(&b, &a);
        assert_ne!(hash, hash_reversed);
    }

    #[test]
    fn test_hash_two_sponge() {
        let env = Env::default();
        let contract_id = env.register(Poseidon2Contract, ());
        let client = Poseidon2ContractClient::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);

        let hash = client.hash_two_sponge(&a, &b);

        // Should produce the same result as hash_two
        let expected = client.hash_two(&a, &b);
        assert_eq!(hash, expected);

        // Reversed inputs should also match
        let hash_reversed = client.hash_two_sponge(&b, &a);
        let expected_reversed = client.hash_two(&b, &a);
        assert_eq!(hash_reversed, expected_reversed);
    }

    #[test]
    fn test_hash_three() {
        let env = Env::default();
        let contract_id = env.register(Poseidon2Contract, ());
        let client = Poseidon2ContractClient::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);
        let c = U256::from_u32(&env, 3);

        let hash = client.hash_three(&a, &b, &c);

        // Call again - should be deterministic
        let hash2 = client.hash_three(&a, &b, &c);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_deterministic() {
        let env = Env::default();
        let contract_id = env.register(Poseidon2Contract, ());
        let client = Poseidon2ContractClient::new(&env, &contract_id);

        let a = U256::from_u32(&env, 42);
        let b = U256::from_u32(&env, 123);

        // Call twice - should get the same result
        let hash1 = client.hash_two(&a, &b);
        let hash2 = client.hash_two(&a, &b);
        assert_eq!(hash1, hash2);
    }
}

/// WASM contract tests - imports the compiled WASM and tests it
#[cfg(test)]
mod wasm_test {
    use soroban_sdk::{Env, U256};

    mod poseidon2_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/release/test_poseidon2_contract.wasm"
        );
    }

    #[test]
    fn test_wasm_poseidon2() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let contract_id = env.register(poseidon2_contract::WASM, ());
        let client = poseidon2_contract::Client::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);
        let c = U256::from_u32(&env, 3);

        // Test hash_two
        let hash = client.hash_two(&a, &b);

        // Poseidon2 is not commutative
        let hash_reversed = client.hash_two(&b, &a);
        assert_ne!(hash, hash_reversed);

        // hash_two_sponge should produce the same result as hash_two
        let hash_sponge = client.hash_two_sponge(&a, &b);
        assert_eq!(hash_sponge, hash);

        // Deterministic: calling twice gives the same result
        let hash2 = client.hash_two(&a, &b);
        assert_eq!(hash, hash2);

        // Test hash_three (t=4, rate=3)
        let hash3 = client.hash_three(&a, &b, &c);
        let hash3_again = client.hash_three(&a, &b, &c);
        assert_eq!(hash3, hash3_again);
    }
}
