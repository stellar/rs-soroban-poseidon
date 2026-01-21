#![no_std]

use soroban_poseidon::{poseidon_hash, PoseidonSponge};
use soroban_sdk::{contract, contractimpl, crypto::BnScalar, vec, Env, U256};

#[contract]
pub struct PoseidonContract;

#[contractimpl]
impl PoseidonContract {
    /// Computes a Poseidon hash of [a, b] using the top-level function.
    pub fn hash_two(env: Env, a: U256, b: U256) -> U256 {
        let inputs = vec![&env, a, b];
        poseidon_hash::<3, BnScalar>(&env, &inputs)
    }

    /// Computes a Poseidon hash of [a, b] using the sponge directly.
    pub fn hash_two_sponge(env: Env, a: U256, b: U256) -> U256 {
        let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
        let inputs = vec![&env, a, b];
        sponge.compute_hash(&inputs)
    }
}

#[cfg(test)]
mod test {
    use soroban_sdk::{bytesn, Env, U256};

    use crate::{PoseidonContract, PoseidonContractClient};

    #[test]
    fn test_hash_two() {
        let env = Env::default();
        let contract_id = env.register(PoseidonContract, ());
        let client = PoseidonContractClient::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);

        let hash = client.hash_two(&a, &b);

        // hash([1, 2]) - known value from circom
        let expected = U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
            )
            .into(),
        );
        assert_eq!(hash, expected);

        // hash([2, 1]) should be different (Poseidon is not commutative)
        let hash_reversed = client.hash_two(&b, &a);
        assert_ne!(hash, hash_reversed);
    }

    #[test]
    fn test_hash_two_sponge() {
        let env = Env::default();
        let contract_id = env.register(PoseidonContract, ());
        let client = PoseidonContractClient::new(&env, &contract_id);

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
    fn test_hash_deterministic() {
        let env = Env::default();
        let contract_id = env.register(PoseidonContract, ());
        let client = PoseidonContractClient::new(&env, &contract_id);

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
    use soroban_sdk::{bytesn, Env, U256};

    mod poseidon_contract {
        soroban_sdk::contractimport!(
            file = "../../target/wasm32v1-none/release/test_poseidon_contract.wasm"
        );
    }

    #[test]
    fn test_wasm_poseidon() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        let contract_id = env.register(poseidon_contract::WASM, ());
        let client = poseidon_contract::Client::new(&env, &contract_id);

        let a = U256::from_u32(&env, 1);
        let b = U256::from_u32(&env, 2);

        // Test hash_two with known value from circom
        let hash = client.hash_two(&a, &b);
        let expected = U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
            )
            .into(),
        );
        assert_eq!(hash, expected);

        // Poseidon is not commutative
        let hash_reversed = client.hash_two(&b, &a);
        assert_ne!(hash, hash_reversed);

        // hash_two_sponge should produce the same result as hash_two
        let hash_sponge = client.hash_two_sponge(&a, &b);
        assert_eq!(hash_sponge, expected);

        // Deterministic: calling twice gives the same result
        let hash2 = client.hash_two(&a, &b);
        assert_eq!(hash, hash2);
    }
}
