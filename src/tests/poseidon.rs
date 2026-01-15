use crate::{
    poseidon::{
        params::{get_mds_bn254_t_3, get_rc_bn254_t_3, SBOX_D},
        PoseidonSponge,
    },
    poseidon_hash,
};
use soroban_sdk::{
    bytesn,
    crypto::{bls12_381::Fr as BlsScalar, BnScalar},
    vec, Env, Symbol, U256,
};

// Poseidon tests

// This test case matches circom hash([1, 2]) with t=3: https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js#L47
#[test]
fn test_poseidon_bn254_hash_1_2() {
    let env = Env::default();

    // Input: [1, 2]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
    ];

    // Expected output: 7853200120776062878684798364095072458815029376092732009249414926327459813530
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([3, 4]) with t=3: https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/test/poseidoncircuit.js#L57
#[test]
fn test_poseidon_bn254_hash_3_4() {
    let env = Env::default();

    // Input: [3, 4]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output: 14763215145315200506921711489642608356394854266165572616578112107564877678998
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x20a3af0435914ccd84b806164531b0cd36e37d4efb93efab76913a93e1f30996
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1]) with t=2 (N=1)
#[test]
fn test_poseidon_bn254_hash_1() {
    let env = Env::default();

    // Input: [1]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<2, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3]) with t=4 (N=3)
#[test]
fn test_poseidon_bn254_hash_1_2_3() {
    let env = Env::default();

    // Input: [1, 2, 3]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<4, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3, 4]) with t=5 (N=4)
#[test]
fn test_poseidon_bn254_hash_1_2_3_4() {
    let env = Env::default();

    // Input: [1, 2, 3, 4]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<5, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches circom hash([1, 2, 3, 4, 5]) with t=6 (N=5)
#[test]
fn test_poseidon_bn254_hash_1_2_3_4_5() {
    let env = Env::default();

    // Input: [1, 2, 3, 4, 5]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000005
            )
            .into(),
        ),
    ];

    // Expected output from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<6, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_bls12_381_hash_1_2() {
    let env = Env::default();

    // Input: [1, 2]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
    ];

    // Expected output
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x3fb8310b0e962b75bffec5f9cfcbf3f965a7b1d2dcac8d95ccb13d434e08e5fa
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1]) with t=2 (N=1)
#[test]
fn test_poseidon_bls12_381_hash_1() {
    let env = Env::default();

    // Input: [1]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x49a66f6b01dbc6440d1a5f920e027b94429916f2c821a920cf6203ad3de56cea
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<2, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3]) with t=4 (N=3)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3() {
    let env = Env::default();

    // Input: [1, 2, 3]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x5ad8bcfa9754b5bc043cc74dea65ae15e3fdb0c2295970aaacfc116c802d9895
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<4, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3, 4]) with t=5 (N=4)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3_4() {
    let env = Env::default();

    // Input: [1, 2, 3, 4]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2ebfd520dd8b5f26dfdc74e4ca0861495e119e6b43f7df3369dbb2f190cd5866
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<5, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// This test case matches poseidon-bls12381-circom hash([1, 2, 3, 4, 5]) with t=6 (N=5)
#[test]
fn test_poseidon_bls12_381_hash_1_2_3_4_5() {
    let env = Env::default();

    // Input: [1, 2, 3, 4, 5]
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000004
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000005
            )
            .into(),
        ),
    ];

    // Expected output from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2c0507691a38c8c109572be56878c10a34a741fafe3e6d04c3d1e0be60ddd781
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<6, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_permutation_t3() {
    let env = Env::default();

    // Input: [0, 1, 2] (capacity=0, rate=[1,2])
    let input = vec![
        &env,
        U256::from_u32(&env, 0),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000002
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 3;
    let mds = get_mds_bn254_t_3(&env);
    let rc = get_rc_bn254_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 57;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon_permutation(&input, field, t, d, rounds_f, rounds_p, &mds, &rc);

    // Expected output[0] = 7853200120776062878684798364095072458815029376092732009249414926327459813530
    let expected_0 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    assert_eq!(result.len(), 3);
    assert_eq!(result.get_unchecked(0), expected_0);
}

// ============================================================================
// Tests for poseidon_hash top-level function
// ============================================================================

#[test]
fn test_poseidon_hash_bn254_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );

    let result = poseidon_hash::<3, BnScalar>(&env, &inputs);
    assert_eq!(result, expected);
}

#[test]
fn test_poseidon_hash_bls12_381_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x3fb8310b0e962b75bffec5f9cfcbf3f965a7b1d2dcac8d95ccb13d434e08e5fa
        )
        .into(),
    );

    let result = poseidon_hash::<3, BlsScalar>(&env, &inputs);
    assert_eq!(result, expected);
}

// ============================================================================
// Tests for sponge reuse (repeated hashing)
// ============================================================================

#[test]
fn test_poseidon_sponge_reuse() {
    let env = Env::default();

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);

    let inputs1 = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];
    let inputs2 = vec![&env, U256::from_u32(&env, 3), U256::from_u32(&env, 4)];

    // Expected outputs
    let expected1 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
        )
        .into(),
    );
    let expected2 = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x20a3af0435914ccd84b806164531b0cd36e37d4efb93efab76913a93e1f30996
        )
        .into(),
    );

    // First hash
    let result1 = sponge.compute_hash(&inputs1);
    assert_eq!(result1, expected1);

    // Second hash - should be independent
    let result2 = sponge.compute_hash(&inputs2);
    assert_eq!(result2, expected2);

    // Hash inputs1 again - should get the same result as before
    let result1_again = sponge.compute_hash(&inputs1);
    assert_eq!(result1_again, expected1);
}

#[test]
fn test_poseidon_sponge_matches_hash_function() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    // Using top-level function
    let hash_result = poseidon_hash::<3, BnScalar>(&env, &inputs);

    // Using sponge directly
    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(hash_result, sponge_result);
}

// ============================================================================
// Partial rate tests (inputs.len() < RATE)
// ============================================================================

// Note: Circom's Poseidon always uses T = inputs.len() + 1 (full rate), so there are
// no reference test vectors for partial rate scenarios. These tests verify that:
// 1. Our implementation handles partial rate correctly (zero-padding)
// 2. Results are deterministic
// 3. Different T values produce different results (as expected)

// Test hashing 1 input with T=3 (rate=2) - partial rate usage
// This verifies zero-padding works correctly when inputs don't fill the rate
#[test]
fn test_poseidon_bn254_partial_rate_t3_1_input() {
    let env = Env::default();

    // 1 input with T=3 (rate=2) - only half the rate is used
    let inputs = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000001
            )
            .into(),
        ),
    ];

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);

    // Verify it's different from using T=2 (full rate with 1 input)
    let mut sponge_t2 = PoseidonSponge::<2, BnScalar>::new(&env);
    let result_t2 = sponge_t2.compute_hash(&inputs);
    assert_ne!(result, result_t2);
}

// ============================================================================
// Failure mode tests
// ============================================================================

#[test]
#[should_panic(expected = "assertion failed")]
fn test_poseidon_sponge_inputs_exceed_rate() {
    let env = Env::default();

    // t=3 means rate=2, so 3 inputs should panic
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// ============================================================================
// Large value tests (values exceeding field modulus)
// ============================================================================

// Test that values larger than the field modulus are properly reduced
// BN254 modulus = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
// Input: [modulus + 42, 2*modulus + 100]
// After reduction: [42, 100]
// Reference: circomlibjs confirms hash(large_values) == hash(reduced_values)
#[test]
fn test_poseidon_bn254_large_values_t3() {
    let env = Env::default();

    let bn254_modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );
    let two_times_modulus_plus_100 = bytesn!(
        &env,
        // 2 * modulus + 100
        0x60c89ce5c263405370a08b6d0302b0ba5067d090f372e12287c3eb27e0000066
    );

    let large_inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bn254_modulus_plus_42.into()),
        U256::from_be_bytes(&env, &two_times_modulus_plus_100.into()),
    ];

    // Compare with reduced values [42, 100]
    let reduced_inputs = vec![&env, U256::from_u32(&env, 42), U256::from_u32(&env, 100)];

    // Expected: same as hash([42, 100])
    // Reference from circomlibjs
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x013f85b7cf992c496d699a1cf7d6aad4ac760b41122849182bd1d7008f757612
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);

    // Test with large values - should automatically reduce
    let result_large = sponge.compute_hash(&large_inputs);

    // Test with reduced values
    let result_reduced = sponge.compute_hash(&reduced_inputs);

    // Both should produce the same result
    assert_eq!(result_large, result_reduced);
    assert_eq!(result_reduced, expected);
}

// Test large values with BLS12-381 field
// BLS12-381 modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
// Input: [modulus + 123, modulus + 456]
// After reduction: [123, 456]
#[test]
fn test_poseidon_bls12_381_large_values_t3() {
    let env = Env::default();

    let bls_modulus_plus_123 = bytesn!(
        &env,
        // modulus + 123
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff0000007c
    );
    let bls_modulus_plus_456 = bytesn!(
        &env,
        // modulus + 456
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff000001c9
    );

    let large_inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bls_modulus_plus_123.into()),
        U256::from_be_bytes(&env, &bls_modulus_plus_456.into()),
    ];

    // Compare with reduced values [123, 456]
    let reduced_inputs = vec![&env, U256::from_u32(&env, 123), U256::from_u32(&env, 456)];

    // Expected: same as hash([123, 456])
    // Reference from poseidon-bls12381-circom
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x11dcf9a2b6ceee9e2d5d2def70adb539b38d8595ab09e1dc5cfab96046ec10a2
        )
        .into(),
    );

    let mut sponge = PoseidonSponge::<3, BlsScalar>::new(&env);

    // Test with large values
    let result_large = sponge.compute_hash(&large_inputs);

    // Test with reduced values
    let result_reduced = sponge.compute_hash(&reduced_inputs);

    // Verify both produce the expected result (tests automatic modular reduction)
    assert_eq!(
        result_large, expected,
        "Large values should reduce mod field"
    );
    assert_eq!(
        result_reduced, expected,
        "Reduced values should match expected"
    );
}

// Empty inputs are explicitly rejected in Poseidon because:
// 1. Circom rejects them
// 2. With IV=0, hash([]) would collide with hash([0]) since both result in
//    permuting state [0, 0, ...]
//
// This differs from Poseidon2, which uses IV = `input_len << 64`, making
// hash([]) and hash([0]) produce different outputs.
#[test]
#[should_panic(expected = "Poseidon: inputs cannot be empty")]
fn test_poseidon_bn254_empty_inputs_rejected() {
    let env = Env::default();

    let empty_inputs = vec![&env];

    let mut sponge = PoseidonSponge::<2, BnScalar>::new(&env);
    // This should panic
    let _ = sponge.compute_hash(&empty_inputs);
}
