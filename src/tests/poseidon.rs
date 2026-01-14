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
