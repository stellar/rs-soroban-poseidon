use crate::{
    poseidon2::{
        params::{
            get_mat_diag_bls12_381_t_2, get_mat_diag_bls12_381_t_3, get_mat_diag_bls12_381_t_4,
            get_mat_diag_bn254_t_2, get_mat_diag_bn254_t_3, get_mat_diag_bn254_t_4,
            get_rc_bls12_381_t_2, get_rc_bls12_381_t_3, get_rc_bls12_381_t_4, get_rc_bn254_t_2,
            get_rc_bn254_t_3, get_rc_bn254_t_4, SBOX_D,
        },
        Poseidon2Sponge,
    },
    poseidon2_hash,
};
use soroban_sdk::{
    bytesn,
    crypto::{bls12_381::Fr as BlsScalar, BnScalar},
    vec, Env, Symbol, U256,
};

// This test matches barretenberg test case for hashing 4 inputs: https://github.com/AztecProtocol/aztec-packages/blob/b95e36c6c1a5a84ba488c720189102ecbb052d2c/barretenberg/cpp/src/barretenberg/crypto/poseidon2/poseidon2.test.cpp#L34
// TODO: Re-enable once multi-round absorption is implemented
#[test]
#[ignore]
fn test_poseidon2_hash() {
    let env = Env::default();

    // Input: 4 identical field elements
    let input_value = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789
        )
        .into(),
    );
    let inputs = vec![
        &env,
        input_value.clone(),
        input_value.clone(),
        input_value.clone(),
        input_value,
    ];

    // Expected output from Aztec's implementation
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x2f43a0f83b51a6f5fc839dea0ecec74947637802a579fa9841930a25a0bcec11
        )
        .into(),
    );

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env); // t=4, rate=3 matches noir
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation() {
    let env = Env::default();

    // Input: 4 identical field elements
    let input_value = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x9a807b615c4d3e2fa0b1c2d3e4f56789fedcba9876543210abcdef0123456789
        )
        .into(),
    );
    let input = vec![
        &env,
        input_value.clone(),
        input_value.clone(),
        input_value.clone(),
        input_value,
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 4;
    let m_diag = get_mat_diag_bn254_t_4(&env);
    let rc = get_rc_bn254_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output (full state after permutation)
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x2bf1eaf87f7d27e8dc4056e9af975985bccc89077a21891d6c7b6ccce0631f95
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0c01fa1b8d0748becafbe452c0cb0231c38224ea824554c9362518eebdd5701f
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x018555a8eb50cf07f64b019ebaf3af3c925c93e631f3ecd455db07bbb52bbdd3
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0cbea457c91c22c6c31fd89afd2541efc2edf31736b9f721e823b2165c90fd41
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t4() {
    let env = Env::default();

    // Input: [0, 1, 2, 3]
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 4u32;
    let m_diag = get_mat_diag_bn254_t_4(&env);
    let rc = get_rc_bn254_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x01bd538c2ee014ed5141b29e9ae240bf8db3fe5b9a38629a9647cf8d76c01737
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x239b62e7db98aa3a2a8f6a0d2fa1709e7a35959aa6c7034814d9daa90cbac662
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x04cbb44c61d928ed06808456bf758cbf0c18d1e15a7b6dbc8245fa7515d5e3cb
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x2e11c5cff2a22c64d01304b778d78f6998eff1ab73163a35603f54794c30847a
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t4() {
    let env = Env::default();

    // Input: [0, 1, 2, 3]
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
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0000000000000000000000000000000000000000000000000000000000000003
            )
            .into(),
        ),
    ];

    // Get parameters
    let field = Symbol::new(&env, "BLS12_381");
    let t = 4u32;
    let m_diag = get_mat_diag_bls12_381_t_4(&env);
    let rc = get_rc_bls12_381_t_4(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x28ff6c4edf9768c08ae26290487e93449cc8bc155fc2fad92a344adceb3ada6d
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0e56f2b6fad25075aa93560185b70e2b180ed7e269159c507c288b6747a0db2d
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x6d8196f28da6006bb89b3df94600acdc03d0ba7c2b0f3f4409a54c1db6bf30d0
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x07cfb49540ee456cce38b8a7d1a930a57ffc6660737f6589ef184c5e15334e36
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t2() {
    let env = Env::default();

    // Input: [0, 1]
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
    ];

    // Get parameters
    let field = Symbol::new(&env, "BN254");
    let t = 2u32;
    let m_diag = get_mat_diag_bn254_t_2(&env);
    let rc = get_rc_bn254_t_2(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1d01e56f49579cec72319e145f06f6177f6c5253206e78c2689781452a31878b
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0d189ec589c41b8cffa88cfc523618a055abe8192c70f75aa72fc514560f6c61
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bn254_t3() {
    let env = Env::default();

    // Input: [0, 1, 2]
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
    let t = 3u32;
    let m_diag = get_mat_diag_bn254_t_3(&env);
    let rc = get_rc_bn254_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t2() {
    let env = Env::default();

    // Input: [0, 1]
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
    ];

    // Get parameters
    let field = Symbol::new(&env, "BLS12_381");
    let t = 2u32;
    let m_diag = get_mat_diag_bls12_381_t_2(&env);
    let rc = get_rc_bls12_381_t_2(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x73c46dd530e248a87b61d19e67fa1b4ed30fc3d09f16531fe189fb945a15ce4e
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1f0e305ee21c9366d5793b80251405032a3fee32b9dd0b5f4578262891b043b4
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

#[test]
fn test_poseidon2_permutation_bls12_381_t3() {
    let env = Env::default();

    // Input: [0, 1, 2]
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
    let field = Symbol::new(&env, "BLS12_381");
    let t = 3u32;
    let m_diag = get_mat_diag_bls12_381_t_3(&env);
    let rc = get_rc_bls12_381_t_3(&env);
    let d = SBOX_D;
    let rounds_f = 8;
    let rounds_p = 56;

    // Call the permutation
    let result = env
        .crypto_hazmat()
        .poseidon2_permutation(&input, field, t, d, rounds_f, rounds_p, &m_diag, &rc);

    // Expected output
    let expected = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891
            )
            .into(),
        ),
        U256::from_be_bytes(
            &env,
            &bytesn!(
                &env,
                0x1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b
            )
            .into(),
        ),
    ];

    assert_eq!(result, expected);
}

// ============================================================================
// Tests for Poseidon2Sponge::compute_hash
// ============================================================================

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t4() {
    let env = Env::default();

    // 3 inputs fit in rate=3 for t=4
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic - hash again and compare
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t3() {
    let env = Env::default();

    // 2 inputs fit in rate=2 for t=3
    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let mut sponge = Poseidon2Sponge::<3, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bn254_t2() {
    let env = Env::default();

    // 1 input fits in rate=1 for t=2
    let inputs = vec![&env, U256::from_u32(&env, 1)];

    let mut sponge = Poseidon2Sponge::<2, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

#[test]
fn test_poseidon2_sponge_compute_hash_bls12_381_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let mut sponge = Poseidon2Sponge::<4, BlsScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    // Result should be deterministic
    let result2 = sponge.compute_hash(&inputs);
    assert_eq!(result, result2);
}

// ============================================================================
// Tests for poseidon2_hash top-level function
// ============================================================================

#[test]
fn test_poseidon2_hash_bn254_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    // Top-level function should work
    let result = poseidon2_hash::<4, BnScalar>(&env, &inputs);

    // Should match sponge directly
    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bls12_381_t4() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    let result = poseidon2_hash::<4, BlsScalar>(&env, &inputs);

    // Should match sponge directly
    let mut sponge = Poseidon2Sponge::<4, BlsScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bn254_t2() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1)];

    let result = poseidon2_hash::<2, BnScalar>(&env, &inputs);

    let mut sponge = Poseidon2Sponge::<2, BnScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

#[test]
fn test_poseidon2_hash_bn254_t3() {
    let env = Env::default();

    let inputs = vec![&env, U256::from_u32(&env, 1), U256::from_u32(&env, 2)];

    let result = poseidon2_hash::<3, BnScalar>(&env, &inputs);

    let mut sponge = Poseidon2Sponge::<3, BnScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(result, sponge_result);
}

// ============================================================================
// Tests for sponge reuse (repeated hashing)
// ============================================================================

#[test]
fn test_poseidon2_sponge_reuse() {
    let env = Env::default();

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);

    let inputs1 = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];
    let inputs2 = vec![
        &env,
        U256::from_u32(&env, 4),
        U256::from_u32(&env, 5),
        U256::from_u32(&env, 6),
    ];

    // First hash
    let result1 = sponge.compute_hash(&inputs1);

    // Second hash - should be independent (different inputs, different result)
    let result2 = sponge.compute_hash(&inputs2);
    assert_ne!(result1, result2);

    // Hash inputs1 again - should get the same result as the first time
    let result1_again = sponge.compute_hash(&inputs1);
    assert_eq!(result1, result1_again);
}

#[test]
fn test_poseidon2_sponge_matches_hash_function() {
    let env = Env::default();

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
    ];

    // Using top-level function
    let hash_result = poseidon2_hash::<4, BnScalar>(&env, &inputs);

    // Using sponge directly
    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let sponge_result = sponge.compute_hash(&inputs);

    assert_eq!(hash_result, sponge_result);
}

// ============================================================================
// Partial rate tests (inputs.len() < RATE)
// ============================================================================

// Test hashing 1 input with T=4 (rate=3) - partial rate usage
// Reference: noir circuit hash([1]) with message_size=1
#[test]
fn test_poseidon2_bn254_partial_rate_t4_1_input() {
    let env = Env::default();

    // 1 input with T=4 (rate=3) - only 1/3 of the rate is used
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

    // Expected from noir circuit: hash([1], 1)
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x168758332d5b3e2d13be8048c8011b454590e06c44bce7f702f09103eef5a373
        )
        .into(),
    );

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// Test hashing 2 inputs with T=4 (rate=3) - partial rate usage
// Reference: noir circuit hash([1, 2]) with message_size=2
#[test]
fn test_poseidon2_bn254_partial_rate_t4_2_inputs() {
    let env = Env::default();

    // 2 inputs with T=4 (rate=3) - 2/3 of the rate is used
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

    // Expected from noir circuit: hash([1, 2], 2)
    let expected = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x038682aa1cb5ae4e0a3f13da432a95c77c5c111f6f030faf9cad641ce1ed7383
        )
        .into(),
    );

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let result = sponge.compute_hash(&inputs);

    assert_eq!(result, expected);
}

// ============================================================================
// Failure mode tests
// ============================================================================

#[test]
#[should_panic(expected = "assertion failed")]
fn test_poseidon2_sponge_inputs_exceed_rate_t4() {
    let env = Env::default();

    // t=4 means rate=3, so 4 inputs should panic
    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
        U256::from_u32(&env, 3),
        U256::from_u32(&env, 4),
    ];

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// ============================================================================
// Large value tests (values exceeding field modulus must panic)
// ============================================================================

// Test that values equal to or larger than the field modulus are rejected
// BN254 modulus = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bn254_input_exceeds_modulus() {
    let env = Env::default();

    let modulus_plus_42 = bytesn!(
        &env,
        // modulus + 42
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000002b
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &modulus_plus_42.into()),
        U256::from_u32(&env, 1),
        U256::from_u32(&env, 2),
    ];

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that a value exactly equal to the BN254 modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bn254_input_equals_modulus() {
    let env = Env::default();

    let bn254_modulus = bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bn254_modulus.into())];

    let mut sponge = Poseidon2Sponge::<2, BnScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that values just below the BN254 modulus are accepted
#[test]
fn test_poseidon2_bn254_input_below_modulus_accepted() {
    let env = Env::default();

    // modulus - 1 (largest valid input)
    let bn254_modulus_minus_1 = bytesn!(
        &env,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000
    );

    let inputs = vec![
        &env,
        U256::from_be_bytes(&env, &bn254_modulus_minus_1.into()),
    ];

    let mut sponge = Poseidon2Sponge::<2, BnScalar>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}

// Test large values with BLS12-381 field
// BLS12-381 modulus = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bls12_381_input_exceeds_modulus() {
    let env = Env::default();

    let bls_modulus_plus_123 = bytesn!(
        &env,
        // modulus + 123
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff0000007c
    );

    let inputs = vec![
        &env,
        U256::from_u32(&env, 1),
        U256::from_be_bytes(&env, &bls_modulus_plus_123.into()),
    ];

    let mut sponge = Poseidon2Sponge::<3, BlsScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that a value exactly equal to the BLS12-381 modulus is rejected
#[test]
#[should_panic(expected = "input exceeds field modulus")]
fn test_poseidon2_bls12_381_input_equals_modulus() {
    let env = Env::default();

    let bls_modulus = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus.into())];

    let mut sponge = Poseidon2Sponge::<2, BlsScalar>::new(&env);
    let _ = sponge.compute_hash(&inputs); // Should panic
}

// Test that values just below the BLS12-381 modulus are accepted
#[test]
fn test_poseidon2_bls12_381_input_below_modulus_accepted() {
    let env = Env::default();

    // modulus - 1 (largest valid input)
    let bls_modulus_minus_1 = bytesn!(
        &env,
        0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    );

    let inputs = vec![&env, U256::from_be_bytes(&env, &bls_modulus_minus_1.into())];

    let mut sponge = Poseidon2Sponge::<2, BlsScalar>::new(&env);
    // Should not panic - value is valid
    let _ = sponge.compute_hash(&inputs);
}

// Poseidon2 supports empty inputs (unlike Poseidon) because its IV choice
// prevents collision
// - hash([]) uses IV = 0, state = [0, 0, 0, 0]
// - hash([0]) uses IV = 2^64, state = [2^64, 0, 0, 0] then absorbs 0
#[test]
fn test_poseidon2_bn254_empty_inputs() {
    let env = Env::default();

    let empty_inputs = vec![&env];
    let zero_inputs = vec![&env, U256::from_u32(&env, 0)];

    // Expected output for empty inputs: first element of permutation([0,0,0,0])
    let expected_empty = U256::from_be_bytes(
        &env,
        &bytesn!(
            &env,
            0x18dfb8dc9b82229cff974efefc8df78b1ce96d9d844236b496785c698bc6732e
        )
        .into(),
    );

    let mut sponge = Poseidon2Sponge::<4, BnScalar>::new(&env);

    let empty_hash = sponge.compute_hash(&empty_inputs);
    assert_eq!(empty_hash, expected_empty);

    let zero_hash = sponge.compute_hash(&zero_inputs);

    // Verify domain separation: hash([]) != hash([0])
    assert_ne!(empty_hash, zero_hash);
}
