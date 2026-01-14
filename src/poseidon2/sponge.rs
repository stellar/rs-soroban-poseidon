use crate::Field;
use super::params::{
    get_mat_diag_bn254_t_2, get_mat_diag_bn254_t_3, get_mat_diag_bn254_t_4,
    get_rc_bn254_t_2, get_rc_bn254_t_3, get_rc_bn254_t_4,
    get_mat_diag_bls12_381_t_2, get_mat_diag_bls12_381_t_3, get_mat_diag_bls12_381_t_4,
    get_rc_bls12_381_t_2, get_rc_bls12_381_t_3, get_rc_bls12_381_t_4,
    SBOX_D,
};
use soroban_sdk::{crypto::{bls12_381::Fr as BlsScalar, BnScalar}, vec, Env, Vec, U256};

const CAPACITY: u32 = 1;

pub trait Poseidon2Config<const T: u32, F: Field> {
    const ROUNDS_F: u32;
    const ROUNDS_P: u32;
    const RATE: u32 = T - CAPACITY;
    fn get_m_diag(e: &Env) -> Vec<U256>;
    fn get_rc(e: &Env) -> Vec<Vec<U256>>; 
}

pub(crate) struct Poseidon2Params {
    pub rounds_f: u32,
    pub rounds_p: u32,
    pub m_diag: Vec<U256>,
    pub rc: Vec<Vec<U256>>,
}

pub struct Poseidon2Sponge<const T: u32, F: Field> {
    env: Env,
    state: Vec<U256>,
    params: Poseidon2Params,
    _phantom: core::marker::PhantomData<F>,
}

// BN254 implementations
impl Poseidon2Config<2, BnScalar> for Poseidon2Sponge<2, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bn254_t_2(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bn254_t_2(e) }
}

impl Poseidon2Config<3, BnScalar> for Poseidon2Sponge<3, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bn254_t_3(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bn254_t_3(e) }
}

impl Poseidon2Config<4, BnScalar> for Poseidon2Sponge<4, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bn254_t_4(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bn254_t_4(e) }
}

// BLS12-381 implementations
impl Poseidon2Config<2, BlsScalar> for Poseidon2Sponge<2, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bls12_381_t_2(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bls12_381_t_2(e) }
}

impl Poseidon2Config<3, BlsScalar> for Poseidon2Sponge<3, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bls12_381_t_3(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bls12_381_t_3(e) }
}

impl Poseidon2Config<4, BlsScalar> for Poseidon2Sponge<4, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_m_diag(e: &Env) -> Vec<U256> { get_mat_diag_bls12_381_t_4(e) }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> { get_rc_bls12_381_t_4(e) }
}

impl<const T: u32, F: Field> Poseidon2Sponge<T, F> 
where
    Self: Poseidon2Config<T, F>
{
    fn reset_state(&mut self, iv: U256) {
        // State layout: [rate elements...][capacity element]
        // Rate elements are at positions 0..RATE, capacity (IV) is at position T-1 (last)
        self.state = vec![&self.env];
        for _ in 0..Self::RATE {
            self.state.push_back(U256::from_u32(&self.env, 0));
        }
        // IV goes at the last position (capacity element)
        self.state.push_back(iv);
    }

    pub fn new(env: &Env) -> Self {
        let params = Poseidon2Params {
            rounds_f: <Self as Poseidon2Config<T, F>>::ROUNDS_F,
            rounds_p: <Self as Poseidon2Config<T, F>>::ROUNDS_P,
            m_diag: <Self as Poseidon2Config<T, F>>::get_m_diag(env),
            rc: <Self as Poseidon2Config<T, F>>::get_rc(env),
        };
        let mut inner = Self {
            env: env.clone(),
            state: vec![env],
            params,
            _phantom: core::marker::PhantomData,
        };
        // Initialize with default IV of 0
        inner.reset_state(U256::from_u32(env, 0));
        inner
    }

    pub(crate) fn perform_duplex(&mut self) {
        self.state = self.env.crypto_hazmat().poseidon2_permutation(
            &self.state,
            F::symbol(),
            T,
            SBOX_D,
            self.params.rounds_f,
            self.params.rounds_p,
            &self.params.m_diag,
            &self.params.rc,
        );
    }

    pub(crate) fn absorb(&mut self, inputs: &Vec<U256>) {
        // Absorb into rate portion of state (positions 0..RATE)
        assert!(inputs.len() <= Self::RATE);
        for i in 0..inputs.len() {
            let v = inputs.get_unchecked(i);
            self.state.set(i as u32, v);
        }
    }

    pub(crate) fn squeeze(&mut self) -> U256 {
        self.perform_duplex();
        // Output is at position 0
        self.state.get_unchecked(0)
    }

    /// Hashes the inputs using the Poseidon2 sponge.
    /// 
    /// The capacity element is initialized to `input.len() << 64`, matching noir's Poseidon2.
    pub fn hash(&mut self, inputs: &Vec<U256>) -> U256 {
        // The initial value for the capacity element: input.len() * 2^64 for Poseidon2
        let iv = U256::from_u128(&self.env, (inputs.len() as u128) << 64);
        self.reset_state(iv);
        self.absorb(inputs);
        self.squeeze()
    }
}
