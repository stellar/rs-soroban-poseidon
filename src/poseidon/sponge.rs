use crate::{
    poseidon::params::{
        get_mds_bls12_381_t_2, get_mds_bls12_381_t_3, get_mds_bls12_381_t_4, get_mds_bls12_381_t_5,
        get_mds_bls12_381_t_6, get_mds_bn254_t_2, get_mds_bn254_t_3, get_mds_bn254_t_4,
        get_mds_bn254_t_5, get_mds_bn254_t_6, get_rc_bls12_381_t_2, get_rc_bls12_381_t_3,
        get_rc_bls12_381_t_4, get_rc_bls12_381_t_5, get_rc_bls12_381_t_6, get_rc_bn254_t_2,
        get_rc_bn254_t_3, get_rc_bn254_t_4, get_rc_bn254_t_5, get_rc_bn254_t_6, SBOX_D,
    },
    Field,
};
use soroban_sdk::{
    crypto::{bls12_381::Fr as BlsScalar, BnScalar},
    vec, Env, Vec, U256,
};

const CAPACITY: u32 = 1;

pub trait PoseidonConfig<const T: u32, F: Field> {
    const ROUNDS_F: u32;
    const ROUNDS_P: u32;
    const RATE: u32 = T - CAPACITY;
    fn get_mds(e: &Env) -> Vec<Vec<U256>>;
    fn get_rc(e: &Env) -> Vec<Vec<U256>>;
}

// Internal struct storing the Poseidon constants, in the future we can make
// this a #[contracttype], which can be stored as contract data (to reduce the
// actual contract size)
pub(crate) struct PoseidonParams {
    pub rounds_f: u32,
    pub rounds_p: u32,
    pub mds: Vec<Vec<U256>>,
    pub rc: Vec<Vec<U256>>,
}

/// A Poseidon sponge configured for a specific state size `T` and field `F`.
///
/// This is a single-absorb, single-squeeze sponge. The primary benefit of
/// creating a sponge instance is to reuse the pre-computed parameters (MDS
/// matrix and round constants) across multiple independent hash computations,
/// avoiding repeated parameter initialization.
///
/// **Note**: Each call to [`compute_hash`](Self::compute_hash) resets the
/// internal state and computes a fresh hash. The sponge does not accumulate
/// state between calls.
///
/// # Example
/// ```ignore
/// // Create sponge once (initializes parameters)
/// let mut sponge = PoseidonSponge::<3, BnScalar>::new(&env);
///
/// // Compute multiple independent hashes, reusing the same parameters
/// let hash1 = sponge.compute_hash(&inputs1);
/// let hash2 = sponge.compute_hash(&inputs2);
/// ```
pub struct PoseidonSponge<const T: u32, F: Field> {
    env: Env,
    state: Vec<U256>,
    params: PoseidonParams,
    _phantom: core::marker::PhantomData<F>,
}

// BN254 implementations
impl PoseidonConfig<2, BnScalar> for PoseidonSponge<2, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bn254_t_2(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_2(e)
    }
}

impl PoseidonConfig<3, BnScalar> for PoseidonSponge<3, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 57;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bn254_t_3(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_3(e)
    }
}

impl PoseidonConfig<4, BnScalar> for PoseidonSponge<4, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bn254_t_4(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_4(e)
    }
}

impl PoseidonConfig<5, BnScalar> for PoseidonSponge<5, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 60;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bn254_t_5(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_5(e)
    }
}

impl PoseidonConfig<6, BnScalar> for PoseidonSponge<6, BnScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 60;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bn254_t_6(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bn254_t_6(e)
    }
}

// BLS12-381 implementations
impl PoseidonConfig<2, BlsScalar> for PoseidonSponge<2, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bls12_381_t_2(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_2(e)
    }
}

impl PoseidonConfig<3, BlsScalar> for PoseidonSponge<3, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bls12_381_t_3(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_3(e)
    }
}

impl PoseidonConfig<4, BlsScalar> for PoseidonSponge<4, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bls12_381_t_4(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_4(e)
    }
}

impl PoseidonConfig<5, BlsScalar> for PoseidonSponge<5, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 56;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bls12_381_t_5(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_5(e)
    }
}

impl PoseidonConfig<6, BlsScalar> for PoseidonSponge<6, BlsScalar> {
    const ROUNDS_F: u32 = 8;
    const ROUNDS_P: u32 = 57;
    fn get_mds(e: &Env) -> Vec<Vec<U256>> {
        get_mds_bls12_381_t_6(e)
    }
    fn get_rc(e: &Env) -> Vec<Vec<U256>> {
        get_rc_bls12_381_t_6(e)
    }
}

impl<const T: u32, F: Field> PoseidonSponge<T, F>
where
    Self: PoseidonConfig<T, F>,
{
    fn reset_state(&mut self) {
        // initialize the state with CAPACITY elements (CAPACITY = 1 in our sponge) at the 0-th element
        // The initial value is 0 for standard Poseidon
        let iv = U256::from_u32(&self.env, 0);
        self.state = vec![&self.env, iv];
        for _ in 0..Self::RATE {
            self.state.push_back(U256::from_u32(&self.env, 0));
        }
    }

    pub fn new(env: &Env) -> Self {
        let params = PoseidonParams {
            rounds_f: <Self as PoseidonConfig<T, F>>::ROUNDS_F,
            rounds_p: <Self as PoseidonConfig<T, F>>::ROUNDS_P,
            mds: <Self as PoseidonConfig<T, F>>::get_mds(env),
            rc: <Self as PoseidonConfig<T, F>>::get_rc(env),
        };
        let mut inner = Self {
            env: env.clone(),
            state: vec![env],
            params,
            _phantom: core::marker::PhantomData,
        };
        inner.reset_state();
        inner
    }

    pub(crate) fn perform_duplex(&mut self) {
        self.state = self.env.crypto_hazmat().poseidon_permutation(
            &self.state,
            F::symbol(),
            T,
            SBOX_D,
            self.params.rounds_f,
            self.params.rounds_p,
            &self.params.mds,
            &self.params.rc,
        );
    }

    pub(crate) fn absorb(&mut self, inputs: &Vec<U256>) {
        assert!(inputs.len() <= Self::RATE);
        for i in 0..inputs.len() {
            let v = inputs.get_unchecked(i);
            self.state.set(i as u32 + CAPACITY, v);
        }
    }

    pub(crate) fn squeeze(&mut self) -> U256 {
        self.perform_duplex();
        self.state.get_unchecked(0)
    }

    /// Computes a fresh Poseidon hash of the inputs.
    ///
    /// This method resets the sponge state and computes a new hash from
    /// scratch. It does **not** accumulate state from previous calls, i.e. each
    /// invocation is independent. The benefit of calling this on an existing
    /// sponge (vs creating a new one) is reusing the pre-initialized
    /// parameters.
    ///
    /// This matches [circom's Poseidon
    /// implementation](https://github.com/iden3/circomlib/blob/master/circuits/poseidon.circom).
    ///
    /// # Panics
    /// - if `inputs.is_empty()`. Empty inputs are not allowed because
    ///   `hash([])` would collide with `hash([0])`. Circom also disallows empty
    ///   inputs.
    /// - if `inputs.len() > RATE` (i.e., `T - 1`). For larger inputs,
    ///   multi-round absorption would be needed (not yet implemented).
    pub fn compute_hash(&mut self, inputs: &Vec<U256>) -> U256 {
        assert!(!inputs.is_empty(), "Poseidon: inputs cannot be empty");
        self.reset_state();
        self.absorb(inputs);
        self.squeeze()
    }
}
