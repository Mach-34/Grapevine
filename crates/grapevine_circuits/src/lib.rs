pub mod nova;
pub mod utils;
use nova_scotia::{C1, C2, F, circom::circuit::CircomCircuit};
use nova_snark::{
    provider,
    traits::circuit::TrivialTestCircuit, PublicParams, RecursiveSNARK,
};
pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F<G1>;
pub type Fq = F<G2>;
pub type Params = PublicParams<G1, G2, C1<G1>, C2<G2>>;
pub type NovaProof = RecursiveSNARK<G1, G2, CircomCircuit<Fr>, TrivialTestCircuit<Fq>>;
// pub type CompressedProof = CompressedSNARK<G1, G2, C1<G1>, C2<G2>, S<G1>, S<G2>>;
// pub type ProvingKey = ProverKey<G1, S<G1>>;
// pub type VerifyingKey = VerifierKey<G2, S<G2>>;

pub const SECRET_FIELD_LENGTH: usize = 6;
pub const MAX_SECRET_CHARS: usize = 180;
pub const MAX_USERNAME_CHARS: usize = 30;
pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const EMPTY_SECRET: [&str; SECRET_FIELD_LENGTH] = [ZERO; SECRET_FIELD_LENGTH];
pub const DEFAULT_WC_PATH: &str = "crates/grapevine_circuits/circom/artifacts/folded_js/folded.wasm";
pub const DEFAULT_R1CS_PATH: &str = "crates/grapevine_circuits/circom/artifacts/folded.r1cs";
pub const DEFAULT_PUBLIC_PARAMS_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/public_params.json";

/**
 * Default start input is 0 for all elements
 */
pub fn start_input() -> [Fr; 4] {
    [Fr::from(0); 4]
}

/**
 * Todo: figure out wtf z0 secondary is
 */
pub fn z0_secondary() -> [Fq; 1] {
    [Fq::from(0)]
}
