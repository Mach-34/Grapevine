use grapevine_common::{Fq, Fr, SECRET_FIELD_LENGTH};
pub mod nova;
pub mod utils;
pub mod inputs;
mod params_gen;

pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const DEFAULT_WC_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/folded_js/folded.wasm";
pub const DEFAULT_R1CS_PATH: &str = "crates/grapevine_circuits/circom/artifacts/folded.r1cs";
pub const DEFAULT_PUBLIC_PARAMS_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/public_params.json";


/**
 * Default start input is 0 first three elements and 1 for chaff step
 */
pub fn start_input() -> [Fr; 12] {
    [Fr::from(0); 12]
}

/**
 * Todo: figure out wtf z0 secondary is
 */
pub fn z0_secondary() -> [Fq; 1] {
    [Fq::from(0)]
}
