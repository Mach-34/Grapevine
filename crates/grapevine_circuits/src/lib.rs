use grapevine_common::{Fr, Fq, SECRET_FIELD_LENGTH};
pub mod nova;
pub mod utils;

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
