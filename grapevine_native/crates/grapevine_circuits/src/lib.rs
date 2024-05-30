use grapevine_common::{Fq, Fr, SECRET_FIELD_LENGTH};
#[cfg(not(target_family = "wasm"))]
pub mod nova;
#[cfg(not(target_family = "wasm"))]
mod params_gen;
pub mod utils;

pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const EMPTY_SECRET: [&str; SECRET_FIELD_LENGTH] = [ZERO; SECRET_FIELD_LENGTH];
pub const DEFAULT_WC_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/grapevine.wasm";
pub const DEFAULT_R1CS_PATH: &str = "crates/grapevine_circuits/circom/artifacts/grapevine.r1cs";
pub const DEFAULT_PUBLIC_PARAMS_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/public_params.json";

/**
 * Default start input is 0 first three elements and 1 for chaff step
 */
pub fn start_input() -> [Fr; 4] {
    [Fr::from(0), Fr::from(0), Fr::from(0), Fr::from(1)]
}

/**
 * Todo: figure out wtf z0 secondary is
 */
pub fn z0_secondary() -> [Fq; 1] {
    [Fq::from(0)]
}
