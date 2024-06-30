use grapevine_common::{Fq, Fr, SECRET_FIELD_LENGTH};
use lazy_static::lazy_static;

pub mod nova;
pub mod utils;
pub mod inputs;
mod params_gen;

lazy_static! {
    pub(crate) static ref Z0_PRIMARY: Vec<Fr> = vec![Fr::from(0); 12];
    pub(crate) static ref Z0_SECONDARY: Vec<Fq> = vec![Fq::from(0)];
}

pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const DEFAULT_WC_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/folded_js/folded.wasm";
pub const DEFAULT_R1CS_PATH: &str = "crates/grapevine_circuits/circom/artifacts/folded.r1cs";
pub const DEFAULT_PUBLIC_PARAMS_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/public_params.json";
