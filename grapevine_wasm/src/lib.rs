use ff::PrimeField;
use grapevine_circuits::{start_input, utils::build_step_inputs, z0_secondary};
use grapevine_common::{utils::random_fr, Fq, Fr, NovaProof, Params, G1, G2};
use js_sys::{Array, Number, Uint8Array};
use nova_scotia::{circom::wasm::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation};
use num::{BigInt, Num};
use serde_json::Value;
use utils::{bigint_to_fr, fr_to_bigint};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;
pub mod utils;

#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);

    pub type Performance;

    pub static performance: Performance;

    #[wasm_bindgen(method)]
    pub fn now(this: &Performance) -> f64;
}

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => ($crate::log(&format_args!($($t)*).to_string()))
}

// extern crate console_error_panic_hook;
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

/**
 * Create a nova folding proof for 0th degree (identity proof/ knowledge of phrase)
 *
 * @param wc_url - the url for the witness calculator
 * @param r1cs_url - the url for the r1cs file
 * @param params_str - the previously downloaded stringified public params
 * @param phrase - the secret phrase to prove knowledge of
 * @param username - the username to associate with this proof
 * @param auth_secret - the auth secret used to authorize downstream degrees (stringified BigInt)
 * @return - the stringified degree 0 proof
 */
#[wasm_bindgen]
pub async fn identity_proof(
    wc_url: String,
    r1cs_url: String,
    params_str: String,
    phrase: String,
    username: String,
    auth_secret: String,
) -> String {
    init_panic_hook();
    // todo: check integrity of string inputs

    // parse params
    let params: Params = serde_json::from_str(&params_str).unwrap();

    // load r1cs from remote url
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;

    // get logic step inputs (chaff -> degree 0 -> chaff)
    let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
    build_step_inputs(
        &mut private_inputs,
        Some(phrase),
        [None, Some(username)],
        [None, Some(bigint_to_fr(auth_secret))],
    );

    // compute the first fold (identity proof)
    let proof = create_recursive_circuit(
        FileLocation::URL(wc_url),
        r1cs.clone(),
        private_inputs,
        start_input().to_vec(),
        &params,
    )
    .await
    .unwrap();

    // serialize the proof into a string and return
    serde_json::to_string(&proof).unwrap()
}

/**
 * Create a nova folding proof for Nth degree (prove knowledge of degree of separation)
 * 
 * @param wc_url - the url for the witness calculator
 * @param r1cs_url - the url for the r1cs file
 * @param params_str - the previously downloaded stringified public params
 * @param usernames - [prev username, prover username]
 * @param auth_secrets - [prev auth secret, prover auth secret]
 * @param prev_outputs - the zi_primary of the previous proof
 *                       this is included to split verification and proof generation
 * @params prev_proof - the previous proof to build from
 */
#[wasm_bindgen]
pub async fn degree_proof(
    wc_url: String,
    r1cs_url: String,
    params_str: String,
    usernames: Array,
    auth_secrets: Array,
    prev_output: Array,
    prev_proof: String,
) -> String {
    // todo: strong typing
    // todo: error messaging
    // parse params
    let params: Params = serde_json::from_str(&params_str).unwrap();

    // load r1cs from remote url
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;

    // parse the usernames
    let usernames: [Option<String>; 2] = usernames
        .iter()
        .map(|username| Some(username.as_string().unwrap()))
        .collect::<Vec<Option<String>>>()
        .try_into()
        .unwrap();

    // parse the auth secrets
    let auth_secrets: [Option<Fr>; 2] = auth_secrets
        .iter()
        .map(|auth_secret| {
            Some(bigint_to_fr(auth_secret.as_string().unwrap()))
        })
        .collect::<Vec<Option<Fr>>>()
        .try_into()
        .unwrap();

    // build the private inputs
    let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
    build_step_inputs(
        &mut private_inputs,
        None,
        usernames,
        auth_secrets,
    );

    // parse the previous outputs (step_in for next proof)
    let zi_primary: Vec<Fr> = prev_output
        .iter()
        .map(|output| bigint_to_fr(output.as_string().unwrap()))
        .collect();

    // parse the previous proof to build from
    let mut proof: NovaProof = serde_json::from_str(&prev_proof).unwrap();

    // fold in logic step + chaff step for the next proof
    continue_recursive_circuit(
        &mut proof,
        zi_primary,
        FileLocation::URL(wc_url),
        r1cs,
        private_inputs,
        start_input().to_vec(),
        &params
    ).await.unwrap();

    // serialize the proof into a string and return
    serde_json::to_string(&proof).unwrap()
}

/**
 * Verify a nova proof of a given degree of separation
 * 
 * @param params_str - the stringified public params
 * @param proof_str - the stringified proof to verify
 * @param degree - the degree of separation to verify
 * 
 * @return - [phrase hash, auth hash] as stringified bigints if proof verifies
 */
#[wasm_bindgen]
pub async fn verify_proof(
    params_str: String,
    proof_str: String,
    degree: Number
) -> Array {
    // parse the params
    let params: Params = serde_json::from_str(&params_str).unwrap();

    // parse the proof
    let proof: NovaProof = serde_json::from_str(&proof_str).unwrap();

    // compute the number of steps in the fold given the degree of separation
    let num_steps = (degree.as_f64().unwrap() as usize) * 2 + 1;

    let res = proof.verify(
        &params,
        num_steps,
        &start_input(),
        &z0_secondary().to_vec()
    ).unwrap();
    // fill array with hashes and return
    let arr = Array::new_with_length(2);
    arr.set(0, JsValue::from_str(&fr_to_bigint(res.0[1])));
    arr.set(1, JsValue::from_str(&fr_to_bigint(res.0[2])));
    arr
}
