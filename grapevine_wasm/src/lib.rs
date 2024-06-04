use ff::PrimeField;
use grapevine_circuits::{start_input, utils::build_step_inputs, z0_secondary};
use grapevine_common::{
    console_log, utils::random_fr, wasm::init_panic_hook, Fq, Fr, NovaProof, Params, G1, G2,
};
use js_sys::{Array, Number, Uint8Array};
use nova_scotia::{
    circom::wasm::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use num::{BigInt, Num};
use serde_json::Value;
use std::collections::HashMap;
use utils::{bigint_to_fr, fr_to_bigint, validate_auth_secret, validate_phrase, validate_username};
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;
pub mod types;
pub mod utils;

macro_rules! js_err {
    ($expr:expr) => {
        match $expr {
            Ok(()) => {}
            Err(e) => return Err(JsValue::from(e)),
        }
    };
}

/**
 * Create a nova folding proof for 0th degree (identity proof/ knowledge of phrase)
 * @notice cannot handle invalid r1cs/ wasm artifacts, use js functions in grapevine.js
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
) -> Result<String, JsValue> {
    init_panic_hook();
    // validate inputs
    js_err!(validate_username(&username));
    js_err!(validate_phrase(&phrase));
    js_err!(validate_auth_secret(&auth_secret));

    // parse params
    let params: Params = match serde_json::from_str(&params_str) {
        Ok(params) => params,
        Err(e) => {
            return js_err!(Err(JsValue::from_str("Could not parse public params")));
        }
    };

    // load r1cs from remote url
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;

    // get logic step inputs (chaff -> degree 0 -> chaff)
    let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();

    build_step_inputs(
        &mut private_inputs,
        Some(phrase),
        [None, Some(username)],
        [None, Some(bigint_to_fr(auth_secret).unwrap())],
    );

    // compute the first fold (identity proof)
    let proof = match create_recursive_circuit(
        FileLocation::URL(wc_url),
        r1cs.clone(),
        private_inputs,
        start_input().to_vec(),
        &params,
    )
    .await
    {
        Ok(proof) => proof,
        Err(e) => {
            return Err(JsValue::from_str(&(format!("Proof creation error: {e}"))));
        }
    };

    // serialize the proof into a string and return
    Ok(serde_json::to_string(&proof).unwrap())
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
) -> Result<String, JsValue> {
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
        .map(|auth_secret| Some(bigint_to_fr(auth_secret.as_string().unwrap())))
        .collect::<Vec<Option<Fr>>>()
        .try_into()
        .unwrap();

    // build the private inputs
    let mut private_inputs: Vec<HashMap<String, Value>> = Vec::new();
    build_step_inputs(&mut private_inputs, None, usernames, auth_secrets);

    // parse the previous outputs (step_in for next proof)
    let zi_primary: Vec<Fr> = prev_output
        .iter()
        .map(|output| bigint_to_fr(output.as_string().unwrap()))
        .collect();

    console_log!("res in: {:?}", zi_primary);

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
        &params,
    )
    .await
    .unwrap();

    // serialize the proof into a string and return
    serde_json::to_string(&proof).unwrap()
}

// /**
//  * Convenient utility for turning known values into the serialized prev_inputs for a proof
//  *
//  * @param phrase_hash - the phrase hash as a stringified bigint
//  * @param auth_hash - the auth hash as a stringified bigint
//  * @param degree - the degree of separation of the proof outputting this auth_hash
//  * @return - the array used as prev_inputs for the next proof
//  */
// #[wasm_bindgen]
// pub async fn serialize_prev_outputs(
//     phrase_hash: String,
//     auth_hash: String,
//     degree: Number
// ) -> Array {
//     // fill array with hashes and return
//     let arr = Array::new_with_length(4);
//     arr.set(0, degree.into());
//     arr.set(1, JsValue::from_str(&phrase_hash));
//     arr.set(2, JsValue::from_str(&auth_hash));
//     arr.set(3, JsValue::from_str("0x00"));
//     arr
// }

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
    degree: Number,
) -> Result<Array, JsValue> {
    // parse the params
    let params: Params = serde_json::from_str(&params_str).unwrap();

    // parse the proof
    let proof: NovaProof = serde_json::from_str(&proof_str).unwrap();

    // compute the number of steps in the fold given the degree of separation
    let num_steps = (degree.as_f64().unwrap() as usize) * 2 + 1;

    let res = proof
        .verify(&params, num_steps, &start_input(), &z0_secondary().to_vec())
        .unwrap();

    // fill array with hashes and return
    let arr = Array::new_with_length(4);
    arr.set(0, JsValue::from_str(&fr_to_bigint(res.0[0])));
    arr.set(1, JsValue::from_str(&fr_to_bigint(res.0[1])));
    arr.set(2, JsValue::from_str(&fr_to_bigint(res.0[2])));
    arr.set(3, JsValue::from_str("0x00"));
    arr
}
