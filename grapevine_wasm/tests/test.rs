use grapevine_common::auth_secret;
use grapevine_wasm::utils::{fr_to_bigint, retrieve_chunked_params};
use grapevine_wasm::{identity_proof, degree_proof, verify_proof};
use grapevine_common::{utils::random_fr, Params, G1, G2, crypto::phrase_hash};
use js_sys::{Array, BigInt, Number};
use nova_scotia::{FileLocation, circom::reader::load_r1cs};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;


const ARTIFACT_BUCKET_URL: &str = "https://bjj-ecdsa-nova.us-southeast-1.linodeobjects.com/grapevine/v0/";

#[ignore]
#[wasm_bindgen_test]
async fn test_retrieve_artifact() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // load the r1cs
    let r1cs_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.r1cs");
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;

    // retrieve the chunked params and assemble
    let params_url = format!("{}{}", ARTIFACT_BUCKET_URL, "chunks/");
    let params_str = retrieve_chunked_params(params_url).await;
    let params: Params = serde_json::from_str(&params_str).unwrap();
}

#[ignore]
#[wasm_bindgen_test]
async fn test_identity_proof_wasm() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // setup inputs
    let phrase = String::from(
        "Easier than folding a chair. like one of the folding ones at outdoor events.",
    );
    let usernames: Vec<String> = vec!["mach34", "jp4g", "ianb", "ct"]
        .iter()
        .map(|s| String::from(*s))
        .collect();
    let auth_secrets: Vec<String> = vec![random_fr(), random_fr(), random_fr(), random_fr()]
        .iter()
        .map(|el| fr_to_bigint(*el))
        .collect();

    console_log!("Auth secrets: {:#?}", auth_secrets);

    // define artifact urls & retrieve the chunked params 
    let params_url = format!("{}{}", ARTIFACT_BUCKET_URL, "chunks/");
    let r1cs_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.r1cs");
    let wc_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.wasm");
    let params_str = retrieve_chunked_params(params_url).await;
    console_log!("Retrieved params");
    

    // start fold with identity proof
    let proof = identity_proof(
        wc_url.clone(),
        r1cs_url.clone(),
        params_str.clone(),
        phrase,
        usernames[0].clone(),
        auth_secrets[0].clone()
    ).await;

    console_log!("Built identity proof");

    // verify first degree
    let verified_res = verify_proof(
        params_str.clone(),
        proof.clone(),
        Number::from(1)
    ).await;

    let phrase_hash = verified_res.get(0).as_string().unwrap();
    console_log!("Phrase hash: {}", phrase_hash);
    let auth_hash = verified_res.get(1).as_string().unwrap();
    console_log!("Auth hash: {}", auth_hash);
}

#[wasm_bindgen_test]
async fn test_degree_4_wasm() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // setup inputs
    let phrase = String::from(
        "Fold this, you filthy casual",
    );
    let usernames: Vec<String> = vec!["mach34", "jp4g", "ianb", "ct"]
        .iter()
        .map(|s| String::from(*s))
        .collect();
    let auth_secrets: Vec<String> = vec![random_fr(), random_fr(), random_fr(), random_fr()]
        .iter()
        .map(|el| fr_to_bigint(*el))
        .collect();

    console_log!("Auth secrets: {:#?}", auth_secrets);

    // define artifact urls & retrieve the chunked params 
    let params_url = format!("{}{}", ARTIFACT_BUCKET_URL, "chunks/");
    let r1cs_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.r1cs");
    let wc_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.wasm");
    let params_str = retrieve_chunked_params(params_url).await;
    console_log!("Retrieved params");
    

    // start fold with identity proof
    let proof = identity_proof(
        wc_url.clone(),
        r1cs_url.clone(),
        params_str.clone(),
        phrase,
        usernames[0].clone(),
        auth_secrets[0].clone()
    ).await;

    console_log!("Built identity proof");

    // verify first degree
    let verified_res = verify_proof(
        params_str.clone(),
        proof.clone(),
        Number::from(1)
    ).await;

    let phrase_hash = verified_res.get(0).as_string().unwrap();
    let auth_hash = verified_res.get(1).as_string().unwrap();

    // build next inputs
    let prev_outputs = Array::new_with_length(4);
    prev_outputs.set(0, JsValue::from_str("0x00"));
    prev_outputs.set(1, JsValue::from_str(&phrase_hash));
    prev_outputs.set(2, JsValue::from_str(&auth_hash));
    prev_outputs.set(3, JsValue::from_str("0x00"));

    let usernames_arr = Array::new_with_length(2);
    usernames_arr.set(0, JsValue::from_str(&usernames[0]));
    usernames_arr.set(1, JsValue::from_str(&usernames[1]));

    let auth_secrets_arr = Array::new_with_length(2);
    auth_secrets_arr.set(0, JsValue::from_str(&auth_secrets[0]));
    auth_secrets_arr.set(1, JsValue::from_str(&auth_secrets[1]));

    console_log!("Building degree proof");
    // build next proof
    let proof = degree_proof(
        wc_url.clone(),
        r1cs_url.clone(),
        params_str.clone(),
        usernames_arr,
        auth_secrets_arr,
        prev_outputs,
        proof
    ).await;

    console_log!("Verifying degree proof");

    // verify second degree
    let verified_res = verify_proof(
        params_str.clone(),
        proof.clone(),
        Number::from(2)
    ).await;
}

#[ignore]
#[wasm_bindgen_test]
async fn test_native_hash() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);

    // setup inputs
    let phrase = String::from(
        "Easier than folding a chair. like one of the folding ones at outdoor events.",
    );
    let usernames: Vec<String> = vec!["mach34", "jp4g"]
        .iter()
        .map(|s| String::from(*s))
        .collect();
    let auth_secrets: Vec<String> = vec![random_fr(), random_fr()]
        .iter()
        .map(|el| fr_to_bigint(*el))
        .collect();

    // define artifact urls & retrieve the chunked params 
    let params_url = format!("{}{}", ARTIFACT_BUCKET_URL, "chunks/");
    let r1cs_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.r1cs");
    let wc_url = format!("{}{}", ARTIFACT_BUCKET_URL, "grapevine.wasm");
    let params_str = retrieve_chunked_params(params_url).await;    

    // start fold with identity proof
    let proof = identity_proof(
        wc_url.clone(),
        r1cs_url.clone(),
        params_str.clone(),
        phrase.clone(),
        usernames[0].clone(),
        auth_secrets[0].clone()
    ).await;

    // verify first degree
    let verified_res = verify_proof(
        params_str.clone(),
        proof.clone(),
        Number::from(1)
    ).await;

    let empirical_phrase_hash = verified_res.get(0).as_string().unwrap();
    console_log!("Circuit phrase hash: {}", empirical_phrase_hash);

    // compute expected hash
    let expected_phrase_hash = phrase_hash(&phrase);
    console_log!("Expected phrase hash: 0x{}", hex::encode(expected_phrase_hash));

    let e = phrase_hash(&String::from(""));
    console_log!("Empirical hash: 0x{}", hex::encode(e));
}

