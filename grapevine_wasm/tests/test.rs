use grapevine_wasm::utils::retrieve_chunked_params;
use grapevine_common::{G1, G2, Params};
use js_sys::BigInt;
use nova_scotia::{FileLocation, circom::reader::load_r1cs};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;


const ARTIFACT_BUCKET_URL: &str = "https://bjj-ecdsa-nova.us-southeast-1.linodeobjects.com/grapevine/v0/";

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

