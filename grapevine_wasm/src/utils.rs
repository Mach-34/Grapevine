use ff::PrimeField;
use flate2::read::GzDecoder;
use grapevine_common::Fr;
use num::{BigInt, Num};
use reqwest::header::CONTENT_TYPE;
use std::io::Read;
use wasm_bindgen::prelude::*;

pub const PARAMS_CHUNKS: usize = 10;

/**
 * Retrieves gzipped params from a url and unzips it
 *
 * @param url - the url to retrieve the params from
 * @param chunks - the number of file chunks
 *   - if < 2 no chunks added
 *   - if >= 2, append -{chunk #} to the url for each chunk
 */
#[wasm_bindgen]
pub async fn retrieve_chunked_params(url: String) -> String {
    // retrieve the chunked params and assemble
    let mut artifact_gz = Vec::<u8>::new();
    let client = reqwest::Client::new();
    for i in 0..PARAMS_CHUNKS {
        let artifact_url = format!("{}params_{}.gz", url, i);
        let mut chunk = client
            .get(&artifact_url)
            .header(CONTENT_TYPE, "application/x-binary")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec();
        artifact_gz.append(&mut chunk);
    }
    // decompress the artifact
    let mut decoder = GzDecoder::new(&artifact_gz[..]);
    let mut serialized = String::new();
    decoder.read_to_string(&mut serialized).unwrap();

    serialized
}

/**
 * Converts a stringified bigint to bn254 Fr
 * @notice assumes little endian order
 *
 * @param val - the bigint to parse
 * @return - the field element
 */
pub fn bigint_to_fr(val: String) -> Fr {
    // if the string contains 0x, remove it
    let val = if val.starts_with("0x") {
        val[2..].to_string()
    } else {
        val
    };
    // parse the string
    let mut bytes = BigInt::from_str_radix(&val, 10).unwrap().to_bytes_le().1;
    // pad bytes to end if necessary (LE)
    if bytes.len() < 32 {
        let mut padded = vec![0; 32 - bytes.len()];
        bytes.append(&mut padded);
    }
    let bytes = bytes.try_into().unwrap();
    Fr::from_repr(bytes).unwrap()
}

/**
 * Converts a bn254 Fr to a stringified bigint in little endian
 * 
 * @param val - the field element to convert
 * @return - the stringified bigint in hex
 */
pub fn fr_to_bigint(val: Fr) -> String {
    format!("0x{}", hex::encode(val.to_bytes()))
}
