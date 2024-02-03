use super::{EMPTY_SECRET, SECRET_FIELD_LENGTH, ZERO};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use grapevine_common::utils::{convert_phrase_to_fr, convert_username_to_fr};
use grapevine_common::{Fr, NovaProof, Params};
use serde_json::{json, Error, Value};
use std::io::{Read, Write};
use std::{collections::HashMap, env::current_dir};

/**
 * Given an input hashmap vec and some inputs, build the inputs for a compute
 * and chaff step and add them into the input hashmap vector
 *
 * @param input - reference to a vector of hashmaps containing inputs for each step of the circuit
 * @param secret - optionally provide the secret to prove knowledge of if degree is 0
 * @param username - optionally provide one or both usernames to hash against
 *   - note: usernames[1] will never be 0 in practice
 * @return - the inputs for one computation step and chaff step
 */
pub fn build_step_inputs(
    input: &mut Vec<HashMap<String, Value>>,
    secret: Option<String>,
    usernames: [Option<String>; 2],
    auth_secrets: [Option<Fr>; 2],
) {
    // @TODO: FIX convert_phrase_to_fr and convert_username_to_fr inputs

    // convert the compute step input to strings, or get the default value
    let secret_input: [String; SECRET_FIELD_LENGTH] = match secret {
        Some(phrase) => convert_phrase_to_fr(&phrase)
            .unwrap()
            .iter()
            .map(|chunk| format!("0x{}", hex::encode(chunk)))
            .collect::<Vec<String>>()
            .try_into()
            .unwrap(),

        None => EMPTY_SECRET
            .iter()
            .map(|limb| String::from(*limb))
            .collect::<Vec<String>>()
            .try_into()
            .unwrap(),
    };
    let usernames_input: [String; 2] = usernames
        .iter()
        .map(|username| match username {
            Some(username) => format!(
                "0x{}",
                hex::encode(convert_username_to_fr(username).unwrap())
            ),
            None => String::from(ZERO),
        })
        .collect::<Vec<String>>()
        .try_into()
        .unwrap();
    let auth_secrets_input: [String; 2] = auth_secrets
        .iter()
        .map(|auth_secret| match auth_secret {
            Some(auth_secret) => format!("0x{}", hex::encode(auth_secret.to_bytes())),
            None => String::from(ZERO),
        })
        .collect::<Vec<String>>()
        .try_into()
        .unwrap();

    // build the input hashmaps
    let mut compute_step = HashMap::new();
    compute_step.insert("phrase".to_string(), json!(secret_input));
    compute_step.insert("usernames".to_string(), json!(usernames_input));
    compute_step.insert("auth_secrets".to_string(), json!(auth_secrets_input));

    let mut chaff_step = HashMap::new();
    chaff_step.insert("phrase".to_string(), json!(EMPTY_SECRET));
    chaff_step.insert("usernames".to_string(), json!([ZERO, ZERO]));
    chaff_step.insert("auth_secrets".to_string(), json!([ZERO, ZERO]));

    // push the compute and chaff step inputs to the input vector
    input.push(compute_step);
    input.push(chaff_step);
}

/**
 * Read in a previously computed public params file
 * https://github.com/dmpierre/zkconnect4/blob/86a129400647edc75a06f032bfb466186874c489/zkconnect4-nova-lib/src/lib.rs#L229C1-L238C2\
 *
 * @param path - the relative path to the public params json file
 * @return - the public params object
 **/
pub fn read_public_params<G1, G2>(path: &str) -> Params {
    // get path to file
    let root = current_dir().unwrap();
    let filepath = root.join(path);

    // read in params file
    let public_params_file = std::fs::read_to_string(filepath).expect("Unable to read file");

    // parse file into params struct
    let public_params: Params =
        serde_json::from_str(&public_params_file).expect("Incorrect public params format");

    public_params
}

/**
 * Write a Nova Proof to the filesystem
 *
 * @param proof - the Nova Proof to write to fs
 * @path - the filepath to save the proof to - includes filename
 */
pub fn write_proof(proof: &NovaProof, path: std::path::PathBuf) {
    // compress the proof
    let compressed_proof = compress_proof(proof);
    // write the proof to fs
    std::fs::write(path, compressed_proof).expect("Unable to write proof");
}

/**
 * Read a Nova Proof from the filesystem
 *
 * @param path - the filepath to read the proof from
 */
pub fn read_proof(path: std::path::PathBuf) -> NovaProof {
    // read the proof from fs
    let compressed_proof = std::fs::read(path).expect("Unable to read proof");
    // decompress the proof
    decompress_proof(&compressed_proof[..]).expect("Failed to parse bytes into Nova Proof")
}

/**
 * Compress a Nova Proof with flate2 for transit to the server and storage
 *
 * @param proof - the Nova Proof to compress
 * @return - the compressed proof
 */
pub fn compress_proof(proof: &NovaProof) -> Vec<u8> {
    // serialize proof to json
    let serialized = serde_json::to_string(&proof).unwrap();
    // compress serialized proof
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(serialized.as_bytes()).unwrap();
    // return compressed proof
    encoder.finish().unwrap()
}

/**
 * Decompress a Nova Proof with flate2 for transit to the server and storage
 *
 * @param proof - the compressed Nova Proof to decompress
 * @return - the decompressed proof
 */
pub fn decompress_proof(proof: &[u8]) -> Result<NovaProof, Error> {
    // decompress the proof into the serialized json string
    let mut decoder = GzDecoder::new(proof);
    let mut serialized = String::new();
    decoder.read_to_string(&mut serialized).unwrap();
    // deserialize the proof
    serde_json::from_str(&serialized)
}

mod test {
    use grapevine_common::utils::{convert_phrase_to_fr, convert_username_to_fr};

    #[test]
    fn test_phrase_to_fr() {
        let phrase = String::from("And that's the waaaayyy the news goes");
        let bytes = convert_phrase_to_fr(&phrase);
        println!("Phrase bytes {:?}", bytes);
    }

    #[test]
    fn test_username_to_fr() {
        let username = String::from("Chad Chadson");
        let bytes = convert_username_to_fr(&username);
        println!("User bytes {:?}", bytes);
    }
}
