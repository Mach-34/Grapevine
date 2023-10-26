use super::{
    Params, EMPTY_SECRET, MAX_SECRET_CHARS, MAX_USERNAME_CHARS, SECRET_FIELD_LENGTH,
    ZERO,
};
use serde_json::{json, Value};
use serde::{de::DeserializeOwned};
use std::{collections::HashMap, env::current_dir, error::Error};

/**
 * Converts a given word to array of 6 field elements
 * @dev split into 31-byte strings to fit in finite field and pad with 0's where necessary
 *
 * @param phrase - the string entered by user to compute hash for (will be length checked)
 * @return - array of 6 Fr elements
 */
pub fn convert_phrase_to_felts(
    phrase: &String,
) -> Result<[String; SECRET_FIELD_LENGTH], Box<dyn Error>> {
    // check
    if phrase.len() > MAX_SECRET_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }

    let mut chunks: [String; SECRET_FIELD_LENGTH] = Default::default();
    for i in 0..SECRET_FIELD_LENGTH {
        let start = i * 31;
        let end = (i + 1) * 31;
        let mut chunk: [u8; 32] = [0; 32];
        if start >= phrase.len() {
        } else if end > phrase.len() {
            chunk[1..(phrase.len() - start + 1)].copy_from_slice(&phrase.as_bytes()[start..]);
        } else {
            chunk[1..32].copy_from_slice(&phrase.as_bytes()[start..end]);
        }
        chunk.reverse();
        chunks[i] = format!("0x{}", hex::encode(chunk));
    }

    Ok(chunks)
}

/**
 * Converts a given username to a field element
 *
 * @param username - the username to convert to utf8 and into field element
 * @return - the username serialied into the field element
 */
pub fn convert_username_to_felt(username: &String) -> Result<String, Box<dyn Error>> {
    if username.len() > MAX_USERNAME_CHARS {
        return Err("Phrase must be <= 180 characters".into());
    }
    let mut bytes: [u8; 32] = [0; 32];
    bytes[1..(username.len() + 1)].copy_from_slice(&username.as_bytes()[..]);
    bytes.reverse();
    Ok(format!("0x{}", hex::encode(bytes)))
}

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
) {
    // convert the compute step input to strings, or get the default value
    let secret_input: [String; SECRET_FIELD_LENGTH] = match secret {
        Some(phrase) => convert_phrase_to_felts(&phrase).unwrap(),
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
            Some(username) => convert_username_to_felt(username).unwrap(),
            None => String::from(ZERO),
        })
        .collect::<Vec<String>>()
        .try_into()
        .unwrap();

    // build the input hashmaps
    let mut compute_step = HashMap::new();
    compute_step.insert("secret".to_string(), json!(secret_input));
    compute_step.insert("usernames".to_string(), json!(usernames_input));

    let mut chaff_step = HashMap::new();
    chaff_step.insert("secret".to_string(), json!(EMPTY_SECRET));
    chaff_step.insert("usernames".to_string(), json!([ZERO, ZERO]));

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

// /**
//  * Read in a proof from the filesystem
//  *
//  * @param path - the relative path to the proof json file
//  * @return - the proof object
//  */
// pub fn read_proof(path: String) -> NovaProof {
//     // get path to file
//     let root = current_dir().unwrap();
//     let filepath = root.join(path);
// }

// /**
//  * Write a proof to the filesystem
//  *
//  * @param proof - the proof object to write to the filesystem
//  * @param path - the relative path to the directory to write the proof to
//  */
// pub fn write_proof(proof: &NovaProof, path: String) -> Result<(), std::io::Error> {
//     // get fs uri to save proof to
//     let root = current_dir().unwrap();
//     let filepath = root.join(path).join("phrasedos.proof");

//     // serialize the proof
//     std::fs::write(filepath, proof.clone())
// }

//https://github.com/chainwayxyz/nova-cli/blob/main/src/utils.rs#L16
pub fn json_to_obj<T: DeserializeOwned>(file_path: std::path::PathBuf) -> T {
    let file = std::fs::File::open(file_path).expect("error");
    let reader = std::io::BufReader::new(file);
    let a: T = serde_json::from_reader(reader).expect("error");
    return a;
}

//https://github.com/chainwayxyz/nova-cli/blob/main/src/utils.rs#L23
pub fn obj_to_json<T: serde::Serialize>(file_path: std::path::PathBuf, obj: T) {
    let file = std::fs::File::create(file_path).expect("error");
    let writer = std::io::BufWriter::new(file);
    serde_json::to_writer(writer, &obj).expect("write cbor error");
}
