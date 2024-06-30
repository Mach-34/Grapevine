use super::{
    utils::read_public_params, DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH, Z0_PRIMARY,
    Z0_SECONDARY,
};
use crate::inputs::{GrapevineArtifacts, GrapevineInputs};
use babyjubjub_rs::Point;
use grapevine_common::{Fq, Fr, NovaProof, Params, G1, G2};
use nova_scotia::{
    circom::{circuit::R1CS, reader::load_r1cs},
    continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use nova_snark::errors::NovaError;
use std::{env::current_dir, path::PathBuf};
 
/**
 * Get public params for the grapevine circuit
 *
 * @param path - the relative path to the public params json file (if none use default)
 * @return  - the public parameters for proving/ verifying grapevine circuit execution
 */
pub fn get_public_params(path: Option<String>) -> Params {
    let root = current_dir().unwrap();
    let public_params_file = match path {
        Some(p) => root.join(p),
        None => root.join(DEFAULT_PUBLIC_PARAMS_PATH),
    };
    read_public_params::<G1, G2>(public_params_file.to_str().unwrap())
}

/**
 * Load the r1cs file for the grapevine circuit
 *
 * @param path - the relative path to the r1cs file of the grapevine circuit (if none use default)
 * @return - the r1cs file for the grapevine circuit
 */
pub fn get_r1cs(path: Option<String>) -> R1CS<Fr> {
    let root = current_dir().unwrap();
    let r1cs_file = match path {
        Some(p) => root.join(p),
        None => root.join(DEFAULT_R1CS_PATH),
    };
    load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file))
}

/**
 * Start a nova IVC proof of for a degree of separation chain
 * This proof is an identity step (+ chaff step) and future iterations show degree from this identity
 *
 * @param artifacts - the loaded params and R1CS, as well as a path to the wasm file
 * @param inputs - the necessary inputs for a grapevine proof
 * @return - a proof of degree 0 (identity) of grapevine identity
 */
pub fn degree_proof(
    artifacts: &GrapevineArtifacts,
    inputs: &GrapevineInputs,
) -> Result<NovaProof, std::io::Error> {
    // get the formatted inputs to the circuit
    println!("xq");
    let private_inputs = inputs.fmt_circom();
    println!("FFFF: {:#?}", private_inputs);
    // create the degree proof
    create_recursive_circuit(
        FileLocation::PathBuf(artifacts.wasm_path.clone()),
        artifacts.r1cs.clone(),
        private_inputs.to_vec(),
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
}

/**
 * Continue a nova IVC proof ofr a degree of separation chain
 * This proof is a degree step (+ chaff step) showing degree of separation from an initial identity
 *
 * @param artifacts - the loaded params and R1CS, as well as a path to the wasm file
 * @param inputs - the necessary inputs for a grapevine proof
 * @param proof - the previous proof to build from
 * @param previous output - the previous output of the proof
 * @return - a proof of degree N from a grapevine identity
 */
pub fn identity_proof(
    artifacts: &GrapevineArtifacts,
    inputs: &GrapevineInputs,
    proof: &mut NovaProof,
    previous_output: &Vec<Fr>,
) -> Result<(), std::io::Error> {
    // get the formatted inputs to the circuit
    let private_inputs = inputs.fmt_circom();
    // create the degree proof
    continue_recursive_circuit(
        proof,
        previous_output.clone(),
        FileLocation::PathBuf(artifacts.wasm_path.clone()),
        artifacts.r1cs.clone(),
        private_inputs.to_vec(),
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
}

/**
 * Verify the correct execution of an IVC proof of the grapevine circuit
 *
 * @param proof - the proof to verify
 * @param public_params - the public params to use to verify the proof
 * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
 * @return - the output of the proof if verified
 */
pub fn verify_grapevine_proof(
    proof: &NovaProof,
    public_params: &Params,
    degree: usize,
) -> Result<(Vec<Fr>, Vec<Fq>), NovaError> {
    proof.verify(public_params, degree * 2 + 2, &Z0_PRIMARY, &Z0_SECONDARY)
}

#[cfg(test)]
mod test {
    use super::*;
    use babyjubjub_rs::new_key;
    use lazy_static::lazy_static;
    use crate::utils::{compress_proof, decompress_proof, read_proof, write_proof};
    use grapevine_common::{account::GrapevineAccount, utils::random_fr};
    use nova_scotia::create_public_params;

    lazy_static! {
        pub static ref ARTIFACTS: GrapevineArtifacts = {
            // load params
            let params_path = String::from("circom/artifacts/public_params.json");
            let params = get_public_params(Some(params_path));
            // load r1cs
            let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
            let r1cs = get_r1cs(Some(r1cs_path));
            // set wasm path
            let wasm_path = current_dir().unwrap().join("circom/artifacts/grapevine.wasm");
            // return artifacts struct
            GrapevineArtifacts { params, r1cs, wasm_path }
        };
    }

    #[test]
    #[ignore]
    fn gen_public_params() {
        let root = current_dir().unwrap();
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params: Params = create_public_params(r1cs.clone());

        // save the full params
        let params_json = serde_json::to_string(&public_params).unwrap();
        let full_params_path = root.clone().join("public_params.json");
        std::fs::write(&full_params_path, &params_json).unwrap();
    }

    #[test]
    fn test_degree_0() {
        // get a random key
        let identity_key = new_key();
        // create inputs
        println!("FLAG 1");
        let identity_inputs = GrapevineInputs::identity_step(&identity_key);
        // create proof
        let proof = degree_proof(&ARTIFACTS, &identity_inputs).unwrap();
        // verify proof
        println!("FLAG 3");
        let verified = verify_grapevine_proof(&proof, &ARTIFACTS.params, 0).unwrap();
        println!("Verified: {:?}", verified);
    }

    // #[test]
    // fn test_degree_0() {
    //     // Test proving knowledge of a secret (1 degree of separation)
    //     let phrase: String = String::from("There's no place like home");
    //     let account = GrapevineAccount::new(String::from("mach34"));
    //     let auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![account.pubkey()],
    //         &auth_signatures,
    //     )
    //     .unwrap();

    //     let iterations = 1 + auth_signatures.len() * 2;
    //     let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
    //     println!("Verified: {:?}", verified);
    // }

    // #[test]
    // fn test_degree_1() {
    //     // Test proving knowledge of a secret (1 degree of separation) and the second degree of separation
    //     let phrase = String::from("hunter2");
    //     let accounts = vec!["mach34", "jp4g"]
    //         .iter()
    //         .map(|s| GrapevineAccount::new(String::from(*s)))
    //         .collect::<Vec<GrapevineAccount>>();
    //     let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
    //     for i in 1..accounts.len() {
    //         let recipient_pubkey = accounts[i].pubkey();
    //         let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
    //         let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
    //         auth_signatures.push(decrypted.fmt_circom());
    //     }

    //     let pubkeys = accounts
    //         .iter()
    //         .map(|acc| acc.pubkey())
    //         .collect::<Vec<Point>>();

    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &pubkeys,
    //         &auth_signatures,
    //     )
    //     .unwrap();

    //     let iterations = 1 + accounts.len() * 2;
    //     let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
    //     println!("Verified: {:?}", verified);
    // }

    // #[test]
    // fn test_degree_3() {
    //     // Test proving knowledge of a secret (1 degree of separation) and the second, third, and fourth degree of separation
    //     let phrase = String::from(
    //         "Easier than folding a chair. like one of the folding ones at outdoor events.",
    //     );
    //     let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
    //         .iter()
    //         .map(|s| GrapevineAccount::new(String::from(*s)))
    //         .collect::<Vec<GrapevineAccount>>();
    //     let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

    //     for i in 1..accounts.len() {
    //         let recipient_pubkey = accounts[i].pubkey();
    //         let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
    //         let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
    //         auth_signatures.push(decrypted.fmt_circom());
    //     }

    //     let pubkeys = accounts
    //         .iter()
    //         .map(|acc| acc.pubkey())
    //         .collect::<Vec<Point>>();

    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &pubkeys,
    //         &auth_signatures,
    //     )
    //     .unwrap();

    //     let iterations = 1 + accounts.len() * 2;
    //     let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();

    //     // todo: compute expected output
    //     println!("Verified: {:?}", verified);
    // }

    // #[test]
    // fn test_sequential_proving() {
    //     // define inputs
    //     let phrase = String::from(
    //         "Easier than folding a chair. like one of the folding ones at outdoor events.",
    //     );
    //     let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
    //         .iter()
    //         .map(|s| GrapevineAccount::new(String::from(*s)))
    //         .collect::<Vec<GrapevineAccount>>();
    //     let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

    //     for i in 1..accounts.len() {
    //         let recipient_pubkey = accounts[i].pubkey();
    //         let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
    //         let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
    //         auth_signatures.push(decrypted.fmt_circom());
    //     }

    //     let pubkeys = accounts
    //         .iter()
    //         .map(|acc| acc.pubkey())
    //         .collect::<Vec<Point>>();

    //     // define paths
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");

    //     // load public params and r1cs
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     // PROVE DEGREE 1 //
    //     let degree = 1;
    //     let mut proof = nova_proof(
    //         wc_path.clone(),
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![pubkeys[0].clone()],
    //         &vec![auth_signatures[0]],
    //     )
    //     .unwrap();

    //     let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //     let mut z0_last = res.0; // step_out for the circuit execution
    //     assert!(z0_last[0].eq(&Fr::from(degree as u64)));

    //     // PROVE DEGREE 2 - 4 //
    //     for i in 1..accounts.len() {
    //         let degree = i + 1;
    //         continue_nova_proof(
    //             &pubkeys[i],
    //             &auth_signatures[i],
    //             &mut proof,
    //             z0_last,
    //             wc_path.clone(),
    //             &r1cs,
    //             &public_params,
    //         )
    //         .unwrap();
    //         let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //         z0_last = res.0;
    //         assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    //     }
    // }

    // #[test]
    // fn test_continued_fs() {
    //     // test recursively proving degree 1 and 2 where proof 1 is saved to fs then read in for proof 2
    //     // define inputs
    //     let phrase = String::from("Filesystem filesystem system of a file");
    //     let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
    //         .iter()
    //         .map(|s| GrapevineAccount::new(String::from(*s)))
    //         .collect::<Vec<GrapevineAccount>>();
    //     let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

    //     for i in 1..accounts.len() {
    //         let recipient_pubkey = accounts[i].pubkey();
    //         let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
    //         let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
    //         auth_signatures.push(decrypted.fmt_circom());
    //     }

    //     let pubkeys = accounts
    //         .iter()
    //         .map(|acc| acc.pubkey())
    //         .collect::<Vec<Point>>();

    //     // define paths
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");

    //     // load public params and r1cs
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));

    //     // PROVE DEGREE 1 //
    //     let degree = 1;
    //     let proof = nova_proof(
    //         wc_path.clone(),
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![pubkeys[0].clone()],
    //         &vec![auth_signatures[0]],
    //     )
    //     .unwrap();

    //     let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //     let z0_last = res.0; // step_out for the circuit execution
    //     assert!(z0_last[0].eq(&Fr::from(degree as u64)));

    //     // safe to fs
    //     let proof_path = std::env::current_dir()
    //         .unwrap()
    //         .join(format!("grapevine_degree_{}.gz", degree));
    //     write_proof(&proof, proof_path.clone());

    //     // PROVE DEGREE 2 //
    //     // read proof from fs
    //     let mut proof = read_proof(proof_path.clone());
    //     // get z0_last
    //     let z0_last = verify_nova_proof(&proof, &public_params, 1 + degree * 2)
    //         .unwrap()
    //         .0;
    //     // prove second degree
    //     let degree = 2;
    //     continue_nova_proof(
    //         &pubkeys[1],
    //         &auth_signatures[1],
    //         &mut proof,
    //         z0_last,
    //         wc_path.clone(),
    //         &r1cs,
    //         &public_params,
    //     )
    //     .unwrap();
    //     let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
    //     let z0_last = res.0;
    //     assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    // }

    // #[test]
    // fn test_compression() {
    //     // Compute a proof
    //     let phrase: String = String::from("There's no place like home");
    //     let account = GrapevineAccount::new(String::from("mach34"));
    //     let auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
    //     let params_path = String::from("circom/artifacts/public_params.json");
    //     let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
    //     let wc_path = current_dir()
    //         .unwrap()
    //         .join("circom/artifacts/grapevine_js/grapevine.wasm");
    //     let r1cs = get_r1cs(Some(r1cs_path));
    //     let public_params = get_public_params(Some(params_path));
    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &public_params,
    //         &phrase,
    //         &vec![account.pubkey()],
    //         &auth_signatures,
    //     )
    //     .unwrap();

    //     // compress the proof
    //     let compressed_proof = compress_proof(&proof);

    //     // compare proof sizes when compressed vs uncompressed
    //     let serialized = serde_json::to_string(&proof).unwrap().as_bytes().to_vec();
    //     println!("Uncompressed proof size: {}", serialized.len());
    //     println!("Compressed proof size: {}", compressed_proof.len());

    //     // decompress the proof
    //     let decompressed_proof = decompress_proof(&compressed_proof[..]);

    //     // verify the compressed then uncompressed proof
    //     let iterations = 3;
    //     verify_nova_proof(&decompressed_proof, &public_params, iterations).unwrap();
    // }
}
