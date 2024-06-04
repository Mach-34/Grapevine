use super::{
    start_input,
    utils::{build_step_inputs, read_public_params},
    z0_secondary, DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH,
};
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
 * Create a nova proof for N degrees of separation, where N is the length of the usernames vector - 1
 * @notice - proving knowledge of preimage is degree 0 hence 1 username means N = 0
 *
 * @param wc_path - the relative path to the witness generator file to use to compute public params (if none use default)
 * @param r1cs - the r1cs of the grapevine circuit
 * @param public_params - the public params to use to compute the proof
 * @param phrase - the secret phrase to prove knowledge of
 * @param pubkeys - the babyjubjub public keys to verify auth signatures with
 * @param auth_signatures - the auth signatures to use to make it impossible to prove degree of separation without previous user signing current user pubkey
 */
pub fn nova_proof(
    wc_path: PathBuf,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
    phrase: &String,
    pubkeys: &Vec<Point>,
    auth_signatures: &Vec<[Fr; 3]>,
) -> Result<NovaProof, std::io::Error> {
    // marshall private inputs into circom inputs
    let mut private_inputs = Vec::new();
    for i in 0..pubkeys.len() {
        // set input options
        let phrase_input = match i {
            0 => Some(phrase.clone()),
            _ => None,
        };
        let auth_signature_input = match i {
            0 => [None, None, None],
            _ => auth_signatures[i].map(|signature| Some(signature)),
        };

        // marshall inputs into the private inputs vector
        build_step_inputs(
            &mut private_inputs,
            phrase_input,
            &pubkeys[i],
            auth_signature_input,
        );
    }

    println!("Start input: {:?}", start_input());

    // generate the a recursive Nova proof of the grapevine circuit
    create_recursive_circuit(
        FileLocation::PathBuf(wc_path),
        r1cs.clone(),
        private_inputs,
        start_input().to_vec(),
        &public_params,
    )
}

/**
 * Verify the correct execution of a nova-grapevine proof of the grapevine circuit
 *
 * @param proof - the proof to verify
 * @param public_params - the public params to use to verify the proof
 * @param iterations - the number of iterations to run the verification ((degrees_of_separation + 1) * 2)
 * @return - true if the proof is valid, false otherwise
 */
pub fn verify_nova_proof(
    proof: &NovaProof,
    public_params: &Params,
    iterations: usize,
) -> Result<(Vec<Fr>, Vec<Fq>), NovaError> {
    proof.verify(public_params, iterations, &start_input(), &z0_secondary())
}

/**
 * Prove another degree of separation using an existing proof from a grapevine circuit
 *
 * @param usernames - the usernames to use in the chain of degrees of separation [prev username, current username]
 *   - todo: check size of usernames is 2
 * @param auth_secrets - the auth_secrets to use to obscure hash at each degree of separation
 * @param proof - the proof of degrees of separation to incrementally prove
 * @param previous_output - the output of the previous proof (z_last)
 * @param wc_path - the relative path to the witness calculator file (if none use default)
 * @param r1cs - the r1cs of the grapevine circuit
 * @param public_params - the public params to use to compute the proof
 */
pub fn continue_nova_proof(
    pubkey: &Point,
    auth_signature: &[Fr; 3],
    proof: &mut NovaProof,
    previous_output: Vec<Fr>,
    wc_path: PathBuf,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
) -> Result<(), std::io::Error> {
    // compute the private inputs for this degree's compute/ chaff step
    let mut private_inputs = Vec::new();
    build_step_inputs(
        &mut private_inputs,
        None,
        pubkey,
        [
            Some(auth_signature[0]),
            Some(auth_signature[1]),
            Some(auth_signature[2]),
        ],
    );

    // compute the next round of the proof
    continue_recursive_circuit(
        proof,
        previous_output,
        FileLocation::PathBuf(wc_path),
        r1cs.clone(),
        private_inputs,
        start_input().to_vec(),
        &public_params,
    )
}

// /**
//  * Compute the proving and verifying keys for a compressed circuit
//  *
//  * @param public_params - the public params to use to compute the keys
//  * @return - the proving and verifying keys for the compressed circuit
//  */
// pub fn setup_compressed_proof(public_params: &Params) -> (ProvingKey, VerifyingKey) {
//     CompressedProof::setup(public_params).unwrap()

//     // CompressedProof::setup(public_params).unwrap()
// }

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::{compress_proof, decompress_proof, read_proof, write_proof};
    use grapevine_common::{account::GrapevineAccount, utils::random_fr};
    use nova_scotia::create_public_params;

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
        // Test proving knowledge of a secret (1 degree of separation)
        let phrase: String = String::from("There's no place like home");
        let account = GrapevineAccount::new(String::from("mach34"));
        let auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            wc_path,
            &r1cs,
            &public_params,
            &phrase,
            &vec![account.pubkey()],
            &auth_signatures,
        )
        .unwrap();

        let iterations = 1 + auth_signatures.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_1() {
        // Test proving knowledge of a secret (1 degree of separation) and the second degree of separation
        let phrase = String::from("hunter2");
        let accounts = vec!["mach34", "jp4g"]
            .iter()
            .map(|s| GrapevineAccount::new(String::from(*s)))
            .collect::<Vec<GrapevineAccount>>();
        let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
        for i in 1..accounts.len() {
            let recipient_pubkey = accounts[i].pubkey();
            let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
            let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
            auth_signatures.push(decrypted.fmt_circom());
        }

        let pubkeys = accounts
            .iter()
            .map(|acc| acc.pubkey())
            .collect::<Vec<Point>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            wc_path,
            &r1cs,
            &public_params,
            &phrase,
            &pubkeys,
            &auth_signatures,
        )
        .unwrap();

        let iterations = 1 + accounts.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_3() {
        // Test proving knowledge of a secret (1 degree of separation) and the second, third, and fourth degree of separation
        let phrase = String::from(
            "Easier than folding a chair. like one of the folding ones at outdoor events.",
        );
        let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| GrapevineAccount::new(String::from(*s)))
            .collect::<Vec<GrapevineAccount>>();
        let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

        for i in 1..accounts.len() {
            let recipient_pubkey = accounts[i].pubkey();
            let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
            let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
            auth_signatures.push(decrypted.fmt_circom());
        }

        let pubkeys = accounts
            .iter()
            .map(|acc| acc.pubkey())
            .collect::<Vec<Point>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            wc_path,
            &r1cs,
            &public_params,
            &phrase,
            &pubkeys,
            &auth_signatures,
        )
        .unwrap();

        let iterations = 1 + accounts.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();

        // todo: compute expected output
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_sequential_proving() {
        // define inputs
        let phrase = String::from(
            "Easier than folding a chair. like one of the folding ones at outdoor events.",
        );
        let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| GrapevineAccount::new(String::from(*s)))
            .collect::<Vec<GrapevineAccount>>();
        let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

        for i in 1..accounts.len() {
            let recipient_pubkey = accounts[i].pubkey();
            let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
            let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
            auth_signatures.push(decrypted.fmt_circom());
        }

        let pubkeys = accounts
            .iter()
            .map(|acc| acc.pubkey())
            .collect::<Vec<Point>>();

        // define paths
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");

        // load public params and r1cs
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        // PROVE DEGREE 1 //
        let degree = 1;
        let mut proof = nova_proof(
            wc_path.clone(),
            &r1cs,
            &public_params,
            &phrase,
            &vec![pubkeys[0].clone()],
            &vec![auth_signatures[0]],
        )
        .unwrap();

        let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
        let mut z0_last = res.0; // step_out for the circuit execution
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // PROVE DEGREE 2 - 4 //
        for i in 1..accounts.len() {
            let degree = i + 1;
            continue_nova_proof(
                &pubkeys[i],
                &auth_signatures[i],
                &mut proof,
                z0_last,
                wc_path.clone(),
                &r1cs,
                &public_params,
            )
            .unwrap();
            let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
            z0_last = res.0;
            assert!(z0_last[0].eq(&Fr::from(degree as u64)));
        }
    }

    #[test]
    fn test_continued_fs() {
        // test recursively proving degree 1 and 2 where proof 1 is saved to fs then read in for proof 2
        // define inputs
        let phrase = String::from("Filesystem filesystem system of a file");
        let accounts = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| GrapevineAccount::new(String::from(*s)))
            .collect::<Vec<GrapevineAccount>>();
        let mut auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];

        for i in 1..accounts.len() {
            let recipient_pubkey = accounts[i].pubkey();
            let auth_signature = accounts[i - 1].generate_auth_signature(recipient_pubkey);
            let decrypted = accounts[i].decrypt_auth_signature(auth_signature);
            auth_signatures.push(decrypted.fmt_circom());
        }

        let pubkeys = accounts
            .iter()
            .map(|acc| acc.pubkey())
            .collect::<Vec<Point>>();

        // define paths
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");

        // load public params and r1cs
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        // PROVE DEGREE 1 //
        let degree = 1;
        let proof = nova_proof(
            wc_path.clone(),
            &r1cs,
            &public_params,
            &phrase,
            &vec![pubkeys[0].clone()],
            &vec![auth_signatures[0]],
        )
        .unwrap();

        let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
        let z0_last = res.0; // step_out for the circuit execution
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // safe to fs
        let proof_path = std::env::current_dir()
            .unwrap()
            .join(format!("grapevine_degree_{}.gz", degree));
        write_proof(&proof, proof_path.clone());

        // PROVE DEGREE 2 //
        // read proof from fs
        let mut proof = read_proof(proof_path.clone());
        // get z0_last
        let z0_last = verify_nova_proof(&proof, &public_params, 1 + degree * 2)
            .unwrap()
            .0;
        // prove second degree
        let degree = 2;
        continue_nova_proof(
            &pubkeys[1],
            &auth_signatures[1],
            &mut proof,
            z0_last,
            wc_path.clone(),
            &r1cs,
            &public_params,
        )
        .unwrap();
        let res = verify_nova_proof(&proof, &public_params, 1 + degree * 2).unwrap();
        let z0_last = res.0;
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    }

    #[test]
    fn test_compression() {
        // Compute a proof
        let phrase: String = String::from("There's no place like home");
        let account = GrapevineAccount::new(String::from("mach34"));
        let auth_signatures = vec![[random_fr(), random_fr(), random_fr()]];
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/grapevine.r1cs");
        let wc_path = current_dir()
            .unwrap()
            .join("circom/artifacts/grapevine_js/grapevine.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));
        let proof = nova_proof(
            wc_path,
            &r1cs,
            &public_params,
            &phrase,
            &vec![account.pubkey()],
            &auth_signatures,
        )
        .unwrap();

        // compress the proof
        let compressed_proof = compress_proof(&proof);

        // compare proof sizes when compressed vs uncompressed
        let serialized = serde_json::to_string(&proof).unwrap().as_bytes().to_vec();
        println!("Uncompressed proof size: {}", serialized.len());
        println!("Compressed proof size: {}", compressed_proof.len());

        // decompress the proof
        let decompressed_proof = decompress_proof(&compressed_proof[..]);

        // verify the compressed then uncompressed proof
        let iterations = 3;
        verify_nova_proof(&decompressed_proof, &public_params, iterations).unwrap();
    }
}
