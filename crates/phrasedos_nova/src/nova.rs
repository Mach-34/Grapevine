use super::{
    start_input,
    utils::{build_step_inputs, read_public_params},
    z0_secondary, Fq, Fr, NovaProof, Params, DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH,
    DEFAULT_WC_PATH, G1, G2,
};
use nova_scotia::{
    circom::{circuit::R1CS, reader::load_r1cs},
    continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use nova_snark::errors::NovaError;
use std::env::current_dir;

/**
 * Get public params for the phrasedos circuit
 *
 * @param path - the relative path to the public params json file (if none use default)
 * @return  - the public parameters for proving/ verifying folded circuit execution
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
 * Load the r1cs file for the phrasedos circuit
 *
 * @param path - the relative path to the r1cs file of the phrasedos circuit (if none use default)
 * @return - the r1cs file for the phrasedos circuit
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
 * @param r1cs - the r1cs of the phrasedos circuit
 * @param public_params - the public params to use to compute the proof
 * @param secret - the secret to prove knowledge of
 * @param usernames - the usernames to use in the chain of degrees of separation
 */
pub fn nova_proof(
    wc_path: Option<String>,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
    secret: &String,
    usernames: &Vec<String>,
) -> Result<NovaProof, std::io::Error> {
    // @TODO: make this friendly with portable paths by maybe include_str! or smth
    // Either get filepaths from option or use defaults
    let root = current_dir().unwrap();
    let wc_file = match wc_path {
        Some(path) => root.join(path),
        None => root.join(DEFAULT_WC_PATH),
    };

    // marshall private inputs into circom inputs
    let mut private_inputs = Vec::new();
    for i in 0..usernames.len() {
        // set input options
        let secret_input = match i {
            0 => Some(secret.clone()),
            _ => None,
        };
        let username_input = {
            let first_username = match i {
                0 => None,
                _ => Some(usernames[i - 1].clone()),
            };
            let second_username = Some(usernames[i].clone());
            [first_username, second_username]
        };

        // marshall inputs into the private inputs vector
        build_step_inputs(&mut private_inputs, secret_input, username_input);
    }

    // generate the a recursive Nova proof of the phrasedos circuit
    create_recursive_circuit(
        FileLocation::PathBuf(wc_file),
        r1cs.clone(),
        private_inputs,
        start_input().to_vec(),
        &public_params,
    )
}

/**
 * Verify the correct execution of a nova-folded proof of the phrasedos circuit
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
 * Prove another degree of separation using an existing proof from a phrasedos circuit
 *
 * @param usernames - the usernames to use in the chain of degrees of separation [prev username, current username]
 *   - todo: check size of usernames is 0
 * @param proof - the proof of degrees of separation to incrementally prove
 * @param previous_output - the output of the previous proof (z_last)
 * @param wc_path - the relative path to the witness calculator file (if none use default)
 * @param r1cs - the r1cs of the phrasedos circuit
 * @param public_params - the public params to use to compute the proof
 */
pub fn continue_nova_proof(
    usernames: &Vec<String>,
    proof: &mut NovaProof,
    previous_output: Vec<Fr>,
    wc_path: Option<String>,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
) -> Result<(), std::io::Error> {
    // get WC file location
    let root = current_dir().unwrap();
    let wc_file = match wc_path {
        Some(path) => root.join(path),
        None => root.join(DEFAULT_WC_PATH),
    };

    // compute the private inputs for this degree's compute/ chaff step
    let mut private_inputs = Vec::new();
    build_step_inputs(
        &mut private_inputs,
        None,
        [Some(usernames[0].clone()), Some(usernames[1].clone())],
    );

    // compute the next round of the proof
    continue_recursive_circuit(
        proof,
        previous_output,
        FileLocation::PathBuf(wc_file),
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
    use crate::utils::{json_to_obj, obj_to_json};

    #[test]
    fn test_degree_0() {
        // Test proving knowledge of a secret (1 degree of separation)
        let secret: String = String::from("There's no place like home");
        let usernames = vec!["mach34"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(Some(wc_path), &r1cs, &public_params, &secret, &usernames).unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_1() {
        // Test proving knowledge of a secret (1 degree of separation) and the second degree of separation
        let secret = String::from("hunter2");
        let usernames = vec!["mach34", "jp4g"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(Some(wc_path), &r1cs, &public_params, &secret, &usernames).unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_3() {
        // Test proving knowledge of a secret (1 degree of separation) and the second, third, and fourth degree of separation
        let secret = String::from(
            "Easier than folding a chair. like one of the folding ones at outdoor events.",
        );
        let usernames = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(Some(wc_path), &r1cs, &public_params, &secret, &usernames).unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();

        // todo: compute expected output
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_sequential_proving() {
        // define inputs
        let secret = String::from(
            "Easier than folding a chair. like one of the folding ones at outdoor events.",
        );
        let usernames = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        // define paths
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");

        // load public params and r1cs
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        // PROVE DEGREE 1 //
        let degree = 1;
        let mut proof = nova_proof(
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
            &secret,
            &vec![usernames[0].clone()],
        )
        .unwrap();

        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0; // step_out for the circuit execution
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // PROVE DEGREE 2 //
        let degree = 2;
        continue_nova_proof(
            &usernames[0..2].to_vec(),
            &mut proof,
            z0_last,
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
        ).unwrap();
        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0;
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // PROVE DEGREE 3 //
        let degree = 3;
        continue_nova_proof(
            &usernames[1..3].to_vec(),
            &mut proof,
            z0_last,
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
        ).unwrap();
        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0;
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // PROVE DEGREE 4 //
        let degree = 4;
        continue_nova_proof(
            &usernames[2..4].to_vec(),
            &mut proof,
            z0_last,
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
        ).unwrap();
        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0;
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    }

    #[test]
    fn test_continued_fs() {
        // test recursively proving degree 1 and 2 where proof 1 is saved to fs then read in for proof 2
        // define inputs
        let secret = String::from(
            "Filesystem filesystem system of a file",
        );
        let usernames = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        // define paths
        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");

        // load public params and r1cs
        let r1cs = get_r1cs(Some(r1cs_path));
        let public_params = get_public_params(Some(params_path));

        // PROVE DEGREE 1 //
        let degree = 1;
        let proof = nova_proof(
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
            &secret,
            &vec![usernames[0].clone()],
        )
        .unwrap();

        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0; // step_out for the circuit execution
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));

        // safe to fs
        let proof_path = std::env::current_dir()
            .unwrap()
            .join(format!("phrasedos_degree_{}.json", degree));
        obj_to_json(proof_path.clone(), proof);

        // PROVE DEGREE 2 //
        // read proof from fs
        let mut proof = json_to_obj::<NovaProof>(proof_path.clone());
        // get z0_last
        let z0_last = verify_nova_proof(&proof, &public_params, degree * 2).unwrap().0;
        // prove second degree
        let degree = 2;
        continue_nova_proof(
            &usernames[0..2].to_vec(),
            &mut proof,
            z0_last,
            Some(wc_path.clone()),
            &r1cs,
            &public_params,
        ).unwrap();
        let res = verify_nova_proof(&proof, &public_params, degree * 2).unwrap();
        let z0_last = res.0;
        assert!(z0_last[0].eq(&Fr::from(degree as u64)));
    }
}
