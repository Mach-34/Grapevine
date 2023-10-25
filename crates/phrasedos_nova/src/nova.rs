use super::{
    start_input,
    utils::{build_step_inputs, read_public_params},
    z0_secondary, Fq, Fr, NovaProof, Params, DEFAULT_PUBLIC_PARAMS_PATH, DEFAULT_R1CS_PATH,
    DEFAULT_WC_PATH, G1, G2,
};
use nova_scotia::{circom::reader::load_r1cs, create_recursive_circuit, FileLocation, S};
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
 * Create a nova proof for N degrees of separation, where N is the length of the usernames vector - 1
 * @notice - proving knowledge of preimage is degree 0 hence 1 username means N = 0
 *
 * @param r1cs_path - the relative path to the r1cs file to use to compute public params (if none use default)
 * @param wc_path - the relative path to the witness generator file to use to compute public params (if none use default)
 * @param public_params - the public params to use to compute the proof
 * @param secret - the secret to prove knowledge of
 * @param usernames - the usernames to use in the chain of degrees of separation
 */
pub fn nova_proof(
    r1cs_path: Option<String>,
    wc_path: Option<String>,
    public_params: &Params,
    secret: &String,
    usernames: &Vec<String>,
) -> Result<NovaProof, std::io::Error> {
    // @TODO: make this friendly with portable paths by maybe include_str! or smth
    // Either get filepaths from option or use defaults
    let root = current_dir().unwrap();
    let r1cs_file = match r1cs_path {
        Some(path) => root.join(path),
        None => root.join(DEFAULT_R1CS_PATH),
    };
    let wc_file = match wc_path {
        Some(path) => root.join(path),
        None => root.join(DEFAULT_WC_PATH),
    };

    // load R1CS from FS
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

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

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_degree_0() {
        let secret = String::from("There's no place like home");
        let usernames = vec!["mach34"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            Some(r1cs_path),
            Some(wc_path),
            &public_params,
            &secret,
            &usernames,
        )
        .unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_1() {
        let secret = String::from("hunter2");
        let usernames = vec!["mach34", "jp4g"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            Some(r1cs_path),
            Some(wc_path),
            &public_params,
            &secret,
            &usernames,
        )
        .unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }

    #[test]
    fn test_degree_3() {
        let secret = String::from("Zero Knowledge Zero College");
        let usernames = vec!["mach34", "jp4g", "ianb", "ct"]
            .iter()
            .map(|s| String::from(*s))
            .collect::<Vec<String>>();

        let params_path = String::from("circom/artifacts/public_params.json");
        let r1cs_path = String::from("circom/artifacts/folded.r1cs");
        let wc_path = String::from("circom/artifacts/folded_js/folded.wasm");
        let public_params = get_public_params(Some(params_path));

        let proof = nova_proof(
            Some(r1cs_path),
            Some(wc_path),
            &public_params,
            &secret,
            &usernames,
        )
        .unwrap();

        let iterations = usernames.len() * 2;
        let verified = verify_nova_proof(&proof, &public_params, iterations).unwrap();
        println!("Verified: {:?}", verified);
    }
}

//vec!["mach34", "jp4g", "ianb", "ct"]