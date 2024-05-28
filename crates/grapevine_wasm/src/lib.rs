use grapevine_common::{G1, G2, Fr, Fq, Params, NovaProof, utils::random_fr};
pub mod utils;
pub use wasm_bindgen_rayon::init_thread_pool;
#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);

    pub type Performance;

    pub static performance: Performance;

    #[wasm_bindgen(method)]
    pub fn now(this: &Performance) -> f64;
}

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => ($crate::log(&format_args!($($t)*).to_string()))
}

// extern crate console_error_panic_hook;
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn retrieve_params_string() -> Params {

}

/**
 * Create a nova proof for N degrees of separation, where N is the length of the usernames vector - 1
 * @notice - proving knowledge of preimage is degree 0 hence 1 username means N = 0
 *
 * @param wc_path - the relative path to the witness generator file to use to compute public params (if none use default)
 * @param r1cs - the r1cs of the grapevine circuit
 * @param public_params - the public params to use to compute the proof
 * @param phrase - the secret phrase to prove knowledge of
 * @param usernames - the usernames to use in the chain of degrees of separation
 * @param auth_secrets - the auth secrets to use to make it impossible to prove degree of separation without previous user giving the secret
 */
pub fn nova_proof(
    wc_path: PathBuf,
    r1cs: &R1CS<Fr>,
    public_params: &Params,
    phrase: &String,
    usernames: &Vec<String>,
    auth_secrets: &Vec<Fr>,
) -> Result<NovaProof, std::io::Error> {
    // marshall private inputs into circom inputs
    let mut private_inputs = Vec::new();
    for i in 0..usernames.len() {
        // set input options
        let phrase_input = match i {
            0 => Some(phrase.clone()),
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
        let auth_secret_input = {
            let first_auth_secret = match i {
                0 => None,
                _ => Some(auth_secrets[i - 1]),
            };
            let second_auth_secret = Some(auth_secrets[i]);
            [first_auth_secret, second_auth_secret]
        };

        // marshall inputs into the private inputs vector
        build_step_inputs(
            &mut private_inputs,
            phrase_input,
            username_input,
            auth_secret_input,
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
    usernames: &Vec<String>,
    auth_secrets: &Vec<Fr>,
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
        [Some(usernames[0].clone()), Some(usernames[1].clone())],
        [Some(auth_secrets[0]), Some(auth_secrets[1])],
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