use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};
use nova_snark::PublicParams;
use phrasedos_nova::{
    nova::{
        continue_nova_proof, get_public_params, get_r1cs, nova_proof,
        verify_nova_proof,
    },
    utils::{json_to_obj, obj_to_json},
    Fr, NovaProof, G1, G2,
};
use std::env::current_dir;
use std::time::Instant;

/**
 * Generate nova public parameters file and save to fs for reuse
 *
 * @param r1cs_path - relative path to the r1cs file to use to compute public params
 * @param output_path - relative path to save public params output json
 */
pub fn gen_params(r1cs_path: String, output_path: String) {
    // get file paths
    let root = current_dir().unwrap();
    let r1cs_file = root.join(r1cs_path);
    let output_file = root.join(output_path).join("public_params.json");
    println!("Phrasedos: Generate public parameters from R1CS");
    println!("Using R1CS file: {}", &r1cs_file.display());
    println!("Saving artifact to {}", &output_file.display());
    println!("Generating parameters (may take ~5 minutes)...");

    // start timer
    let start: Instant = Instant::now();

    // load r1cs from fs
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(r1cs_file));

    // compute public parameters
    let public_params: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    // log elapsed time to compute parameters
    println!(
        "Computation completed- took {:?}. Saving...",
        start.elapsed()
    );

    // save public params to fs
    let params_json = serde_json::to_string(&public_params).unwrap();
    std::fs::write(&output_file, &params_json).unwrap();

    // output completion message
    println!("Saved public parameters to {}", &output_file.display());
}

/**
 * Generate a new recursive nova proof of degree 1 that proves knowledge of a preimage and save to fs
 *
 * @param secret - the secret phrase to prove knowledge of
 * @param username - the username to associate with the secret at degree 1
 * @param out_dir - relative path to save proof output to
 * @param params_path - relative path to the public params file to use to compute proof
 * @param r1cs_path - relative path to the r1cs file to use to compute proof
 * @param wc_path - relative path to the witness generator file to use to compute proof
 */
pub fn degree_0_proof(
    secret: String,
    username: String,
    out_dir: String,
    params_path: String,
    r1cs_path: String,
    wc_path: String,
) {
    println!("Phrasedos: Generate new proof of knowledge of secret (separation degree 1)");
    println!("Username: {}", username);
    println!("Secret: {}", secret);
    println!("Proving...");
    // start timer
    let start: Instant = Instant::now();

    // load public params and r1cs
    let r1cs = get_r1cs(Some(r1cs_path));
    let public_params = get_public_params(Some(params_path));

    // prove compute and chaff step for degree 1
    let degrees = 1;
    let proof = nova_proof(
        Some(wc_path.clone()),
        &r1cs,
        &public_params,
        &secret,
        &vec![username],
    )
    .unwrap();

    // verify correct execution of folded proof
    let z0_last = verify_nova_proof(&proof, &public_params, degrees * 2)
        .unwrap()
        .0;
    let expected_outcome = z0_last[0].eq(&Fr::from(degrees as u64));
    match expected_outcome {
        true => (),
        false => panic!("Unexpected outcome"),
    }

    // save proof to fs
    let proof_path = std::env::current_dir()
        .unwrap()
        .join(out_dir)
        .join("phrasedos_degree_1.json");
    obj_to_json(proof_path.clone(), proof);

    println!(
        "Completed phrasedos proof with 1 degree of separation in {:?}",
        start.elapsed()
    );
    println!("Saved proof to {}", proof_path.display());
}

/**
 * Verify the authenticity of a proof stored on the filesystem
 *
 * @param degrees - the degrees of separation from secert asserted
 * @param proof_path - relative path to the proof file to verify
 * @param params_path - relative path to the public params file to use to verify proof
 */
pub fn verify_proof(degrees: usize, proof_path: String, params_path: String) {
    println!(
        "Phasedos: Verifying proof of {} degrees of separation...",
        degrees
    );
    // start timer
    let start: Instant = Instant::now();

    // load proof from filesystem
    let proof_file = std::env::current_dir().unwrap().join(proof_path);
    let proof = json_to_obj::<NovaProof>(proof_file.clone());

    // load public params from filesystem
    let public_params = get_public_params(Some(params_path));

    // verify integrity of proof
    let z0_last = verify_nova_proof(&proof, &public_params, degrees * 2)
        .unwrap()
        .0;
    let expected_outcome = z0_last[0].eq(&Fr::from(degrees as u64));
    match expected_outcome {
        true => (),
        false => panic!("Could not verify proof with given degrees"),
    }

    println!("Successfully verified proof of {} degree(s) of separation in {:?}", degrees, start.elapsed());
}

/**
 * Build on top of an existing proof of degrees of separation to prove a new degree of separation from a secret and save to fs
 *
 * @param degrees - the degrees of separation from secret asserted
 * @param previous_username - the username to assert one degree of separation from
 * @param username - the username given by the proof creator
 * @param proof_path - relative path to the proof file to recursively prove from
 * @param out_dir - relative path to save proof output to
 * @param params_path - relative path to the public params file to use to compute proof
 * @param r1cs_path - relative path to the r1cs file to use to compute proof
 * @param wc_path - relative path to the witness generator file to use to compute proof
 */
pub fn degree_n_proof(
    degrees: usize,
    previous_username: String,
    username: String,
    proof_path: String,
    out_dir: String,
    params_path: String,
    r1cs_path: String,
    wc_path: String,
) {
    println!(
        "Phrasedos: Generate new proof {} degrees of separation from a secret",
        degrees
    );
    println!(
        "Username to prove 1 degree of separation from: {}",
        previous_username
    );
    println!("Your username: {}", username);
    println!("Proving...");
    // start timer
    let start: Instant = Instant::now();

    // load public params and r1cs
    let r1cs = get_r1cs(Some(r1cs_path));
    let public_params = get_public_params(Some(params_path));

    // load proof from filesystem
    let proof_file = std::env::current_dir().unwrap().join(proof_path);
    let mut proof = json_to_obj::<NovaProof>(proof_file.clone());
    let z0_last = verify_nova_proof(&proof, &public_params, (degrees - 1) * 2)
        .unwrap()
        .0;

    // prove compute and chaff step for degree N > 1
    continue_nova_proof(
        &vec![previous_username, username],
        &mut proof,
        z0_last,
        Some(wc_path),
        &r1cs.clone(),
        &public_params,
    )
    .unwrap();

    // verify correct execution
    let z0_last = verify_nova_proof(&proof, &public_params, degrees * 2)
        .unwrap()
        .0;
    let expected_outcome = z0_last[0].eq(&Fr::from(degrees as u64));
    match expected_outcome {
        true => (),
        false => panic!("Could not compute proof with given degrees"),
    }

    // save new proof to fs
    // safe to fs
    let new_proof_path = std::env::current_dir()
        .unwrap()
        .join(out_dir)
        .join(format!("phrasedos_degree_{}.json", degrees));
    obj_to_json(new_proof_path.clone(), proof);

    println!(
        "Completed phrasedos proof with {} degree of separation in {:?}",
        degrees,
        start.elapsed()
    );
    println!("Saved proof to {}", new_proof_path.display());
}
