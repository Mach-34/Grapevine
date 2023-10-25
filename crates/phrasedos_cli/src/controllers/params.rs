use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation, F};
use nova_snark::{provider, PublicParams};
use std::env::current_dir;
use std::time::Instant;

pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F<G1>;

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
    let start = Instant::now();

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
