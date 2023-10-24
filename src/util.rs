use nova_snark::{provider, CompressedSNARK, PublicParams};
use std::env::current_dir;
pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::bn256::Point;

/**
 * Load the artifacts for the circuit and witness calculator
 * 
 * @param circuit_filepath - the path to the circuit directory
 * @param wc_filepath - the path to the witness calculator directory
 * 
 * @return
 *  - 
 */
pub fn load_artifacts(circuit_filepath: String, wc_filepath: String) {
    println!(
        "Running test with witness generator: {} and group: {}",
        wc_filepath,
        std::any::type_name::<G1>()
    );
    // get filepaths
    let root = current_dir().unwrap();
    let circuit_file = root.join(circuit_filepath);
    let wc_file = root.join(wc_filepath);

    // load r1cs
}