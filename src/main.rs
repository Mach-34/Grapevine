mod util;

use nova_scotia::{
    circom::reader::load_r1cs,
    create_public_params,
    create_recursive_circuit,
    // continue_recursive_circuit,
    FileLocation,
    F,
    S,
};
use nova_snark::{provider, CompressedSNARK, PublicParams};
use serde_json::json;
use std::{collections::HashMap, env::current_dir, time::Instant};

pub type G1 = provider::bn256_grumpkin::bn256::Point;
pub type G2 = provider::bn256_grumpkin::grumpkin::Point;
pub type Fr = F::<G1>;

pub fn driver(
    circuit_filepath: String,
    wc_filepath: String,
    phrase: String,
    usernames: Vec<String>,
) {
    println!(
        "Running test with witness generator: {} and group: {}",
        wc_filepath,
        std::any::type_name::<G1>()
    );

    // convert phrase to felts
    let phrase_felts = util::convert_phrase_to_felts(phrase).unwrap();
    let usernames_felts = usernames
        .iter()
        .map(|u| util::convert_username_to_felt(u.clone()).unwrap())
        .collect::<Vec<String>>();

    // // get filepaths
    let root = current_dir().unwrap();
    let circuit_file = root.join(circuit_filepath);
    let wc_file = root.join(wc_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));

    println!("loaded r1cs");

    let mut private_inputs = Vec::new();
    // push first proof
    let mut private_input = HashMap::new();
    private_input.insert("secret".to_string(), json!(phrase_felts));
    private_input.insert("usernames".to_string(), json!([util::ZERO, usernames_felts[0]]));

    private_inputs.push(private_input);
    // push second proof inputs
    private_input = HashMap::new();
    private_input.insert("secret".to_string(), json!(util::EMPTY_SECRET));
    private_input.insert("usernames".to_string(), json!([util::ZERO, util::ZERO]));
    private_inputs.push(private_input);


    println!("created private inputs");

    let start_public_input = [F::<G1>::from(0); 4];
    println!("Start public input: {:#?}", start_public_input);
    let p_start = Instant::now();

    let public_params: PublicParams<G1, G2, _, _> = util::read_pp_file(
        "circuits/artifacts/public_params.json"
    );

    // let public_params: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());
    // println!("Public Params creation took {:?}", p_start.elapsed());
    // util::write_pp_file("circuits/artifacts/public_params.json", &public_params);

    println!("Public Params creation took {:?}", p_start.elapsed());

    println!(
        "Number of constraints per step (primary circuit): {}",
        public_params.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        public_params.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        public_params.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        public_params.num_variables().1
    );

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let mut recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(wc_file.clone()),
        r1cs.clone(),
        private_inputs,
        start_public_input.to_vec(),
        &public_params,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    let z0_secondary = [F::<G2>::from(0)];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&public_params, 2, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    let z_last = res.unwrap().0;

    println!("z_last: {:?}", z_last);

    // // assert_eq!(z_last[0], F::<G1>::from(20));
    // // assert_eq!(z_last[1], F::<G1>::from(70));
}

pub fn main() {
    let phrase = String::from("There's no place like home");
    let usernames = vec!["mach34", "jp4g", "ianb", "ct"]
        .iter()
        .map(|s| String::from(*s))
        .collect::<Vec<String>>();
    let circuit_filepath = String::from("circuits/artifacts/folded.r1cs");
    let wc_filepath = String::from("circuits/artifacts/folded_js/folded.wasm");
    // prove and verify folded circuit
    driver(
        circuit_filepath.clone(),
        wc_filepath.clone(),
        phrase.clone(),
        usernames.clone(),
    );
}
