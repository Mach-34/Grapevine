use grapevine_common::Params;
use lazy_static::lazy_static;
use std::env::current_dir;

lazy_static! {
    pub static ref PUBLIC_PARAMS: Params = use_public_params().unwrap();
}

// @TODO: lazy static implementation for public params and r1cs

pub fn use_public_params() -> Result<Params, Box<dyn std::error::Error>> {
    // get the path to grapevine (will create if it does not exist)
    let filepath = current_dir().unwrap().join("static/public_params.json");
    println!("Filepath: {}", filepath.display());
    // read in params file
    let public_params_file = std::fs::read_to_string(filepath).expect("Unable to read file");

    // parse file into params struct
    let public_params: Params =
        serde_json::from_str(&public_params_file).expect("Incorrect public params format");

    Ok(public_params)
}
