use grapevine_common::{Fr, Params, G1, G2};
use nova_scotia::circom::circuit::R1CS;
use nova_scotia::circom::reader::load_r1cs;
use nova_scotia::FileLocation;
use std::env::{var, VarError};
use std::fs::write;
use std::path::{Path, PathBuf};
use lazy_static::lazy_static;
use crate::errors::GrapevineCLIError;
use crate::SERVER_URL;

lazy_static! {
    pub static ref ACCOUNT_PATH: PathBuf = get_account_path().unwrap();
}

/**
 * Gets the path to the grapevine account file
 *
 * @returns {PathBuf} path to the grapevine account file   
 */
pub fn get_account_path() -> Result<PathBuf, GrapevineCLIError> {
    // get grapevine path
    let grapevine_dir_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(e) => {
            return Err(GrapevineCLIError::FsError(String::from(
                "Couldn't find home directory??",
            )))
        }
    };
    Ok(grapevine_dir_path.join("grapevine.key"))
}

pub fn use_public_params() -> Result<Params, Box<dyn std::error::Error>> {
    // get the path to grapevine (will create if it does not exist)
    let filepath = get_storage_path().unwrap().join("public_params.json");
    // read in params file
    let public_params_file = std::fs::read_to_string(filepath).expect("Unable to read file");

    // parse file into params struct
    let public_params: Params =
        serde_json::from_str(&public_params_file).expect("Incorrect public params format");

    Ok(public_params)
}

pub fn use_r1cs() -> Result<R1CS<Fr>, Box<dyn std::error::Error>> {
    // get the path to grapevine (will create if it does not exist)
    let filepath = get_storage_path().unwrap().join("grapevine.r1cs");
    // read in params file
    Ok(load_r1cs::<G1, G2>(&FileLocation::PathBuf(filepath)))
}

pub fn use_wasm() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // get the path to grapevine (will create if it does not exist)
    Ok(get_storage_path().unwrap().join("grapevine.wasm"))
}

/**
 * Gets the path to the ~/.grapevine directory
 * If the directory does not exist, create it
 *
 * @returns {PathBuf} path to ~/.grapevine if successful
 */
pub fn get_storage_path() -> Result<PathBuf, VarError> {
    // check whether .grapevine exists
    let grapevine_path = match var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(e) => return Err(e),
    };
    // if does not exist, create the dir
    if !grapevine_path.exists() {
        println!("Creating .grapevine directory...");
        std::fs::create_dir(grapevine_path.clone()).unwrap();
    }
    Ok(grapevine_path)
}

/**
 * Checks whether r1cs, wasm, witcalc exist in ~/.grapevine
 *
 * @returns {bool} true if all artifacts exist, false otherwise
 */
pub fn check_artifacts_exist() -> bool {
    // get the path to grapevine (will create if it does not exist)
    let storage_dir = get_storage_path().unwrap();
    // specify artifact files to check
    let r1cs_path = storage_dir.join("grapevine.r1cs");
    let wasm_path = storage_dir.join("grapevine.wasm");
    let public_params_path = storage_dir.join("public_params.json");
    // check if all artifacts exist
    return r1cs_path.exists() && wasm_path.exists() && public_params_path.exists();
}

/**
 * Retrieves proving artifacts (r1cs, wasm witcalc, nova public params) and saves them to .grapevine
 *
 * @returns - result of whether or not artifacts were downloaded successfully
 */
pub async fn get_artifacts() -> Result<(), Box<dyn std::error::Error>> {
    let artifacts = ["grapevine.r1cs", "grapevine.wasm", "public_params.json"];
    for artifact in artifacts {
        println!("Downloading {}...", artifact);
        let path = get_storage_path().unwrap().join(artifact);
        let url = format!("{}/static/{}", SERVER_URL, artifact);
        download_file(url, path.clone()).await.unwrap();
        println!("Downloaded {} to {}", artifact, path.display());
    }
    Ok(())
}

/**
 * Downloads an arbitrary file from a URI and saves it to a specified path
 *
 * @param uri - URI of the file to download
 * @param path - path to save the file to
 * @returns - result of whether or not file downloaded successfully
 */
async fn download_file(uri: String, path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let data = reqwest::get(uri).await?.bytes().await?;
    write(path, data)?;
    Ok(())
}
