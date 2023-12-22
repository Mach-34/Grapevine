use crate::account::GrapevineAccount;
use babyjubjub_rs::PrivateKey;
use grapevine_circuits::{
    nova::{continue_nova_proof, get_public_params, get_r1cs, nova_proof, verify_nova_proof},
    utils::{json_to_obj, obj_to_json, random_fr},
    Fr, NovaProof, G1, G2,
};
use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};
use nova_snark::PublicParams;
use rand::random;
use std::env::current_dir;
use std::path::Path;
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
    println!("Grapevine: Generate public parameters from R1CS");
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

pub fn get_account_info() {
    // get grapevine path
    let grapevine_dir_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(_) => {
            println!("Error: no home directory found");
            return;
        }
    };
    let grapevine_key_path = grapevine_dir_path.join("grapevine.key");
    match grapevine_key_path.exists() {
        true => (),
        false => {
            println!(
                "No Grapevine account found at {}",
                grapevine_key_path.display()
            );
            return;
        }
    };
    // read from the saved account file
    let json = std::fs::read_to_string(grapevine_key_path).unwrap();
    let account = serde_json::from_str::<GrapevineAccount>(&json).unwrap();
    println!("Username: {}", account.username());
    println!("Private Key: 0x{}", hex::encode(account.private_key_raw()));
    println!(
        "Auth Secret: 0x{}",
        hex::encode(account.auth_secret().to_bytes())
    );
}

pub fn make_account(username: String) {
    // get grapevine path
    let grapevine_dir_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(e) => {
            println!("Error: no home directory found");
            return;
        }
    };
    let grapevine_key_path = grapevine_dir_path.join("grapevine.key");
    // check if grapevine.key exists
    match grapevine_key_path.exists() {
        true => {
            println!(
                "Error: Grapevine account already exists at {}",
                &grapevine_key_path.display()
            );
            return;
        }
        false => (),
    };
    // create account
    let account = GrapevineAccount::new(username);
    // save account to fs
    let json = serde_json::to_string(&account).unwrap();
    std::fs::create_dir(grapevine_dir_path.clone()).unwrap();
    std::fs::write(&grapevine_key_path, json).unwrap();
    println!(
        "Created Grapevine account at {}",
        grapevine_key_path.display()
    );
    get_account_info();
}

pub async fn health() {
    let text = reqwest::get("http://localhost:8000/health")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("Health: {}", text);
}

// pub fn make_or_get_key() -> Result<Account, std::env::VarError> {
//     // check whether .grapevine exists
//     let grapevine_path = match std::env::var("HOME") {
//         Ok(home) => Path::new(&home).join(".grapevine"),
//         Err(e) => return Err(e),
//     };
//     // if does not exist, create the dir
//     if !grapevine_path.exists() {
//         println!("Creating .grapevine directory...");
//         std::fs::create_dir(grapevine_path.clone()).unwrap();
//     }
//     // check if key exists
//     let key_path = grapevine_path.join("grapevine.key");
//     if !key_path.exists() {
//         println!("Generating new key...");
//         let key = random_fr();
//         let key_bytes = key.to_bytes();
//         std::fs::write(key_path.clone(), key_bytes).unwrap();
//         println!("Saved key to {}", key_path.display());
//     }
//     // get key from fs
//     let key_bytes = std::fs::read(key_path.clone()).unwrap();
//     let key = PrivateKey::import(key_bytes).unwrap();
//     return Ok(key);
// }

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_wallet() {
        let key = make_or_get_key().unwrap();
        println!("Key: 0x{}", hex::encode(key.scalar_key().to_bytes_le().1));
    }
}
