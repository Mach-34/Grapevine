use crate::account::GrapevineAccount;
use crate::errors::GrapevineCLIError;
use crate::utils::artifacts_guard;
use babyjubjub_rs::{decompress_point, PrivateKey};
// use grapevine_common::{Fr, NovaProof, G1, G2};
use grapevine_common::http::requests::CreateUserRequest;
use grapevine_common::utils::random_fr;
use grapevine_common::models::user::User;
use ff::PrimeField;
// use grapevine_circuits::{
//     nova::{continue_nova_proof, get_public_params, get_r1cs, nova_proof, verify_nova_proof},
// };
// use nova_scotia::{circom::reader::load_r1cs, create_public_params, FileLocation};
// use nova_snark::PublicParams;
// use rand::random;
// use std::env::current_dir;
use std::path::Path;

/**
 * Register a new user on Grapevine
 *
 * @param username - the username to register
 */
pub async fn register(username: String) -> Result<(), GrapevineCLIError> {
    // make account
    let account = make_or_get_account(username.clone())?;
    // sign the username
    let signature = account.sign_username();
    // encrypt auth secret with own pubkey for recovery
    let auth_secret_encrypted = account.encrypt_auth_secret(account.pubkey());
    // build request body
    let body = CreateUserRequest {
        username: username.clone(),
        pubkey: account.pubkey().compress(),
        auth_secret: auth_secret_encrypted,
        signature: signature.compress(),
    };
    // send create user request
    let url = format!("{}/user/create", crate::SERVER_URL);
    let client = reqwest::Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    // handle response from server
    match res.status() {
        reqwest::StatusCode::CREATED => {
            println!("Registered user {}", username);
            Ok(())
        }
        reqwest::StatusCode::BAD_REQUEST => {
            println!("Error: username {} already exists", username);
            Ok(())
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            Err(GrapevineCLIError::ServerError(text))
        }
    }
}

/**
 * Add a connection to another user by providing them your auth secret
 *
 * @param username - the username of the user to add a connection to
 */
pub async fn add_connection(username: String) -> Result<(), GrapevineCLIError> {
    // get own account
    let account = get_account()?;
    // download own auth secret
    // @todo: maybe custom route to get own auth secret and other's pubkey?
    let url = format!("{}/user/{}", crate::SERVER_URL, account.username());
    let data: User = reqwest::get(&url).await.unwrap().json::<User>().await.unwrap();
    let secret = account.decrypt_auth_secret(data.auth_secret);
    // // get connection's pubkey
    // let url = format!("{}/user/{}", crate::SERVER_URL, username);
    // let data: User = reqwest::get(&url).await.unwrap().json::<User>().await.unwrap();
    // let recipient = decompress_point(data.pubkey).unwrap();
    // let encrypted_auth_secret = account.encrypt_auth_secret(recipient);
    Ok(())
}

pub fn get_account_info() {
    // @TODO: pass info in
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

pub fn make_or_get_account(username: String) -> Result<GrapevineAccount, GrapevineCLIError> {
    // get grapevine path
    let grapevine_dir_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(e) => {
            return Err(GrapevineCLIError::FsError(String::from(
                "Couldn't find home directory??",
            )))
        }
    };
    // if ~/.grapevine doesn't exist, create it
    if !grapevine_dir_path.exists() {
        std::fs::create_dir(grapevine_dir_path.clone()).unwrap();
    };
    let grapevine_account_path = grapevine_dir_path.join("grapevine.key");
    // check if grapevine.key exists and pull
    let account = match grapevine_account_path.exists() {
        true => match GrapevineAccount::from_fs(grapevine_account_path) {
            Ok(account) => account,
            Err(e) => {
                return Err(GrapevineCLIError::FsError(String::from(
                    "Error reading existing Grapevine account from filesystem",
                )))
            }
        },
        false => {
            let account = GrapevineAccount::new(username);
            let json = serde_json::to_string(&account).unwrap();
            std::fs::write(&grapevine_account_path, json).unwrap();
            println!(
                "Created Grapevine account at {}",
                grapevine_account_path.display()
            );
            account
        }
    };
    get_account_info();
    Ok(account)
}

pub async fn health() -> Result<(), GrapevineCLIError> {
    // ensure artifacts exist
    artifacts_guard().await.unwrap();
    // get health status
    let text = reqwest::get("http://localhost:8000/health")
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("Health: {}", text);
    return Ok(());
}

/**
 * Attempts to get Grapevine account from fs and fails if it cannot
 *
 * @returns - the Grapevine account
 */
pub fn get_account() -> Result<GrapevineAccount, GrapevineCLIError> {
    // get grapevine path
    let grapevine_account_path = Path::new(&std::env::var("HOME").unwrap())
        .join(".grapevine")
        .join("grapevine.key");
    // if ~/.grapevine doesn't exist, create it
    match grapevine_account_path.exists() {
        true => match GrapevineAccount::from_fs(grapevine_account_path) {
            Ok(account) => Ok(account),
            Err(e) => Err(GrapevineCLIError::FsError(String::from(
                "Error reading existing Grapevine account from filesystem",
            ))),
        },
        false => {
            return Err(GrapevineCLIError::FsError(String::from(
                "No Grapevine account found",
            )));
        }
    }
}

pub fn make_or_get_key() -> Result<PrivateKey, std::env::VarError> {
    // check whether .grapevine exists
    let grapevine_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(e) => return Err(e),
    };
    // if does not exist, create the dir
    if !grapevine_path.exists() {
        println!("Creating .grapevine directory...");
        std::fs::create_dir(grapevine_path.clone()).unwrap();
    }
    // check if key exists
    let key_path = grapevine_path.join("grapevine.key");
    if !key_path.exists() {
        println!("Generating new key...");
        let key = random_fr();
        let key_bytes = key.to_bytes();
        std::fs::write(key_path.clone(), key_bytes).unwrap();
        println!("Saved key to {}", key_path.display());
    }
    // get key from fs
    let key_bytes = std::fs::read(key_path.clone()).unwrap();
    let key = PrivateKey::import(key_bytes).unwrap();
    return Ok(key);
}

// #[cfg(test)]
// mod test {

//     use super::*;

//     #[test]
//     fn test_wallet() {
//         let key = make_or_get_key().unwrap();
//         println!("Key: 0x{}", hex::encode(key.scalar_key().to_bytes_le().1));
//     }
// }
