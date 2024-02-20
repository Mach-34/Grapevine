use crate::errors::GrapevineCLIError;
use crate::utils::artifacts_guard;
use crate::utils::fs::{use_public_params, use_r1cs, use_wasm};
use babyjubjub_rs::{decompress_point, PrivateKey};
use grapevine_circuits::nova::{continue_nova_proof, nova_proof, verify_nova_proof};
use grapevine_circuits::utils::{compress_proof, decompress_proof};
use grapevine_common::account::GrapevineAccount;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::http::requests::{
    CreateUserRequest, DegreeProofRequest, NewPhraseRequest, NewRelationshipRequest,
    TestProofCompressionRequest,
};
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::proof::ProvingData;
use grapevine_common::utils::random_fr;

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
    // build request body
    let body = account.create_user_request();
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
pub async fn add_relationship(username: String) -> Result<(), GrapevineCLIError> {
    // get own account
    let account = get_account()?;
    // get pubkey for recipient
    let url = format!("{}/user/{}/pubkey", crate::SERVER_URL, username);
    let pubkey = match reqwest::get(&url).await.unwrap().text().await {
        Ok(pubkey) => decompress_point(hex::decode(pubkey).unwrap().try_into().unwrap()).unwrap(),
        Err(e) => {
            return Err(GrapevineCLIError::ServerError(format!(
                "Couldn't get pubkey for user {}",
                username
            )))
        }
    };
    // encrypt auth secret with recipient's pubkey
    let encrypted_auth_secret = account.encrypt_auth_secret(pubkey);
    // build relationship request body
    let body = NewRelationshipRequest {
        // from: account.username().clone(),
        to: username.clone(),
        ephemeral_key: encrypted_auth_secret.ephemeral_key,
        ciphertext: encrypted_auth_secret.ciphertext,
    };
    // send request
    let url = format!("{}/user/relationship", crate::SERVER_URL);
    let client = reqwest::Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    // handle response from server
    match res.status() {
        reqwest::StatusCode::CREATED => {
            println!("Added relationship with {}", username);
            Ok(())
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            Err(GrapevineCLIError::ServerError(text))
        }
    }
}

pub async fn create_new_phrase(phrase: String) -> Result<(), GrapevineCLIError> {
    // ensure artifacts are present
    artifacts_guard().await.unwrap();
    // get account
    let account = get_account()?;
    // get proving artifacts
    let params = use_public_params().unwrap();
    let r1cs = use_r1cs().unwrap();
    let wc_path = use_wasm().unwrap();
    // check phrase length
    if phrase.len() > 180 {
        return Err(GrapevineCLIError::PhraseTooLong);
    }
    // @todo: check if phrase is ascii
    // get proof inputs
    let username = vec![account.username().clone()];
    let auth_secret = vec![account.auth_secret().clone()];
    // create proof
    // println!("Auth Secret: {:?}", auth_secret_input[0].to_bytes);
    let res = nova_proof(wc_path, &r1cs, &params, &phrase, &username, &auth_secret);
    let proof = match res {
        Ok(proof) => proof,
        Err(e) => {
            return Err(GrapevineCLIError::PhraseCreationProofFailed(phrase));
        }
    };
    // verify the correctness of the folding proof DO THIS ON SERVER SIDE
    // let res = verify_nova_proof(&proof, &params, 2);
    // let (phrase_hash, auth_has) = match res {
    //     Ok(data) => {
    //         let phrase_hash = data.0[1].to_bytes();
    //         let auth_hash = data.0[2].to_bytes();
    //         (phrase_hash, auth_hash)
    //     },
    //     Err(e) => {
    //         println!("Verification Failed");
    //         return Err(GrapevineCLIError::PhraseCreationProofFailed(phrase));
    //     }
    // };
    // println!("Phrase hash: {:?}", phrase_hash);
    // println!("Auth hash: {:?}", auth_has);
    // compress the proof
    let compressed = compress_proof(&proof);

    // build request body
    let body = NewPhraseRequest {
        proof: compressed,
        // username: account.username().clone(),
    };
    let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

    // send request
    let url = format!("{}/phrase/create", crate::SERVER_URL);
    let client = reqwest::Client::new();
    let res = client.post(&url).body(serialized).send().await.unwrap();
    // handle response from server
    match res.status() {
        reqwest::StatusCode::CREATED => {
            println!("Created new phrase");
            Ok(())
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            Err(GrapevineCLIError::ServerError(text))
        }
    }
}

// DEV: Remove later

pub async fn prove_separation_degree(oid: String) -> Result<(), GrapevineCLIError> {
    // ensure proving artifacts are downloaded
    artifacts_guard().await.unwrap();
    let public_params = use_public_params().unwrap();
    let r1cs = use_r1cs().unwrap();
    let wc_path = use_wasm().unwrap();
    // get account
    let account = get_account()?;
    // get proof and encrypted auth secret
    let url = format!(
        "{}/proof/{}/params/{}",
        crate::SERVER_URL,
        oid,
        account.username()
    );
    let res = reqwest::get(&url).await.unwrap();
    let proving_data = match res.status() {
        reqwest::StatusCode::OK => {
            let proving_data = res.json::<ProvingData>().await.unwrap();
            proving_data
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            return Err(GrapevineCLIError::ServerError(text));
        }
    };
    // decrypt auth secret
    let auth_secret_encrypted = AuthSecretEncrypted {
        ephemeral_key: proving_data.ephemeral_key,
        ciphertext: proving_data.ciphertext,
        username: proving_data.username,
        recipient: account.pubkey().compress(),
    };
    let auth_secret = account.decrypt_auth_secret(auth_secret_encrypted);
    // decompress proof
    let mut proof = decompress_proof(&proving_data.proof);
    // verify proof
    let res = verify_nova_proof(&proof, &public_params, (proving_data.degree * 2) as usize);
    let previous_output = match res {
        Ok(data) => data.0,
        Err(e) => {
            println!("Verification Failed");
            return Err(GrapevineCLIError::DegreeProofVerificationFailed);
        }
    };
    // build nova proof
    let username_input = vec![auth_secret.username, account.username().clone()];
    let auth_secret_input = vec![auth_secret.auth_secret, account.auth_secret().clone()];
    match continue_nova_proof(
        &username_input,
        &auth_secret_input,
        &mut proof,
        previous_output,
        wc_path,
        &r1cs,
        &public_params,
    ) {
        Ok(_) => (),
        Err(e) => {
            println!("Proof continuation failed");
            return Err(GrapevineCLIError::DegreeProofVerificationFailed);
        }
    };

    // compress the proof
    let compressed = compress_proof(&proof);

    // build request body
    let body = DegreeProofRequest {
        proof: compressed,
        // username: account.username().clone(),
        previous: oid,
        degree: proving_data.degree + 1,
    };
    let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    let url = format!("{}/phrase/continue", crate::SERVER_URL);
    let client = reqwest::Client::new();
    let res = client.post(&url).body(serialized).send().await.unwrap();
    // // handle response from server
    match res.status() {
        reqwest::StatusCode::CREATED => {
            println!("Created new phrase");
            Ok(())
        }
        _ => {
            let text = res.status().to_string();
            println!("Error: {}", text);
            Err(GrapevineCLIError::ServerError(text))
        }
    }
}

pub async fn prove_all_available() -> Result<(), GrapevineCLIError> {
    // get account
    let account = get_account()?;
    // get available proofs
    let url = format!(
        "{}/proof/{}/available",
        crate::SERVER_URL,
        account.username()
    );
    let res = reqwest::get(&url)
        .await
        .unwrap()
        .json::<Vec<String>>()
        .await
        .unwrap();
    // prove each available proof
    println!("Found {} available proofs", res.len());
    for oid in res {
        println!("Proving {}", oid);
        prove_separation_degree(oid).await.unwrap();
    }
    println!("Finished updating available proofs");
    Ok(())
}

pub async fn get_available_proofs() -> Result<(), GrapevineCLIError> {
    // get account
    let account = get_account()?;
    // send request
    println!("Attempting to get proofs");
    let url = format!(
        "{}/proof/{}/available",
        crate::SERVER_URL,
        account.username()
    );
    let res = reqwest::get(&url)
        .await
        .unwrap()
        .json::<Vec<String>>()
        .await;
    // handle result
    match res {
        Ok(proofs) => {
            println!("Available proofs: {:#?}", proofs);
            Ok(())
        }
        Err(e) => {
            println!("Failed to get proofs");
            return Err(GrapevineCLIError::ServerError(String::from(
                "Couldn't get available proofs",
            )));
        }
    }
}

pub async fn get_my_proofs() -> Result<(), GrapevineCLIError> {
    // get account
    let account = get_account()?;
    // send request
    let url = format!("{}/user/{}/degrees", crate::SERVER_URL, account.username());
    let res = reqwest::get(&url)
        .await
        .unwrap()
        .json::<Vec<DegreeData>>()
        .await;
    // handle result
    let degree_data = match res {
        Ok(proofs) => proofs,
        Err(e) => {
            println!("Failed to get proofs");
            return Err(GrapevineCLIError::ServerError(String::from(
                "Couldn't get available proofs",
            )));
        }
    };
    println!(
        "Proofs of {}'s degrees of separation from phrases/ users:",
        account.username()
    );
    for degree in degree_data {
        println!("=-=-=-=-=-=-=-=-=-=-=-=-=");
        println!("Phrase hash: 0x{}", hex::encode(degree.phrase_hash));
        if degree.relation.is_none() {
            println!("Phrase created by this user");
        } else {
            println!("Degrees of separation from origin: {}", degree.degree);
            println!("Your relation: {}", degree.relation.unwrap());
        }
    }
    println!("=-=-=-=-=-=-=-=-=-=-=-=-=");

    Ok(())
}

pub fn account_details() -> Result<(), GrapevineCLIError> {
    // get account
    let account = get_account().unwrap();
    let auth_secret = hex::encode(account.auth_secret().to_bytes());
    let pk = hex::encode(account.private_key_raw());
    let pubkey = hex::encode(account.pubkey().compress());
    println!("Username: {}", account.username());
    println!("Auth Secret: {}", auth_secret);
    println!("Private Key: {}", pk);
    println!("Pubkey: {}", pubkey);
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
    let text = reqwest::get("http://localhost:8000/test/health")
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


// #[cfg(test)]
// mod test {

//     use super::*;

//     #[test]
//     fn test_wallet() {
//         let key = make_or_get_key().unwrap();
//         println!("Key: 0x{}", hex::encode(key.scalar_key().to_bytes_le().1));
//     }
// }
