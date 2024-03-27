use crate::errors::GrapevineCLIError;
use crate::http::{
    add_relationship_req, create_user_req, degree_proof_req, get_account_details_req,
    get_available_proofs_req, get_degrees_req, get_known_req, get_nonce_req, get_phrase_req,
    get_proof_with_params_req, get_pubkey_req, phrase_req, show_connections_req,
};
use crate::utils::artifacts_guard;
use crate::utils::fs::{use_public_params, use_r1cs, use_wasm, ACCOUNT_PATH};
use babyjubjub_rs::{decompress_point, PrivateKey};
use grapevine_circuits::nova::{continue_nova_proof, nova_proof, verify_nova_proof};
use grapevine_circuits::utils::{compress_proof, decompress_proof};
use grapevine_common::account::GrapevineAccount;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::compat::{convert_ff_to_ff_ce, ff_ce_from_le_bytes};
use grapevine_common::crypto::phrase_hash;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::{
    CreateUserRequest, DegreeProofRequest, NewRelationshipRequest, PhraseRequest,
    TestProofCompressionRequest,
};
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::ProvingData;
use grapevine_common::utils::{convert_phrase_to_fr, random_fr};

use std::path::Path;

/**
 * Get the details of the current account
 */
pub async fn account_details() -> Result<String, GrapevineCLIError> {
    // get account
    let mut account = match get_account() {
        Ok(account) => account,
        Err(e) => return Err(e),
    };
    // sync nonce
    synchronize_nonce().await?;
    let auth_secret = hex::encode(account.auth_secret().to_bytes());
    let pk = hex::encode(account.private_key_raw());
    let pubkey = hex::encode(account.pubkey().compress());

    // Fetch account stats
    let res = get_account_details_req(&mut account).await;

    match res {
        Ok(_) => {
            let details = res.unwrap();
            Ok(format!(
                "Username: {}\nAuth secret: 0x{}\nPrivate key: 0x{}\nPublic key: 0x{}\n# 1st degree connections: {}\n# 2nd degree connections: {}\n# phrases created: {}",
                account.username(),
                auth_secret,
                pk,
                pubkey,
                details.1,
                details.2,
                details.0
            ))
        }
        Err(e) => Err(GrapevineCLIError::from(e)),
    }
}

/**
 * Register a new user on Grapevine
 *
 * @param username - the username to register
 */
pub async fn register(username: Option<String>) -> Result<String, GrapevineCLIError> {
    // check that username is provided
    let username = match username {
        Some(username) => username,
        None => return Err(GrapevineCLIError::NoInput(String::from("username"))),
    };
    // check username is < 30 chars
    if username.len() > 30 {
        return Err(GrapevineCLIError::UsernameTooLong(username));
    }
    // check username is ascii
    if !username.is_ascii() {
        return Err(GrapevineCLIError::UsernameNotAscii(username));
    }
    // make account (or retrieve from fs)
    let account = make_or_get_account(username.clone())?;
    // build request body
    let body = account.create_user_request();
    // send create user request
    let res = create_user_req(body).await;
    match res {
        Ok(_) => Ok(format!("Success: registered account for \"{}\"", username)),
        Err(e) => Err(GrapevineCLIError::from(e)),
    }
}

/**
 * Add a connection to another user by providing them your auth secret
 *
 * @param username - the username of the user to add a connection to
 */
pub async fn add_relationship(username: String) -> Result<String, GrapevineCLIError> {
    // get own account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // get pubkey for recipient
    let pubkey = match get_pubkey_req(username.clone()).await {
        Ok(pubkey) => pubkey,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };
    // build relationship request body with encrypted auth secret payload
    let body = account.new_relationship_request(&username, &pubkey);
    // send add relationship request
    let res = add_relationship_req(&mut account, body).await;
    match res {
        Ok(_) => Ok(format!(
            "Success: added this account as a relationship for \"{}\"",
            &username
        )),
        Err(e) => Err(GrapevineCLIError::from(e)),
    }
}

/**
 * Retrieve the current nonce for the account and synchronize it with the locally stored account
 */
pub async fn synchronize_nonce() -> Result<String, GrapevineCLIError> {
    // get the account
    let mut account = get_account()?;
    // build nonce request body
    let body = account.get_nonce_request();
    // send nonce request
    let res = get_nonce_req(body).await;
    let expected_nonce = match res {
        Ok(nonce) => nonce,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };
    match expected_nonce == account.nonce() {
        true => Ok(format!(
            "Nonce is already synchronized at \"{}\"",
            expected_nonce
        )),
        false => {
            let msg = format!(
                "Local nonce of \"{}\" synchronized to \"{}\" from server",
                account.nonce(),
                expected_nonce
            );
            account
                .set_nonce(expected_nonce, Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            Ok(msg)
        }
    }
}

/**
 * Create a new phrase and proves knowledge of it
 * @notice if phrase does not exists, creates new phrase. Otherwise, proves knowledge of existing phrase
 *
 * @param phrase - the phrase to create
 * @param description - the description of the phrase (discarded if phrase exists)
 */
pub async fn prove_phrase(
    phrase: String,
    description: String,
) -> Result<String, GrapevineCLIError> {
    // ensure artifacts are present
    artifacts_guard().await.unwrap();
    let params = use_public_params().unwrap();
    let r1cs = use_r1cs().unwrap();
    let wc_path = use_wasm().unwrap();
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;

    // check that phrase is > 180 chars
    if phrase.len() > 180 {
        return Err(GrapevineCLIError::PhraseTooLong);
    }

    // prove phrase
    let username = vec![account.username().clone()];
    let auth_secret = vec![account.auth_secret().clone()];
    let proof = nova_proof(wc_path, &r1cs, &params, &phrase, &username, &auth_secret).unwrap();

    // compress proof
    let compressed = compress_proof(&proof);
    // encrypt phrase
    let ciphertext = account.encrypt_phrase(&phrase);

    // build request body
    let body = PhraseRequest {
        proof: compressed,
        ciphertext,
        description: description.clone(),
    };
    // send request
    let res = phrase_req(&mut account, body).await;
    match res {
        Ok(data) => match data.new_phrase {
            true => Ok(format!(
                "Success: Created and proved knowledge of new phrase #{}: \"{}\"",
                data.phrase_index, phrase
            )),
            false => Ok(format!(
                "Success: Proved knowledge of existing phrase #{}: \"{}\"",
                data.phrase_index, phrase
            )),
        },
        Err(e) => Err(GrapevineCLIError::from(e)),
    }
}

pub async fn prove_all_available() -> Result<String, GrapevineCLIError> {
    /// GETTING
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // get available proofs
    let res = get_available_proofs_req(&mut account).await;
    // handle result
    let proofs = match res {
        Ok(proofs) => proofs,
        Err(e) => {
            println!("Failed to get available proofs");
            return Err(GrapevineCLIError::ServerError(String::from(
                "Couldn't get available proofs",
            )));
        }
    };
    match proofs.len() {
        0 => {
            println!();
            return Ok(format!(
                "No new degree proofs found for user \"{}\"",
                account.username()
            ));
        }
        _ => (),
    }
    /// PROVING
    // ensure proving artifacts are downloaded
    artifacts_guard().await.unwrap();
    let public_params = use_public_params().unwrap();
    let r1cs = use_r1cs().unwrap();
    let wc_path = use_wasm().unwrap();
    for i in 0..proofs.len() {
        let oid = proofs[i].clone();
        println!("Proving #{}: {}", i, oid);
        // get proof and encrypted auth secret
        let res = get_proof_with_params_req(&mut account, oid.clone()).await;
        let proving_data = match res {
            Ok(proving_data) => proving_data,
            Err(e) => return Err(GrapevineCLIError::from(e)),
        };
        // prepare inputs
        let auth_secret_encrypted = AuthSecretEncrypted {
            ephemeral_key: proving_data.ephemeral_key,
            ciphertext: proving_data.ciphertext,
            username: proving_data.username,
            recipient: account.pubkey().compress(),
        };
        let auth_secret = account.decrypt_auth_secret(auth_secret_encrypted);
        let mut proof = decompress_proof(&proving_data.proof);
        let verified =
            verify_nova_proof(&proof, &public_params, (proving_data.degree * 2) as usize);
        let previous_output = match verified {
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
            wc_path.clone(),
            &r1cs,
            &public_params,
        ) {
            Ok(_) => (),
            Err(_) => {
                println!("Proof continuation failed");
                return Err(GrapevineCLIError::DegreeProofVerificationFailed);
            }
        }
        let compressed = compress_proof(&proof);
        // build request body
        let body = DegreeProofRequest {
            proof: compressed,
            // username: account.username().clone(),
            previous: oid,
            degree: proving_data.degree + 1,
        };
        // handle response from server
        let res: Result<(), GrapevineServerError> = degree_proof_req(&mut account, body).await;
        match res {
            Ok(_) => (),
            Err(e) => return Err(GrapevineCLIError::from(e)),
        }
    }
    Ok(format!(
        "Success: proved {} new degree proofs",
        proofs.len()
    ))
}

pub async fn get_my_proofs() -> Result<String, GrapevineCLIError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let res = get_degrees_req(&mut account).await;
    let data = match res {
        Ok(data) => data,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };
    println!(
        "Proofs of {}'s degrees of separation from phrases/ users:",
        account.username()
    );
    for degree in data {
        println!(
            "=-=-=-=-=-=-=[Phrase #{}]=-=-=-=-=-=-=",
            degree.phrase_index
        );
        println!("Phrase hash: 0x{}", hex::encode(degree.phrase_hash));
        println!("Phrase description: \"{}\"", degree.description);
        println!("Degrees of separation from origin: {}", degree.degree.unwrap());
        if degree.relation.is_none() {
            println!("Phrase created by this user");
            let phrase = account.decrypt_phrase(&degree.secret_phrase.unwrap());
            println!("Secret phrase: \"{}\"", phrase);
        } else {
            println!("Your relation: {}", degree.relation.unwrap());
            if degree.preceding_relation.is_some() {
                println!(
                    "2nd degree relation: {}",
                    degree.preceding_relation.unwrap()
                );
            }
        }
    }
    Ok(String::from(""))
}

pub async fn get_known_phrases() -> Result<String, GrapevineCLIError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let res = get_known_req(&mut account).await;
    let data = match res {
        Ok(data) => data,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };
    for degree in data {
        println!(
            "=-=-=-=-=-=-=[Phrase #{}]=-=-=-=-=-=-=",
            degree.phrase_index
        );
        println!("Phrase hash: 0x{}", hex::encode(degree.phrase_hash));
        let phrase = account.decrypt_phrase(&degree.secret_phrase.unwrap());
        println!("Secret phrase: \"{}\"", phrase);
        println!("Description: \"{}\"", degree.description);
    }
    Ok(String::from(""))
}

pub async fn get_phrase(phrase_index: u32) -> Result<String, GrapevineCLIError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // get degree data
    let res = get_phrase_req(phrase_index, &mut account).await;
    let phrase_data = match res {
        Ok(data) => data,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };
    // get connection data
    let res = show_connections_req(phrase_index, &mut account).await;
    let connection_data = match res {
        Ok(data) => data,
        Err(e) => return Err(GrapevineCLIError::from(e)),
    };

    /// OUTPUT
    // header (always shown)
    println!("=-=-=-=-=-=-=[Phrase #{}]=-=-=-=-=-=-=", phrase_index);
    println!("Phrase description: \"{}\"", &phrase_data.description);
    println!("Phrase hash: 0x{}", hex::encode(&phrase_data.phrase_hash));
    // if no degree, show that this user does not know the phrase
    if phrase_data.degree.is_none() {
        println!("You do not have any connections to this phrase!");
        return Ok(String::from(""));
    }
    if phrase_data.secret_phrase.is_some() {
        // If phrase is known, show secret
        let decrypted_phrase = account.decrypt_phrase(&phrase_data.secret_phrase.unwrap());
        println!("Secret phrase: \"{}\"", decrypted_phrase);
    } else {
        // If phrase is not known, show degrees of separation from origin + upstream relations
        println!(
            "Degrees of separation from phrase: {}",
            phrase_data.degree.unwrap()
        );
        if phrase_data.relation.is_some() {
            println!(
                "Your 1st degree relation to this phrase: {}",
                phrase_data.relation.unwrap()
            );
        }
        if phrase_data.preceding_relation.is_some() {
            println!(
                "Your 2nd degree relation to this phrase: {}",
                phrase_data.preceding_relation.unwrap()
            );
        }
    }
    // Show connection data
    println!("#####################");
    println!("Total of {} connections to this phrase", connection_data.0);
    for i in 0..connection_data.1.len() {
        let connections = connection_data.1.get(i).unwrap();
        let degree_plural = match i == 0 {
            true => "degree",
            false => "degrees",
        };
        println!(
            "Relationships with {} {} connection to this phrase: {}",
            i + 1,
            degree_plural,
            connections
        );
    }
    Ok(String::from(""))
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
    // get_account_info();
    Ok(account)
}

pub async fn health() -> Result<String, GrapevineCLIError> {
    println!("SERVER URL IS: {}", &**crate::http::SERVER_URL);
    // ensure artifacts exist
    artifacts_guard().await.unwrap();
    // get health status
    let text = reqwest::get(&**crate::http::SERVER_URL)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    return Ok("Health check passed".to_string());
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
