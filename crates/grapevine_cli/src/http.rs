use crate::errors::GrapevineCLIError;
use crate::utils::fs::ACCOUNT_PATH;
use babyjubjub_rs::{decompress_point, Point};
use grapevine_common::http::requests::{
    CreateUserRequest, Degree1ProofRequest, DegreeNProofRequest, GetNonceRequest, NewPhraseRequest,
    NewRelationshipRequest,
};
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::ProvingData;
use grapevine_common::{account::GrapevineAccount, errors::GrapevineServerError};
use lazy_static::lazy_static;
use reqwest::{Client, StatusCode};

lazy_static! {
    pub static ref SERVER_URL: String = String::from(env!("SERVER_URL"));
}
// pub const SERVER_URL: &str = "http://localhost:8000";

/// GET REQUESTS ///

/**
 * Makes an HTTP Request to get the public key of a user
 *
 * @param username - the username of the user to get the public key of
 * @returns - the public key of the user
 */
pub async fn get_pubkey_req(username: String) -> Result<Point, GrapevineServerError> {
    let url = format!("{}/user/{}/pubkey", &**SERVER_URL, username);
    let res = reqwest::get(&url).await.unwrap();
    match res.status() {
        StatusCode::OK => {
            let pubkey = res.text().await.unwrap();
            Ok(decompress_point(hex::decode(pubkey).unwrap().try_into().unwrap()).unwrap())
        }
        StatusCode::NOT_FOUND => Err(GrapevineServerError::UserNotFound(username)),
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn get_nonce_req(body: GetNonceRequest) -> Result<u64, GrapevineServerError> {
    let url = format!("{}/user/nonce", &**SERVER_URL);
    let client = Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    match res.status() {
        StatusCode::OK => {
            let nonce = res.text().await.unwrap();
            Ok(nonce.parse().unwrap())
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn get_available_proofs_req(
    account: &mut GrapevineAccount,
) -> Result<Vec<String>, GrapevineServerError> {
    let url = format!("{}/proof/available", &**SERVER_URL);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let proofs = res.json::<Vec<String>>().await.unwrap();
            Ok(proofs)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn get_proof_with_params_req(
    account: &mut GrapevineAccount,
    oid: String,
) -> Result<ProvingData, GrapevineServerError> {
    let url = format!("{}/proof/params/{}", &**SERVER_URL, oid);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let proof = res.json::<ProvingData>().await.unwrap();
            Ok(proof)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

/// POST REQUESTS ///
/**
 * Makes an HTTP Request to create a new user
 *
 * @param body - the CreateUserRequest data to provide as the body of the http request
 * @returns - Ok if 201, or the error type otherwise
 */
pub async fn create_user_req(body: CreateUserRequest) -> Result<(), GrapevineServerError> {
    let url = format!("{}/user/create", &**SERVER_URL);
    let client = Client::new();
    let res = client.post(&url).json(&body).send().await.unwrap();
    match res.status() {
        StatusCode::CREATED => return Ok(()),
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

/**
 * Makes an HTTP Request to add a relationship for another user
 *
 * @param account - the account of the user adding themselves as a relationship to another user
 * @param body - the NewRelationshipRequest data to provide as the body of the http request
 */
pub async fn add_relationship_req(
    account: &mut GrapevineAccount,
    body: NewRelationshipRequest,
) -> Result<(), GrapevineServerError> {
    let url = format!("{}/user/relationship", &**SERVER_URL);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .post(&url)
        .json(&body)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::CREATED => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            return Ok(());
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

/**
 * Makes an HTTP Request to create a new phrase
 *
 * @param account - the account of the user creating the new phrase
 * @param body - the NewPhraseRequest containing proof to provide as the body of the http request
 */
pub async fn new_phrase_req(
    account: &mut GrapevineAccount,
    body: NewPhraseRequest,
) -> Result<u32, GrapevineServerError> {
    let url = format!("{}/proof/phrase", &**SERVER_URL);
    // serialize the proof
    let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .post(&url)
        .body(serialized)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::CREATED => {
            let index = res.text().await.unwrap().parse().unwrap();
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            return Ok(index);
        }
        _ => {
            // Err(res.json::<GrapevineServerError>().await.unwrap())
            Err(GrapevineServerError::InternalError)
        }
    }
}

pub async fn get_account_details_req(
    account: &mut GrapevineAccount,
) -> Result<(u64, u64, u64), GrapevineServerError> {
    let url = format!("{}/user/details", &**SERVER_URL);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let details = res.json::<(u64, u64, u64)>().await.unwrap();
            Ok(details)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn get_degrees_req(
    account: &mut GrapevineAccount,
) -> Result<Vec<DegreeData>, GrapevineServerError> {
    let url = format!("{}/user/degrees", &**SERVER_URL);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let degrees = res.json::<Vec<DegreeData>>().await.unwrap();
            Ok(degrees)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

// todo: combine 1st and n degree proof reqs since only route changes (can make serialization generic)

/**
 * Prove knowledge of a phrase and create a degree 1 proof
 * 
 * @param account - the account of the user proving knowledge of the phrase
 * @param body - the Degree1ProofRequest containing proof and context to provide as the body of the http request
 * @returns - Ok if 201, or the error type otherwise
 */
pub async fn knowledge_proof_req(
    account: &mut GrapevineAccount,
    body: Degree1ProofRequest,
) -> Result<(), GrapevineServerError> {
    let url = format!("{}/proof/knowledge", &**SERVER_URL);
    // serialize the proof
    let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .post(&url)
        .body(serialized)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::CREATED => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            return Ok(());
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

/**
 * Makes an HTTP Request to prove a separation degree
 *
 * @param account - the account of the user proving the separation degree
 * @param body - the NewPhraseRequest containing proof and context to provide as the body of the http request
 */
pub async fn degree_proof_req(
    account: &mut GrapevineAccount,
    body: DegreeNProofRequest,
) -> Result<(), GrapevineServerError> {
    let url = format!("{}/proof/degree", &**SERVER_URL);
    // serialize the proof
    let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .post(&url)
        .body(serialized)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::CREATED => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            return Ok(());
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn get_known_req(
    account: &mut GrapevineAccount,
) -> Result<Vec<DegreeData>, GrapevineServerError> {
    let url = format!("{}/proof/known", &**SERVER_URL);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let proofs = res.json::<Vec<DegreeData>>().await.unwrap();
            Ok(proofs)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}

pub async fn show_connections_req(
    account: &mut GrapevineAccount,
    phrase_index: u32,
) -> Result<(u64, Vec<u64>), GrapevineServerError> {
    let url = format!("{}/proof/connections/{}", &**SERVER_URL, phrase_index);
    // produce signature over current nonce
    let signature = hex::encode(account.sign_nonce().compress());
    let client = Client::new();
    let res = client
        .get(&url)
        .header("X-Username", account.username())
        .header("X-Authorization", signature)
        .send()
        .await
        .unwrap();
    match res.status() {
        StatusCode::OK => {
            // increment nonce
            account
                .increment_nonce(Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            let connection_data = res.json::<(u64, Vec<u64>)>().await.unwrap();
            Ok(connection_data)
        }
        _ => Err(res.json::<GrapevineServerError>().await.unwrap()),
    }
}
