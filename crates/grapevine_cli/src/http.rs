use crate::errors::GrapevineCLIError;
use crate::utils::fs::ACCOUNT_PATH;
use babyjubjub_rs::{decompress_point, Point};
use grapevine_common::http::requests::{
    CreateUserRequest, GetNonceRequest, NewRelationshipRequest,
};
use grapevine_common::{account::GrapevineAccount, errors::GrapevineServerError};
use reqwest::{Client, StatusCode};

pub const SERVER_URL: &str = "http://localhost:8000";

/// GET REQUESTS ///

/**
 * Makes an HTTP Request to get the public key of a user
 *
 * @param username - the username of the user to get the public key of
 * @returns - the public key of the user
 */
pub async fn get_pubkey_req(username: String) -> Result<Point, GrapevineServerError> {
    let url = format!("{}/user/{}/pubkey", SERVER_URL, username);
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
    let url = format!("{}/user/nonce", SERVER_URL);
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

/// POST REQUESTS ///
/**
 * Makes an HTTP Request to create a new user
 *
 * @param body - the CreateUserRequest data to provide as the body of the http request
 * @returns - Ok if 201, or the error type otherwise
 */
pub async fn create_user_req(body: CreateUserRequest) -> Result<(), GrapevineServerError> {
    let url = format!("{}/user/create", SERVER_URL);
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
    let url = format!("{}/user/relationship", SERVER_URL);
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
