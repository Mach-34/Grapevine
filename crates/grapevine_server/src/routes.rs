use grapevine_common::models::user::User;
use crate::mongo::GrapevineDB;
use babyjubjub_rs::{decompress_point, decompress_signature, verify};
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::CreateUserRequest;
use grapevine_common::utils::convert_username_to_fr;
use grapevine_common::MAX_USERNAME_CHARS;
use mongodb::bson::oid::ObjectId;
use num_bigint::{BigInt, Sign};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;
use std::io::{self, Write};

/**
 * Attempts to create a new user
 *
 * @param username - the username for the new user
 * @param pubkey - the public key used to authenticate API access for the user
 * @param signature - the signature over the username by pubkey
 * @param auth_secret - the encrypted auth secret used by this user (encrypted with given pubkey)
 */
#[post("/user/create", format = "json", data = "<request>")]
pub async fn create_user(
    request: Json<CreateUserRequest>,
    db: &State<GrapevineDB>,
) -> Result<Status, Status> {
    // check the validity of the signature over the username
    let message = BigInt::from_bytes_le(
        Sign::Plus,
        &convert_username_to_fr(&request.username).unwrap()[..],
    );
    let pubkey_decompressed = decompress_point(request.pubkey).unwrap();
    let signature_decompressed = decompress_signature(&request.signature).unwrap();
    match verify(pubkey_decompressed, signature_decompressed, message) {
        true => (),
        false => {
            // return Err(GrapevineServerError::Signature(
            //     "Signature by pubkey does not match given message".to_string(),
            // ))
            return Err(Status::Unauthorized);
        }
    };
    // check username length is valid
    if !request.username.len() <= MAX_USERNAME_CHARS {
        return Err(Status::BadRequest);
        // return Err(GrapevineServerError::UsernameTooLong(
        //     request.username.clone(),
        // ));
    };
    // check the username is ascii
    if !request.username.is_ascii() {
        return Err(Status::BadRequest);
        // return Err(GrapevineServerError::UsernameNotAscii(
        //     request.username.clone(),
        // ));
    };
    // check that the username or pubkey are not already used
    match db.check_creation_params(&request.username, &request.pubkey).await {
        Ok(found) => {
            let error_msg = match found {
                [true, true] => "Both Username and Pubkey already exist",
                [true, false] => "Username already exists",
                [false, true] => "Pubkey already exists",
                _ => "",
            };
            if found[0] || found[1] {
                // return Err(GrapevineServerError::UserExists(String::from(error_msg)));
                return Err(Status::Conflict);
            }
        }
        Err(e) => return Err(Status::NotImplemented),
    };
    // create the new user in the database
    let user = User {
        id: None,
        nonce: 0,
        username: request.username.clone(),
        pubkey: request.pubkey.clone(),
        connections: None,
    };
    match db.create_user(user, request.auth_secret.clone()).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => Err(Status::NotImplemented),
    }
}

#[get("/user/<username>")]
pub async fn get_user(username: String, db: &State<GrapevineDB>) -> Result<Json<User>, Status> {
    match db.get_user(username).await {
        Some(user) => Ok(Json(user)),
        None => Err(Status::NotFound),
    }
}