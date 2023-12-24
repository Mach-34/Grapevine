#[macro_use]
extern crate rocket;
use crate::models::user::User;
use babyjubjub_rs::{Point, Signature};
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::session_key::{Server, SessionKey};
use grapevine_common::utils::convert_username_to_fr;
use jsonwebtoken::errors::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header}; // 👈 New!
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::{ClientOptions, FindOneOptions, ServerApi, ServerApiVersion},
    Client, Collection,
};
use num_bigint::{BigInt, Sign};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::State;
use rocket::{Data, Request, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

mod models;
mod mongo;
mod routes;

const MONGODB_URI: &str = "mongodb://localhost:27017";
const DATABASE: &str = "grapevine";
const JWT_SECRET: &str = "grapevine_secret";

// pub fn create_jwt(id: i32) -> Result<String, Error> {
//     let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set."); // 👈 New!

//     let expiration = Utc::now()
//         .checked_add_signed(chrono::Duration::seconds(60))
//         .expect("Invalid timestamp")
//         .timestamp();

//     let claims = Claims {
//         subject_id: id,
//         exp: expiration as usize,
//     };

//     let header = Header::new(Algorithm::HS512);

//     // 👇 New!
//     encode(
//         &header,
//         &claims,
//         &EncodingKey::from_secret(secret.as_bytes()),
//     )
// }

/**
 * Attempts to create a new user
 *
 * @param username - the username for the new user
 * @param pubkey - the public key used to authenticate API access for the user
 * @param signature - the signature over the username by pubkey
 * @param auth_secret - the encrypted auth secret used by this user (encrypted with given pubkey)
 */
pub fn create_user(
    username: String,
    pubkey: [u8; 32],
    signature: [u8; 64],
    auth_secret: AuthSecretEncrypted,
) -> Result<(), GrapevineServerError> {
    // check if the username exists already in the database
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb

    // let db = client.database(DATABASE);

    // Initialize logger
    tracing_subscriber::fmt::init();

    // Define warp filter to serve files from static dir
    rocket::build()
        .mount("/", routes![health])
        .launch()
        .await
        .unwrap();

    Ok(())
}

// fn

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
