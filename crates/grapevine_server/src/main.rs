#[macro_use]
extern crate rocket;
use crate::models::user::User;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::session_key::{Server, SessionKey};
use grapevine_common::utils::convert_username_to_fr;
use jsonwebtoken::errors::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mongo::GrapvineMongo;
// 👈 New!
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::{ClientOptions, FindOneOptions, ServerApi, ServerApiVersion},
    Client, Collection,
};
use num_bigint::{BigInt, Sign};
use rocket::data::FromData;
use rocket::http::Status;
use rocket::outcome::Outcome::{Error as Failure, Success};
use rocket::request::{self as request, FromRequest};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{Data, Request, Response, State};
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

    let mongo = GrapvineMongo::init().await;
    // Initialize logger
    tracing_subscriber::fmt::init();

    // Define warp filter to serve files from static dir
    rocket::build()
        .manage(mongo)
        .mount("/", routes![action, health])
        .launch()
        .await
        .unwrap();

    Ok(())
}

struct NonceGuard {
    // pubkey: String,
    // TODO: Replace with signature
    nonce: u128,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NonceGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let mongo_request = request.guard::<&State<GrapvineMongo>>().await;
        let mongo = mongo_request.unwrap();
        // println!("Nonce: {}", nonce.unwrap().nonce);
        let auth_string = request.headers().get_one("Authorization");
        if auth_string.is_some() {
            let split: Vec<&str> = auth_string.unwrap().split("-").collect();
            if split.len() == 2 {
                // Public key
                let pubkey = split[0];
                // TODO: Switch nonce to signature
                // Nonce
                let nonce: u128 = split[1].parse().expect("Not a valid number.");
                let mongo_nonce = mongo.get_nonce(pubkey).await;
                match mongo_nonce == nonce {
                    true => Success(NonceGuard { nonce }),
                    // Mismatched nonce or public key
                    false => Failure((Status::BadRequest, ())),
                }
            } else {
                // Improperly formatted authorization header
                Failure((Status::BadRequest, ()))
            }
        } else {
            // Authorization header is missing
            // TODO: Add verbose messaging
            Failure((Status::Unauthorized, ()))
        }
    }
}

#[get("/action")]
async fn action(_guard: NonceGuard) -> &'static str {
    "Succesfully verified nonce"
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
