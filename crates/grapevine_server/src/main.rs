#[macro_use]
extern crate rocket;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::TestProofCompressionRequest;
use grapevine_common::session_key::{Server, SessionKey};
use grapevine_common::utils::convert_username_to_fr;
use jsonwebtoken::errors::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mongo::GrapevineDB;
use routes::{create_user, get_user};
// 👈 New!
use crate::guards::NonceGuard;
use babyjubjub_rs::{decompress_point, decompress_signature, verify, Point, Signature};
use mongodb::{
    bson::{doc, oid::ObjectId},
    options::{ClientOptions, FindOneOptions, ServerApi, ServerApiVersion},
    Client, Collection,
};
use num_bigint::{BigInt, Sign};
use rocket::fs::{relative, FileServer};
use rocket::outcome::Outcome::{Error as Failure, Success};
use rocket::request::{self as request, FromRequest};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{Data, Request, Response, State};

mod guards;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb

    let mongo = GrapevineDB::init().await;
    // Initialize logger
    tracing_subscriber::fmt::init();

    // Define warp filter to serve files from static dir
    rocket::build()
        .manage(mongo)
        .mount(
            "/",
            routes![action, health, create_user, get_user, test_proof],
        )
        .mount("/static", FileServer::from(relative!("static")))
        .launch()
        .await
        .unwrap();

    Ok(())
}

#[get("/action")]
async fn action(_guard: NonceGuard) -> &'static str {
    "Succesfully verified nonce"
}

#[post("/test-proof-compression", format = "json", data = "<body>")]
async fn test_proof(body: Json<TestProofCompressionRequest>) {
    println!("Proof: {:?}", body.proof);
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
