#[macro_use]
extern crate rocket;
use catchers::{bad_request, not_found, unauthorized};
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::TestProofCompressionRequest;
use grapevine_common::session_key::{Server, SessionKey};
use grapevine_common::utils::convert_username_to_fr;
use jsonwebtoken::errors::Error;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mongo::GrapevineDB;
use routes::{
    add_relationship, create_phrase, create_user, get_available_proofs, get_proof_with_params,
    get_pubkey, get_user,
};
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

mod catchers;
mod guards;
mod mongo;
mod routes;
mod utils;

const MONGODB_URI: &str = "mongodb://localhost:27017";
const DATABASE: &str = "grapevine";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb

    let mongo = GrapevineDB::init().await;
    // Initialize logger
    tracing_subscriber::fmt::init();

    // TODO: Route formatting/ segmenting logic
    rocket::build()
        .manage(mongo)
        .mount(
            "/",
            routes![
                action,
                health,
                create_user,
                get_user,
                create_phrase,
                get_pubkey,
                add_relationship,
                get_available_proofs,
                get_proof_with_params,
            ],
        )
        .mount("/static", FileServer::from(relative!("static")))
        .register("/", catchers![bad_request, not_found, unauthorized])
        .launch()
        .await
        .unwrap();
    Ok(())
}

#[get("/action")]
async fn action(_guard: NonceGuard) -> &'static str {
    "Succesfully verified nonce"
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
