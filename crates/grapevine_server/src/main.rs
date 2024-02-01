#[macro_use]
extern crate rocket;

use mongo::GrapevineDB;
use routes::{
    add_relationship, create_phrase, create_user, degree_proof, get_all_degrees,
    get_available_proofs, get_proof_with_params, get_pubkey, get_user,
};

use crate::guards::NonceGuard;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

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
                degree_proof,
                get_all_degrees
            ],
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

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}
