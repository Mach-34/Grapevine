#[macro_use]
extern crate rocket;
use catchers::{bad_request, not_found, unauthorized, CustomResponder};
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::TestProofCompressionRequest;
use grapevine_common::session_key::{Server, SessionKey};
use grapevine_common::utils::convert_username_to_fr;
use mongo::GrapevineDB;
use rocket::http::{Header, Status};
use routes::{
    add_relationship, create_phrase, create_user, degree_proof, get_all_degrees,
    get_available_proofs, get_proof_with_params, get_pubkey, get_user,
};

use crate::guards::NonceGuard;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

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
                degree_proof,
                get_all_degrees
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

#[cfg(test)]
mod test {
    use super::*;
    use rocket::local::asynchronous::Client;

    struct GrapevineTestContext {
        client: Client,
    }

    impl GrapevineTestContext {
        async fn init() -> Self {
            let mongo = GrapevineDB::init().await;
            let rocket = rocket::build()
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
                .register("/", catchers![bad_request, not_found, unauthorized]);

            GrapevineTestContext {
                client: Client::tracked(rocket).await.unwrap(),
            }
        }
    }

    #[rocket::async_test]
    async fn test_create_user() {
        // let account =
        let GrapevineTestContext { client } = GrapevineTestContext::init().await;
        // let auth_header = Header::new("Authorization", "Missing_delimeter");
        let res = client
            .post("/user/create")
            // .header(auth_header)
            .dispatch()
            .await;
        // Clear
    }

    #[rocket::async_test]
    async fn test_nonce_guard() {
        let GrapevineTestContext { client } = GrapevineTestContext::init().await;

        // Test no authorization header
        let res = client.get("/action").dispatch().await;
        let message = res.into_string().await.unwrap();
        assert_eq!("Missing authorization header", message);

        // Test malformed authorization header #1
        let auth_header = Header::new("Authorization", "Missing_delimeter");
        let res = client.get("/action").header(auth_header).dispatch().await;
        let message = res.into_string().await.unwrap();
        assert_eq!("Malformed authorization header", message);

        // Test malformed authorization header #2
        // let auth_header = Header::new("Authorization", "Correct_delimeter-Incorrect_form");
        // let res = client.get("/action").header(auth_header).dispatch().await;
        // let message = res.into_string().await.unwrap();
        // assert_eq!("Malformed authorization header", message);

        let auth_header = Header::new("Authorization", "Missing_delimeter");
        let res = client.get("/action").header(auth_header).dispatch().await;
        let message = res.into_string().await.unwrap();
        assert_eq!("Malformed authorization header", message);
    }
}
