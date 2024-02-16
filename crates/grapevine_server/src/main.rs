#[macro_use]
extern crate rocket;
use crate::guards::NonceGuard;
use catchers::{bad_request, not_found, unauthorized};
use dotenv::dotenv;
use lazy_static::lazy_static;
use mongo::GrapevineDB;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

mod catchers;
mod guards;
mod mongo;
mod routes;
mod utils;

lazy_static! {
    static ref MONGODB_URI: String = {
        dotenv().ok();
        match std::env::var("MONGODB_URI") {
            Ok(uri) => uri,
            Err(_) => "mongodb://localhost:27017".to_string(),
        }
    };
    static ref DATABASE_NAME: String = {
        dotenv().ok();
        match std::env::var("DATABASE_NAME") {
            Ok(db) => db,
            Err(_) => "grapevine".to_string(),
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb
    let mongo = GrapevineDB::init().await;
    // Initialize logger
    tracing_subscriber::fmt::init();
    // TODO: Route formatting/ segmenting logic
    rocket::build()
        // add mongodb client to context
        .manage(mongo)
        // mount user routes
        .mount("/user", &**routes::USER_ROUTES)
        // mount proof routes
        .mount("/proof", &**routes::PROOF_ROUTES)
        // mount artifact file server
        .mount("/static", FileServer::from(relative!("static")))
        // mount test methods (TO BE REMOVED)
        .mount("/test", routes![action, health])
        // register request guards
        .register("/", catchers![bad_request, not_found, unauthorized])
        .launch()
        .await?;
    Ok(())
}

#[get("/nonce-guard-test")]
async fn action(_guard: NonceGuard) -> &'static str {
    "Succesfully verified nonce"
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}

// #[cfg(test)]
// mod test_rocket {
//     use self::utils::{use_public_params};

//     use super::*;
//     use babyjubjub_rs::PrivateKey;
//     use grapevine_circuits::{
//         nova::nova_proof,
//         utils::{compress_proof, decompress_proof},
//     };
//     use grapevine_common::{
//         account::GrapevineAccount,
//         auth_secret::AuthSecretEncryptedUser,
//         http::requests::{CreateUserRequest, NewPhraseRequest, NewRelationshipRequest},
//         models::{proof::ProvingData, user},
//         utils::random_fr,
//     };
//     use lazy_static::lazy_static;
//     use rocket::{
//         local::asynchronous::{Client, LocalResponse},
//         request,
//         serde::json::Json,
//     };
//     use std::sync::Mutex;

//     lazy_static! {
//         static ref USERS: Mutex<Vec<GrapevineAccount>> = Mutex::new(vec![]);
//     }

//     struct GrapevineTestContext {
//         client: Client,
//     }

//     impl GrapevineTestContext {
//         async fn init() -> Self {
//             let mongo = GrapevineDB::init().await;
//             let rocket = rocket::build()
//                 .manage(mongo)
//                 .mount(
//                     "/",
//                     routes![
//                         action,
//                         health,
//                         create_user,
//                         degree_proof,
//                         get_user,
//                         create_phrase,
//                         get_pubkey,
//                         add_relationship,
//                         get_available_proofs,
//                         get_proof_with_params,
//                     ],
//                 )
//                 .mount("/static", FileServer::from(relative!("static")))
//                 .register("/", catchers![bad_request, not_found, unauthorized]);

//             GrapevineTestContext {
//                 client: Client::tracked(rocket).await.unwrap(),
//             }
//         }
//     }

//     async fn clear_user_from_db(username: String) {
//         let db = GrapevineDB::init().await;
//         let user = db.get_user(username.clone()).await;
//         if user.is_some() {
//             db.remove_user(&user.unwrap().id.unwrap()).await;
//         }
//     }

//     async fn create_user_request(
//         context: &GrapevineTestContext,
//         request: &CreateUserRequest,
//     ) -> String {
//         context
//             .client
//             .post("/user/create")
//             .header(ContentType::JSON)
//             .body(serde_json::json!(request).to_string())
//             .dispatch()
//             .await
//             .into_string()
//             .await
//             .unwrap()
//     }

//     async fn get_user_request(context: &GrapevineTestContext, username: String) -> Option<User> {
//         context
//             .client
//             .get(format!("/user/{}", username))
//             .dispatch()
//             .await
//             .into_json::<User>()
//             .await
//     }

//     fn check_test_env_prepared() -> bool {
//         let users = USERS.lock().unwrap();
//         let prepared = users.get(0).is_some();
//         drop(users);
//         prepared
//     }

//     async fn prepare_test_env() {
//         let mut users = USERS.lock().unwrap();
//         let user_1 = GrapevineAccount::new(String::from("manbearpig"));
//         // Check if user exists or not in database. If it does then remove it so that test can be performed
//         clear_user_from_db(user_1.username().clone()).await;

//         let context = GrapevineTestContext::init().await;

//         let request = user_1.create_user_request();

//         create_user_request(&context, &request).await;
//         users.push(user_1);
//         drop(users);
//     }

//     #[rocket::async_test]
//     async fn test_create_user_wrong_signature() {
//         // todo: CTOR for running beforeAll
//         // initiate context
//         let context = GrapevineTestContext::init().await;
//         // generate two accounts
//         let account_1 = GrapevineAccount::new(String::from("userA1"));
//         let account_2 = GrapevineAccount::new(String::from("userA2"));
//         // generate a signature from account 2
//         let bad_sig = account_2.sign_username().compress();
//         // generate a "Create User" http request from account 1
//         let mut request = account_1.create_user_request();
//         // set the signature for creating account 1 to be the signature of account 2
//         request.signature = bad_sig;
//         // check response failure
//         assert_eq!(
//             create_user_request(&context, &request).await,
//             "Signature by pubkey does not match given message",
//             "Request should fail due to mismatched msg"
//         );
//     }

//     #[rocket::async_test]
//     async fn test_username_exceeding_character_limit() {
//         let context = GrapevineTestContext::init().await;

//         let account = GrapevineAccount::new(String::from("userA1"));

//         let mut request = account.create_user_request();

//         request.username = String::from("fake_username_1234567890_abcdef");

//         assert_eq!(
//             create_user_request(&context, &request).await,
//             format!(
//                 "Username {} exceeds limit of 30 characters.",
//                 request.username
//             ),
//             "Request should fail to to character length exceeded"
//         );
//     }

//     #[rocket::async_test]
//     async fn test_username_with_non_ascii_characters() {
//         let context = GrapevineTestContext::init().await;

//         let account = GrapevineAccount::new(String::from("fake_username_😍😌£"));

//         let request = account.create_user_request();

//         assert_eq!(
//             create_user_request(&context, &request).await,
//             "Username must only contain ascii characters.",
//             "User should be created"
//         );
//     }

//     #[rocket::async_test]
//     async fn test_successful_user_creation() {
//         let username = String::from("manbearpig");
//         clear_user_from_db(username.clone()).await;

//         let context = GrapevineTestContext::init().await;

//         let account = GrapevineAccount::new(username.clone());

//         let request = account.create_user_request();

//         assert_eq!(
//             create_user_request(&context, &request).await,
//             "User succefully created",
//             "User should be created"
//         );

//         // Check that user was stored in DB
//         let user = get_user_request(&context, username).await;
//         assert!(user.is_some(), "User should be stored inside of MongoDB");
//     }

//     #[rocket::async_test]
//     async fn test_nonce_guard_missing_auth_header() {
//         let context = GrapevineTestContext::init().await;

//         // Test no authorization header
//         let res = context.client.get("/nonce-guard-test").dispatch().await;
//         let message = res.into_string().await.unwrap();
//         assert_eq!("Missing authorization header", message);
//     }

//     #[rocket::async_test]
//     async fn test_nonce_guard_malformed_auth_header() {
//         let context = GrapevineTestContext::init().await;

//         let auth_header = Header::new("Authorization", "Missing_delimeter");
//         let res = context
//             .client
//             .get("/nonce-guard-test")
//             .header(auth_header)
//             .dispatch()
//             .await;
//         let message = res.into_string().await.unwrap();
//         assert_eq!("Malformed authorization header", message);
//     }

//     #[rocket::async_test]
//     async fn test_nonce_guard_non_existent_user() {
//         let context = GrapevineTestContext::init().await;
//         let auth_header = Header::new("Authorization", "charlie-0");
//         let res = context
//             .client
//             .get("/nonce-guard-test")
//             .header(auth_header)
//             .dispatch()
//             .await;
//         let message = res.into_string().await.unwrap();
//         assert_eq!("User charlie not found", message);
//     }

//     // #[rocket::async_test]
//     // async fn test_nonce_guard_successful_verification() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();
//     //     let auth_header = Header::new(
//     //         "Authorization",
//     //         format!("{}-{}", user.username(), user.nonce()),
//     //     );
//     //     let context = GrapevineTestContext::init().await;
//     //     let res = context
//     //         .client
//     //         .get("/nonce-guard-test")
//     //         .header(auth_header)
//     //         .dispatch()
//     //         .await;
//     //     let message = res.into_string().await.unwrap();
//     //     assert_eq!("Succesfully verified nonce", message);
//     //     drop(users);
//     // }

//     // #[rocket::async_test]
//     // async fn test_nonce_guard_with_incorrect_nonce() {
//     //     let mut users = USERS.lock().unwrap();
//     //     let mut user = users.get(0).unwrap().clone();
//     //     let nonce = user.nonce();
//     //     let auth_header = Header::new("Authorization", format!("{}-{}", user.username(), nonce));
//     //     let context = GrapevineTestContext::init().await;
//     //     let res = context
//     //         .client
//     //         .get("/nonce-guard-test")
//     //         .header(auth_header)
//     //         .dispatch()
//     //         .await;
//     //     let message = res.into_string().await.unwrap();
//     //     assert_eq!(
//     //         format!(
//     //             "Incorrect nonce provided. Expected {} and received {}",
//     //             nonce + 1,
//     //             nonce
//     //         ),
//     //         message
//     //     );
//     //     user.increment_nonce();
//     //     users[0] = user;
//     //     drop(users);
//     // }

//     // // #[rocket::async_test]
//     // // async fn test_nonce_guard_after_nonce_increment() {
//     // //     let mut users = USERS.lock().unwrap();
//     // //     let mut user = users.get(0).unwrap().clone();
//     // //     let context = GrapevineTestContext::init().await;
//     // //     let auth_header = Header::new(
//     // //         "Authorization",
//     // //         format!("{}-{}", user.username(), user.nonce()),
//     // //     );
//     // //     let res = context
//     // //         .client
//     // //         .get("/nonce-guard-test")
//     // //         .header(auth_header)
//     // //         .dispatch()
//     // //         .await;
//     // //     let message = res.into_string().await.unwrap();
//     // //     assert_eq!("Succesfully verified nonce", message);

//     // //     user.increment_nonce();
//     // //     users[0] = user;
//     // //     drop(users)
//     // // }

//     // // #[rocket::async_test]
//     // // async fn test_create_phrase_with_non_existent_user() {
//     // //     let user = GrapevineAccount::new(String::from("omniman"));
//     // //     let phrase = String::from("She'll be coming around the mountain when she comes");
//     // //     let context = GrapevineTestContext::init().await;

//     // //     let code = context
//     // //         .client
//     // //         .post("/phrase/create")
//     // //         .body(vec![])
//     // //         .dispatch()
//     // //         .await
//     // //         .status()
//     // //         .code;

//     // //     // TODO: Replace code with error message
//     // //     assert_eq!(code, Status::NotFound.code);
//     // // }

//     // #[rocket::async_test]
//     // async fn test_create_phrase_with_invalid_request_body() {
//     //     let context = GrapevineTestContext::init().await;

//     //     let res = context
//     //         .client
//     //         .post("/phrase/create")
//     //         .body(vec![])
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "Request body could not be parsed to NewPhraseRequest", res,
//     //         "Empty request body shouldn't be parseable"
//     //     );
//     // }

//     // // #[rocket::async_test]
//     // // async fn test_create_phrase_with_request_body_over_2_mb() {
//     // //     let context = GrapevineTestContext::init().await;

//     // //     let body = vec![1; 4 * 1024 * 1024];

//     // //     let res = context
//     // //         .client
//     // //         .post("/phrase/create")
//     // //         .body(body)
//     // //         .dispatch()
//     // //         .await
//     // //         .into_string()
//     // //         .await
//     // //         .unwrap();

//     // //     assert_eq!(
//     // //         "Request body execeeds 2 megabytes", res,
//     // //         "Error should be thrown if request execeeds 2 megabytes"
//     // //     );
//     // // }

//     // #[rocket::async_test]
//     // async fn test_successful_phrase_creation() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();
//     //     let phrase = String::from("She'll be coming around the mountain when she comes");

//     //     let username_vec = vec![user.username().clone()];
//     //     let auth_secret_vec = vec![user.auth_secret().clone()];

//     //     let params = use_public_params().unwrap();
//     //     let r1cs = use_r1cs().unwrap();
//     //     let wc_path = use_wasm().unwrap();

//     //     let proof = nova_proof(
//     //         wc_path,
//     //         &r1cs,
//     //         &params,
//     //         &phrase,
//     //         &username_vec,
//     //         &auth_secret_vec,
//     //     )
//     //     .unwrap();

//     //     let context = GrapevineTestContext::init().await;

//     //     let compressed = compress_proof(&proof);

//     //     let body = NewPhraseRequest {
//     //         proof: compressed,
//     //         username: user.username().clone(),
//     //     };

//     //     let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

//     //     let res = context
//     //         .client
//     //         .post("/phrase/create")
//     //         .body(serialized)
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "Succesfully created phrase", res,
//     //         "New phrase should be created with proper request body"
//     //     );
//     // }

//     // // TODO: Test proof generation with a different set of public params

//     // #[rocket::async_test]
//     // async fn test_create_degree_proof_with_invalid_request_body() {
//     //     let context = GrapevineTestContext::init().await;

//     //     let res = context
//     //         .client
//     //         .post("/phrase/continue")
//     //         .body(vec![])
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "Request body could not be parsed to DegreeProofRequest", res,
//     //         "Empty request body shouldn't be parseable"
//     //     );
//     // }

//     // #[rocket::async_test]
//     // async fn test_successful_degree_proof_creation() {
//     //     let context = GrapevineTestContext::init().await;

//     //     let params = use_public_params().unwrap();
//     //     let r1cs = use_r1cs().unwrap();
//     //     let wc_path = use_wasm().unwrap();

//     //     // TODO: Grab
//     //     let oid = "65ce16827c35eaf5e6f4eda5";

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();

//     //     let context = GrapevineTestContext::init().await;

//     //     let url = format!("/proof/{}/params/{}", oid, user.username());

//     //     let res = context.client.get(url).dispatch().await;

//     //     let proving_data = res.into_json::<ProvingData>().await.unwrap();

//     //     let auth_secret_encrypted = AuthSecretEncrypted {
//     //         ephemeral_key: proving_data.ephemeral_key,
//     //         ciphertext: proving_data.ciphertext,
//     //         username: proving_data.username,
//     //         recipient: account.pubkey().compress(),
//     //     };
//     // }

//     // #[rocket::async_test]
//     // async fn test_relationship_creation_with_empty_request_body() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();
//     //     let pubkey = user.pubkey();
//     //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

//     //     let body = NewRelationshipRequest {
//     //         from: user.username().clone(),
//     //         to: user.username().clone(),
//     //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
//     //         ciphertext: encrypted_auth_secret.ciphertext,
//     //     };

//     //     let context = GrapevineTestContext::init().await;

//     //     let res = context
//     //         .client
//     //         .post("/user/relationship")
//     //         .json(&body)
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "User cannot have a relationship with themself", res,
//     //         "User should not be able to have a relationsip with themselves."
//     //     );
//     // }

//     // #[rocket::async_test]
//     // async fn test_relationship_creation_with_non_existent_sender() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();

//     //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));

//     //     let pubkey = user.pubkey();
//     //     let encrypted_auth_secret = user_2.encrypt_auth_secret(pubkey);

//     //     let context = GrapevineTestContext::init().await;

//     //     let body = NewRelationshipRequest {
//     //         from: user_2.username().clone(),
//     //         to: user.username().clone(),
//     //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
//     //         ciphertext: encrypted_auth_secret.ciphertext,
//     //     };

//     //     let res = context
//     //         .client
//     //         .post("/user/relationship")
//     //         .json(&body)
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "Sender does not exist.", res,
//     //         "Sender shouldn't exist inside database."
//     //     );
//     // }

//     // #[rocket::async_test]
//     // async fn test_relationship_creation_with_non_existent_recipient() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();

//     //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));

//     //     let pubkey = user_2.pubkey();
//     //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

//     //     let context = GrapevineTestContext::init().await;

//     //     let body = NewRelationshipRequest {
//     //         from: user.username().clone(),
//     //         to: user_2.username().clone(),
//     //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
//     //         ciphertext: encrypted_auth_secret.ciphertext,
//     //     };

//     //     let res = context
//     //         .client
//     //         .post("/user/relationship")
//     //         .json(&body)
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         "Recipient does not exist.", res,
//     //         "Recipient shouldn't exist inside database."
//     //     );
//     // }

//     // #[rocket::async_test]
//     // async fn test_successful_relationship_creation() {
//     //     if !check_test_env_prepared() {
//     //         prepare_test_env().await
//     //     }

//     //     let users = USERS.lock().unwrap();
//     //     let user = users.get(0).unwrap().clone();

//     //     // Create new user
//     //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));
//     //     let request = user_2.create_user_request();

//     //     let context = GrapevineTestContext::init().await;
//     //     create_user_request(&context, &request).await;

//     //     let pubkey = user_2.pubkey();
//     //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

//     //     let body = NewRelationshipRequest {
//     //         from: user.username().clone(),
//     //         to: user_2.username().clone(),
//     //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
//     //         ciphertext: encrypted_auth_secret.ciphertext,
//     //     };

//     //     let res = context
//     //         .client
//     //         .post("/user/relationship")
//     //         .json(&body)
//     //         .dispatch()
//     //         .await
//     //         .into_string()
//     //         .await
//     //         .unwrap();

//     //     assert_eq!(
//     //         format!(
//     //             "Relationship between {} and {} created",
//     //             user.username(),
//     //             user_2.username()
//     //         ),
//     //         res,
//     //         "Recipient shouldn't exist inside database."
//     //     );
//     // }
// }
