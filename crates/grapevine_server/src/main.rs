#[macro_use]
extern crate rocket;
use crate::guards::AuthenticatedUser;
use catchers::{bad_request, not_found, unauthorized};
use dotenv::dotenv;
use lazy_static::lazy_static;
use mongo::GrapevineDB;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

mod catchers;
mod errors;
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

// #[get("/nonce-guard-test")]
// async fn action(_guard: NonceGuard) -> &'static str {
//     println!("test");
//     "Succesfully verified nonce"
// }

#[get("/nonce-guard-test")]
async fn action(_guard: AuthenticatedUser) -> &'static str {
    println!("test");
    "Succesfully verified nonce"
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}

#[cfg(test)]
mod test_rocket {
    use self::utils::{use_public_params, use_r1cs, use_wasm};

    use super::*;
    use babyjubjub_rs::PrivateKey;
    use grapevine_circuits::{
        nova::{continue_nova_proof, nova_proof, verify_nova_proof},
        utils::{compress_proof, decompress_proof},
    };
    use grapevine_common::{
        account::GrapevineAccount,
        auth_secret::{AuthSecretEncrypted, AuthSecretEncryptedUser},
        http::requests::{
            CreateUserRequest, DegreeProofRequest, NewPhraseRequest, NewRelationshipRequest,
        },
        models::{
            proof::{DegreeProof, ProvingData},
            user::{self, User},
        },
        utils::random_fr,
    };
    use lazy_static::lazy_static;
    use rocket::{
        http::{ContentType, Header, HeaderMap},
        local::asynchronous::{Client, LocalResponse},
        request,
        serde::json::Json,
    };
    use std::sync::Mutex;

    lazy_static! {
        static ref USERS: Mutex<Vec<GrapevineAccount>> = Mutex::new(vec![]);
    }

    struct GrapevineTestContext {
        client: Client,
    }

    impl GrapevineTestContext {
        async fn init() -> Self {
            let mongo = GrapevineDB::init().await;
            let rocket = rocket::build()
                // add mongodb client to context
                .manage(mongo)
                // mount user routes
                .mount("/user", &**routes::USER_ROUTES)
                // mount proof routes
                .mount("/proof", &**routes::PROOF_ROUTES)
                // mount test routes
                .mount("/", routes![action, health])
                // mount artifact file server
                .mount("/static", FileServer::from(relative!("static")))
                .register("/", catchers![bad_request, not_found, unauthorized]);

            GrapevineTestContext {
                client: Client::tracked(rocket).await.unwrap(),
            }
        }
    }

    async fn clear_user_from_db(username: String) {
        let db = GrapevineDB::init().await;
        let user = db.get_user(&username).await;
        if user.is_some() {
            db.remove_user(&user.unwrap().id.unwrap()).await;
        }
    }

    // @TODO: Change eventually because to doesn't need to be mutable?
    async fn add_relationship_request(from: &mut GrapevineAccount, to: &mut GrapevineAccount) {
        let pubkey = to.pubkey();
        let encrypted_auth_secret = from.encrypt_auth_secret(pubkey);

        let body = NewRelationshipRequest {
            to: to.username().clone(),
            ephemeral_key: encrypted_auth_secret.ephemeral_key,
            ciphertext: encrypted_auth_secret.ciphertext,
        };

        let context = GrapevineTestContext::init().await;

        let username = from.username().clone();
        let signature = generate_nonce_signature(from);

        context
            .client
            .post("/user/relationship")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .json(&body)
            .dispatch()
            .await
            .into_string()
            .await;

        // Increment nonce after request
        from.increment_nonce();
    }

    fn generate_nonce_signature(user: &GrapevineAccount) -> String {
        let nonce_signature = user.sign_nonce();
        hex::encode(nonce_signature.compress())
    }

    async fn get_all_degree_proofs(username: String) {
        let context = GrapevineTestContext::init().await;

        let res = context
            .client
            .get(format!("/user/{}/degrees", username))
            .dispatch()
            .await
            .into_json::<Vec<String>>()
            .await;
        if res.is_some() {
            println!("Res: {:?}", res);
        }
    }

    async fn get_available_degrees_request(user: &mut GrapevineAccount) -> Option<Vec<String>> {
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        let degrees = context
            .client
            .get(format!("/proof/available"))
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await
            .into_json::<Vec<String>>()
            .await;

        // Increment nonce after request
        user.increment_nonce();
        degrees
    }

    async fn get_pipeline_test(username: String) -> Option<Vec<String>> {
        let context = GrapevineTestContext::init().await;

        context
            .client
            .get(format!("/proof/{}/pipeline-test", username))
            .dispatch()
            .await
            .into_json::<Vec<String>>()
            .await
    }

    async fn create_degree_proof_request(prev_id: &str, user: &mut GrapevineAccount) {
        let public_params = use_public_params().unwrap();
        let r1cs = use_r1cs().unwrap();
        let wc_path = use_wasm().unwrap();
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        let preceding = context
            .client
            .get(format!("/proof/{}/params", prev_id))
            .header(Header::new("X-Authorization", signature.clone()))
            .header(Header::new("X-Username", username.clone()))
            .dispatch()
            .await
            .into_json::<ProvingData>()
            .await
            .unwrap();

        // Increment nonce after request
        user.increment_nonce();

        let auth_secret_encrypted = AuthSecretEncrypted {
            ephemeral_key: preceding.ephemeral_key,
            ciphertext: preceding.ciphertext,
            username: preceding.username,
            recipient: user.pubkey().compress(),
        };
        let auth_secret = user.decrypt_auth_secret(auth_secret_encrypted);

        // decompress proof
        let mut proof = decompress_proof(&preceding.proof);
        // verify proof
        let previous_output =
            verify_nova_proof(&proof, &public_params, (preceding.degree * 2) as usize)
                .unwrap()
                .0;

        // build nova proof
        let username_input = vec![auth_secret.username, username.clone()];
        let auth_secret_input = vec![auth_secret.auth_secret, user.auth_secret().clone()];

        continue_nova_proof(
            &username_input,
            &auth_secret_input,
            &mut proof,
            previous_output,
            wc_path,
            &r1cs,
            &public_params,
        );

        let compressed = compress_proof(&proof);

        let body = DegreeProofRequest {
            proof: compressed,
            previous: String::from(prev_id),
            degree: preceding.degree + 1,
        };
        let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

        context
            .client
            .post("/proof/phrase/continue")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .body(serialized)
            .dispatch()
            .await;

        // Increment nonce after request
        user.increment_nonce();
    }

    // TODO: Move part of this into grapevine account?
    async fn create_phrase_request(phrase: String, user: &mut GrapevineAccount) {
        let username_vec = vec![user.username().clone()];
        let auth_secret_vec = vec![user.auth_secret().clone()];

        let params = use_public_params().unwrap();
        let r1cs = use_r1cs().unwrap();
        let wc_path = use_wasm().unwrap();

        let proof = nova_proof(
            wc_path,
            &r1cs,
            &params,
            &phrase,
            &username_vec,
            &auth_secret_vec,
        )
        .unwrap();

        let context = GrapevineTestContext::init().await;

        let compressed = compress_proof(&proof);

        let body = NewPhraseRequest { proof: compressed };

        let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        context
            .client
            .post("/proof/phrase/create")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .body(serialized)
            .dispatch()
            .await;

        // Increment nonce after request
        user.increment_nonce();
    }

    async fn create_user_request(
        context: &GrapevineTestContext,
        request: &CreateUserRequest,
    ) -> String {
        context
            .client
            .post("/user/create")
            .header(ContentType::JSON)
            .body(serde_json::json!(request).to_string())
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap()
    }

    async fn get_proof_chain_request(
        context: &GrapevineTestContext,
        phrase_hash: String,
    ) -> Option<Vec<DegreeProof>> {
        context
            .client
            .get(format!("/proof/chain/{}", phrase_hash))
            .dispatch()
            .await
            .into_json::<Vec<DegreeProof>>()
            .await
    }

    async fn get_user_request(context: &GrapevineTestContext, username: String) -> Option<User> {
        context
            .client
            .get(format!("/user/{}", username))
            .dispatch()
            .await
            .into_json::<User>()
            .await
    }

    fn check_test_env_prepared() -> bool {
        let users = USERS.lock().unwrap();
        let prepared = users.get(0).is_some();
        drop(users);
        prepared
    }

    async fn prepare_test_env() {
        let mut users = USERS.lock().unwrap();
        let user_1 = GrapevineAccount::new(String::from("manbearpig"));
        // Check if user exists or not in database. If it does then remove it so that test can be performed
        clear_user_from_db(user_1.username().clone()).await;

        let context = GrapevineTestContext::init().await;

        let request = user_1.create_user_request();

        create_user_request(&context, &request).await;
        users.push(user_1);
        drop(users);
    }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_proof_reordering_with_3_proof_chain() {
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     // Create test users
    //     let mut users = vec![
    //         GrapevineAccount::new(String::from("User_A")),
    //         GrapevineAccount::new(String::from("User_B")),
    //         GrapevineAccount::new(String::from("User_C")),
    //     ];

    //     for i in 0..users.len() {
    //         let request = users[i].create_user_request();
    //         create_user_request(&context, &request).await;
    //     }

    //     // Create phrase for User A
    //     let phrase = String::from("The sheep waited patiently in the field");
    //     create_phrase_request(phrase, &mut users[0]).await;

    //     // Add relationship between User A and User B, B and C, and C and D
    //     for i in 0..users.len() - 1 {
    //         add_relationship_request(&mut users[i], &mut users[i + 1]).await;
    //     }

    //     // Create degree proofs: A <- B <- C
    //     for i in 1..users.len() {
    //         let proofs = get_available_degrees_request(&mut users[i]).await.unwrap();
    //         create_degree_proof_request(&proofs[0], &mut users[i]).await;
    //     }

    //     // Establish relationship between A and C now
    //     add_relationship_request(&mut users[0], &mut users[2]).await;

    //     // Check that C now has an available degree request
    //     let proofs_c = get_available_degrees_request(&mut users[2]).await.unwrap();

    //     // Create new degree proof between A and C
    //     create_degree_proof_request(&proofs_c[0], &mut users[2]).await;
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_proof_reordering_with_4_proof_chain() {
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     // Create test users
    //     let mut users = vec![
    //         GrapevineAccount::new(String::from("User_A")),
    //         GrapevineAccount::new(String::from("User_B")),
    //         GrapevineAccount::new(String::from("User_C")),
    //         GrapevineAccount::new(String::from("User_D")),
    //     ];

    //     for i in 0..users.len() {
    //         let request = users[i].create_user_request();
    //         create_user_request(&context, &request).await;
    //     }

    //     // Create phrase for User A
    //     let phrase = String::from("And that's the waaaayyyy the news goes");
    //     create_phrase_request(phrase, &mut users.get(0).unwrap().clone()).await;

    //     // Add relationship between User A and User B, B and C, and C and D
    //     for i in 0..users.len() - 1 {
    //         add_relationship_request(&mut users[i], &mut users[i + 1]).await;
    //     }

    //     // Create degree proofs: A <- B <- C <- D
    //     for i in 1..users.len() {
    //         let proofs = get_available_degrees_request(&mut users[i]).await.unwrap();
    //         create_degree_proof_request(&proofs[0], &mut users[i]).await;
    //     }

    //     // Establish relationship between A and C now
    //     add_relationship_request(&mut users[0], &mut users[2]).await;

    //     // Check that C now has an available degree request
    //     let proofs_c = get_available_degrees_request(&mut users[2]).await.unwrap();

    //     // Create new degree proof between A and C
    //     create_degree_proof_request(&proofs_c[0], &mut users[2]).await;

    //     // Check avaiable degree with D and perform necessary update
    //     let proofs_d = get_available_degrees_request(&mut users[3]).await.unwrap();

    //     // Create new degree proof between C and D
    //     create_degree_proof_request(&proofs_d[0], &mut users[3]).await;
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_proof_reordering_with_5_proof_chain() {
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     // Create test users
    //     let mut users = vec![
    //         GrapevineAccount::new(String::from("User_A")),
    //         GrapevineAccount::new(String::from("User_B")),
    //         GrapevineAccount::new(String::from("User_C")),
    //         GrapevineAccount::new(String::from("User_D")),
    //         GrapevineAccount::new(String::from("User_E")),
    //     ];

    //     for i in 0..users.len() {
    //         let request = users[i].create_user_request();
    //         create_user_request(&context, &request).await;
    //     }

    //     // Create phrase for User A
    //     let phrase = String::from("You are what you eat");
    //     create_phrase_request(phrase, &mut users.get(0).unwrap().clone()).await;

    //     // Add relationship and degree proofs: A <- B, B <- C
    //     for i in 0..2 {
    //         add_relationship_request(&mut users[i], &mut users[i + 1]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 1])
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut users[i + 1]).await;
    //     }

    //     // Add relationship and degree proofs: C <- D, C <- E
    //     for i in 0..2 {
    //         add_relationship_request(&mut users[2], &mut users[i + 3]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 3])
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut users[i + 3]).await;
    //     }

    //     // Set every proof to degree 2
    //     for i in 0..3 {
    //         add_relationship_request(&mut users[0], &mut users[i + 2]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 2])
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut users[i + 2]).await;
    //     }
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_proof_reordering_with_27_proof_chain() {
    //     // Start with tree structure and eventually have each user connect directly to A
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let mut users: Vec<GrapevineAccount> = vec![];
    //     // Create test users
    //     for i in 0..27 {
    //         let usersname = format!("User_{}", i);
    //         let user = GrapevineAccount::new(usersname);
    //         let creation_request = user.create_user_request();
    //         create_user_request(&context, &creation_request).await;
    //         users.push(user);
    //     }

    //     // Create phrase for User A
    //     let phrase = String::from("They're bureaucrats Morty");
    //     create_phrase_request(phrase, &mut users.get(0).unwrap().clone()).await;

    //     // Create relationships and degree 2 proofs
    //     for i in 0..2 {
    //         add_relationship_request(&mut users[0], &mut users[i + 1]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 1])
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut users[i + 1]).await;
    //     }

    //     // Create relationships and degree 3 proofs
    //     for i in 0..6 {
    //         let preceding_index = 1 + i / 3;
    //         add_relationship_request(&mut users[preceding_index], &mut users[i + 3]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 3])
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut users[i + 3]).await;
    //     }

    //     // Create relationships and degree 4 proofs
    //     for i in 0..18 {
    //         let preceding_index = 3 + i / 3;
    //         add_relationship_request(&mut users[preceding_index], &mut users[i + 9]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 9])
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut users[i + 9]).await;
    //     }

    //     // Bring all proofs to degree 2
    //     for i in 0..24 {
    //         add_relationship_request(&mut users[0], &mut users[i + 3]).await;
    //         let proofs = get_available_degrees_request(&mut users[i + 3])
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut users[i + 3]).await;
    //     }
    // }

    #[rocket::async_test]
    async fn test_create_user_wrong_signature() {
        // todo: CTOR for running beforeAll
        // initiate context
        let context = GrapevineTestContext::init().await;
        // generate two accounts
        let account_1 = GrapevineAccount::new(String::from("userA1"));
        let account_2 = GrapevineAccount::new(String::from("userA2"));
        // generate a signature from account 2
        let bad_sig = account_2.sign_username().compress();
        // generate a "Create User" http request from account 1
        let mut request = account_1.create_user_request();
        // set the signature for creating account 1 to be the signature of account 2
        request.signature = bad_sig;
        // check response failure
        assert_eq!(
            create_user_request(&context, &request).await,
            "Signature by pubkey does not match given message",
            "Request should fail due to mismatched msg"
        );
    }

    #[rocket::async_test]
    async fn test_username_exceeding_character_limit() {
        let context = GrapevineTestContext::init().await;

        let account = GrapevineAccount::new(String::from("userA1"));

        let mut request = account.create_user_request();

        request.username = String::from("fake_username_1234567890_abcdef");

        assert_eq!(
            create_user_request(&context, &request).await,
            format!(
                "Username {} exceeds limit of 30 characters.",
                request.username
            ),
            "Request should fail to to character length exceeded"
        );
    }

    #[rocket::async_test]
    async fn test_username_with_non_ascii_characters() {
        let context = GrapevineTestContext::init().await;

        let account = GrapevineAccount::new(String::from("😍"));

        let request = account.create_user_request();

        assert_eq!(
            create_user_request(&context, &request).await,
            "Username must only contain ascii characters.",
            "User should be created"
        );
    }

    #[rocket::async_test]
    async fn test_successful_user_creation() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let username = String::from("username");

        let context = GrapevineTestContext::init().await;

        let account = GrapevineAccount::new(username.clone());

        let request = account.create_user_request();

        assert_eq!(
            create_user_request(&context, &request).await,
            "User succefully created",
            "User should be created"
        );

        // Check that user was stored in DB
        let user = get_user_request(&context, username).await;
        assert!(user.is_some(), "User should be stored inside of MongoDB");
    }

    #[rocket::async_test]
    async fn test_nonce_guard_missing_auth_headers() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        // Test no authorization header
        let res = context.client.get("/nonce-guard-test").dispatch().await;
        let message = res.into_string().await.unwrap();
        assert_eq!("Missing X-Username header", message);
    }

    #[rocket::async_test]
    async fn test_nonce_guard_missing_authorization_header() {
        let context = GrapevineTestContext::init().await;

        let username = String::from("user_missing_auth_header");

        let username_header = Header::new("X-Username", username);
        let res = context
            .client
            .get("/nonce-guard-test")
            .header(username_header)
            .dispatch()
            .await;
        let message = res.into_string().await.unwrap();
        assert_eq!("Missing X-Authorization header", message);
    }

    #[rocket::async_test]
    #[ignore]
    async fn test_nonce_guard_invalid_authorization_header() {
        let context = GrapevineTestContext::init().await;

        let username = String::from("user_invalid_auth_header");

        let auth_header = Header::new("X-Authorization", "00000000000");
        let username_header = Header::new("X-Username", username);

        let res = context
            .client
            .get("/nonce-guard-test")
            .header(auth_header)
            .header(username_header)
            .dispatch()
            .await;
        let message = res.into_string().await.unwrap();
        println!("Message: {}", message);
        // assert_eq!("User charlie not found", message);
    }

    // #[rocket::async_test]
    // async fn test_nonce_guard_successful_verification() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();
    //     let auth_header = Header::new(
    //         "Authorization",
    //         format!("{}-{}", user.username(), user.nonce()),
    //     );
    //     let context = GrapevineTestContext::init().await;
    //     let res = context
    //         .client
    //         .get("/nonce-guard-test")
    //         .header(auth_header)
    //         .dispatch()
    //         .await;
    //     let message = res.into_string().await.unwrap();
    //     assert_eq!("Succesfully verified nonce", message);
    //     drop(users);
    // }

    // #[rocket::async_test]
    // async fn test_nonce_guard_with_incorrect_nonce() {
    //     let mut users = USERS.lock().unwrap();
    //     let mut user = users.get(0).unwrap().clone();
    //     let nonce = user.nonce();
    //     let auth_header = Header::new("Authorization", format!("{}-{}", user.username(), nonce));
    //     let context = GrapevineTestContext::init().await;
    //     let res = context
    //         .client
    //         .get("/nonce-guard-test")
    //         .header(auth_header)
    //         .dispatch()
    //         .await;
    //     let message = res.into_string().await.unwrap();
    //     assert_eq!(
    //         format!(
    //             "Incorrect nonce provided. Expected {} and received {}",
    //             nonce + 1,
    //             nonce
    //         ),
    //         message
    //     );
    //     user.increment_nonce();
    //     users[0] = user;
    //     drop(users);
    // }

    // // #[rocket::async_test]
    // // async fn test_nonce_guard_after_nonce_increment() {
    // //     let mut users = USERS.lock().unwrap();
    // //     let mut user = users.get(0).unwrap().clone();
    // //     let context = GrapevineTestContext::init().await;
    // //     let auth_header = Header::new(
    // //         "Authorization",
    // //         format!("{}-{}", user.username(), user.nonce()),
    // //     );
    // //     let res = context
    // //         .client
    // //         .get("/nonce-guard-test")
    // //         .header(auth_header)
    // //         .dispatch()
    // //         .await;
    // //     let message = res.into_string().await.unwrap();
    // //     assert_eq!("Succesfully verified nonce", message);

    // //     user.increment_nonce();
    // //     users[0] = user;
    // //     drop(users)
    // // }

    // // #[rocket::async_test]
    // // async fn test_create_phrase_with_non_existent_user() {
    // //     let user = GrapevineAccount::new(String::from("omniman"));
    // //     let phrase = String::from("She'll be coming around the mountain when she comes");
    // //     let context = GrapevineTestContext::init().await;

    // //     let code = context
    // //         .client
    // //         .post("/phrase/create")
    // //         .body(vec![])
    // //         .dispatch()
    // //         .await
    // //         .status()
    // //         .code;

    // //     // TODO: Replace code with error message
    // //     assert_eq!(code, Status::NotFound.code);
    // // }

    // #[rocket::async_test]
    // async fn test_create_phrase_with_invalid_request_body() {
    //     let context = GrapevineTestContext::init().await;

    //     let res = context
    //         .client
    //         .post("/phrase/create")
    //         .body(vec![])
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "Request body could not be parsed to NewPhraseRequest", res,
    //         "Empty request body shouldn't be parseable"
    //     );
    // }

    // // #[rocket::async_test]
    // // async fn test_create_phrase_with_request_body_over_2_mb() {
    // //     let context = GrapevineTestContext::init().await;

    // //     let body = vec![1; 4 * 1024 * 1024];

    // //     let res = context
    // //         .client
    // //         .post("/phrase/create")
    // //         .body(body)
    // //         .dispatch()
    // //         .await
    // //         .into_string()
    // //         .await
    // //         .unwrap();

    // //     assert_eq!(
    // //         "Request body execeeds 2 megabytes", res,
    // //         "Error should be thrown if request execeeds 2 megabytes"
    // //     );
    // // }

    // #[rocket::async_test]
    // async fn test_successful_phrase_creation() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();
    //     let phrase = String::from("She'll be coming around the mountain when she comes");

    //     let username_vec = vec![user.username().clone()];
    //     let auth_secret_vec = vec![user.auth_secret().clone()];

    //     let params = use_public_params().unwrap();
    //     let r1cs = use_r1cs().unwrap();
    //     let wc_path = use_wasm().unwrap();

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &params,
    //         &phrase,
    //         &username_vec,
    //         &auth_secret_vec,
    //     )
    //     .unwrap();

    //     let context = GrapevineTestContext::init().await;

    //     let compressed = compress_proof(&proof);

    //     let body = NewPhraseRequest {
    //         proof: compressed,
    //         username: user.username().clone(),
    //     };

    //     let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

    //     let res = context
    //         .client
    //         .post("/phrase/create")
    //         .body(serialized)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "Succesfully created phrase", res,
    //         "New phrase should be created with proper request body"
    //     );
    // }

    // // TODO: Test proof generation with a different set of public params

    // #[rocket::async_test]
    // async fn test_create_degree_proof_with_invalid_request_body() {
    //     let context = GrapevineTestContext::init().await;

    //     let res = context
    //         .client
    //         .post("/phrase/continue")
    //         .body(vec![])
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "Request body could not be parsed to DegreeProofRequest", res,
    //         "Empty request body shouldn't be parseable"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_successful_degree_proof_creation() {
    //     let context = GrapevineTestContext::init().await;

    //     let params = use_public_params().unwrap();
    //     let r1cs = use_r1cs().unwrap();
    //     let wc_path = use_wasm().unwrap();

    //     // TODO: Grab
    //     let oid = "65ce16827c35eaf5e6f4eda5";

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();

    //     let context = GrapevineTestContext::init().await;

    //     let url = format!("/proof/{}/params/{}", oid, user.username());

    //     let res = context.client.get(url).dispatch().await;

    //     let proving_data = res.into_json::<ProvingData>().await.unwrap();

    //     let auth_secret_encrypted = AuthSecretEncrypted {
    //         ephemeral_key: proving_data.ephemeral_key,
    //         ciphertext: proving_data.ciphertext,
    //         username: proving_data.username,
    //         recipient: account.pubkey().compress(),
    //     };
    // }

    // #[rocket::async_test]
    // async fn test_relationship_creation_with_empty_request_body() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();
    //     let pubkey = user.pubkey();
    //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

    //     let body = NewRelationshipRequest {
    //         from: user.username().clone(),
    //         to: user.username().clone(),
    //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
    //         ciphertext: encrypted_auth_secret.ciphertext,
    //     };

    //     let context = GrapevineTestContext::init().await;

    //     let res = context
    //         .client
    //         .post("/user/relationship")
    //         .json(&body)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "User cannot have a relationship with themself", res,
    //         "User should not be able to have a relationsip with themselves."
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_relationship_creation_with_non_existent_sender() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();

    //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));

    //     let pubkey = user.pubkey();
    //     let encrypted_auth_secret = user_2.encrypt_auth_secret(pubkey);

    //     let context = GrapevineTestContext::init().await;

    //     let body = NewRelationshipRequest {
    //         from: user_2.username().clone(),
    //         to: user.username().clone(),
    //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
    //         ciphertext: encrypted_auth_secret.ciphertext,
    //     };

    //     let res = context
    //         .client
    //         .post("/user/relationship")
    //         .json(&body)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "Sender does not exist.", res,
    //         "Sender shouldn't exist inside database."
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_relationship_creation_with_non_existent_recipient() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();

    //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));

    //     let pubkey = user_2.pubkey();
    //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

    //     let context = GrapevineTestContext::init().await;

    //     let body = NewRelationshipRequest {
    //         from: user.username().clone(),
    //         to: user_2.username().clone(),
    //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
    //         ciphertext: encrypted_auth_secret.ciphertext,
    //     };

    //     let res = context
    //         .client
    //         .post("/user/relationship")
    //         .json(&body)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         "Recipient does not exist.", res,
    //         "Recipient shouldn't exist inside database."
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_successful_relationship_creation() {
    //     if !check_test_env_prepared() {
    //         prepare_test_env().await
    //     }

    //     let users = USERS.lock().unwrap();
    //     let user = users.get(0).unwrap().clone();

    //     // Create new user
    //     let user_2 = GrapevineAccount::new(String::from("pizzaEater"));
    //     let request = user_2.create_user_request();

    //     let context = GrapevineTestContext::init().await;
    //     create_user_request(&context, &request).await;

    //     let pubkey = user_2.pubkey();
    //     let encrypted_auth_secret = user.encrypt_auth_secret(pubkey);

    //     let body = NewRelationshipRequest {
    //         from: user.username().clone(),
    //         to: user_2.username().clone(),
    //         ephemeral_key: encrypted_auth_secret.ephemeral_key,
    //         ciphertext: encrypted_auth_secret.ciphertext,
    //     };

    //     let res = context
    //         .client
    //         .post("/user/relationship")
    //         .json(&body)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     assert_eq!(
    //         format!(
    //             "Relationship between {} and {} created",
    //             user.username(),
    //             user_2.username()
    //         ),
    //         res,
    //         "Recipient shouldn't exist inside database."
    //     );
    // }
}
