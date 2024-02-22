#[macro_use]
extern crate rocket;
use crate::guards::AuthenticatedUser;
// use catchers::{bad_request, not_found, unauthorized};
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
    static ref MONGODB_URI: String = String::from(env!("MONGODB_URI"));
    static ref DATABASE_NAME: String = String::from(env!("DATABASE_NAME"));
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
        // .register("/", catchers![bad_request, not_found, unauthorized])
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
    use crate::catchers::GrapevineResponse;

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
        errors::GrapevineServerError,
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
        form::validate::Contains,
        http::{ContentType, Header, HeaderMap, Status},
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
                .mount("/static", FileServer::from(relative!("static")));
            // .register("/", catchers![bad_request, not_found, unauthorized]);

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
    async fn add_relationship_request(
        from: &mut GrapevineAccount,
        to: &mut GrapevineAccount,
    ) -> (u16, Option<String>) {
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

        let res = context
            .client
            .post("/user/relationship")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .json(&body)
            .dispatch()
            .await;

        let code = res.status().code;
        let msg = res.into_string().await;

        // Increment nonce after request
        let _ = from.increment_nonce(None);

        (code, msg)
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
        let _ = user.increment_nonce(None);
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

    async fn create_degree_proof_request(
        prev_id: &str,
        user: &mut GrapevineAccount,
    ) -> (u16, Option<String>) {
        let public_params = use_public_params().unwrap();
        let r1cs = use_r1cs().unwrap();
        let wc_path = use_wasm().unwrap();
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature_params = generate_nonce_signature(user);

        let preceding = context
            .client
            .get(format!("/proof/{}/params", prev_id))
            .header(Header::new("X-Authorization", signature_params))
            .header(Header::new("X-Username", username.clone()))
            .dispatch()
            .await
            .into_json::<ProvingData>()
            .await
            .unwrap();

        // Increment nonce after request
        let _ = user.increment_nonce(None);

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

        let signature_continue = generate_nonce_signature(user);

        let res = context
            .client
            .post("/proof/phrase/continue")
            .header(Header::new("X-Authorization", signature_continue))
            .header(Header::new("X-Username", username))
            .body(serialized)
            .dispatch()
            .await;

        let code = res.status().code;
        let msg = res.into_string().await;

        // Increment nonce after request
        user.increment_nonce(None);

        (code, msg)
    }

    async fn create_phrase_request(
        phrase: String,
        user: &mut GrapevineAccount,
    ) -> (u16, Option<String>) {
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

        let res = context
            .client
            .post("/proof/phrase/create")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .body(serialized)
            .dispatch()
            .await;

        let code = res.status().code;
        let msg = res.into_string().await;

        // Increment nonce after request
        let _ = user.increment_nonce(None);
        (code, msg)
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

    #[rocket::async_test]
    #[ignore]
    async fn test_proof_reordering_with_5_proof_chain() {
        let context = GrapevineTestContext::init().await;

        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        // Create test users
        let mut users = vec![
            GrapevineAccount::new(String::from("User_A")),
            GrapevineAccount::new(String::from("User_B")),
            GrapevineAccount::new(String::from("User_C")),
            GrapevineAccount::new(String::from("User_D")),
            GrapevineAccount::new(String::from("User_E")),
        ];

        for i in 0..users.len() {
            let request = users[i].create_user_request();
            create_user_request(&context, &request).await;
        }

        // Create phrase for User A
        let phrase = String::from("You are what you eat");
        create_phrase_request(phrase, &mut users[0]).await;

        // Add relationship and degree proofs: A <- B, B <- C
        for i in 0..2 {
            // Remove users from vector to reference
            let mut preceding = users.remove(i);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i);

            add_relationship_request(&mut preceding, &mut proceeding).await;
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();
            create_degree_proof_request(&proofs[0], &mut proceeding).await;

            // Add users back to vector
            users.insert(i, preceding);
            users.insert(i + 1, proceeding);
        }

        // Add relationship and degree proofs: C <- D, C <- E
        for i in 0..2 {
            let mut preceding = users.remove(2);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i + 2);

            add_relationship_request(&mut preceding, &mut proceeding).await;
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();
            create_degree_proof_request(&proofs[0], &mut proceeding).await;

            users.insert(2, preceding);
            users.insert(i + 3, proceeding);
        }

        // Set every proof to degree 2
        for i in 0..3 {
            let mut preceding = users.remove(0);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i + 1);

            add_relationship_request(&mut preceding, &mut proceeding).await;
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();
            create_degree_proof_request(&proofs[0], &mut proceeding).await;

            users.insert(0, preceding);
            users.insert(i + 2, proceeding);
        }
    }

    #[rocket::async_test]
    async fn test_proof_reordering_with_20_proof_chain() {
        let context = GrapevineTestContext::init().await;

        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let mut users: Vec<GrapevineAccount> = vec![];

        // Create test users
        for i in 0..20 {
            let user = GrapevineAccount::new(String::from(format!("User_{}", i)));
            let request = user.create_user_request();
            create_user_request(&context, &request).await;
            users.push(user);
        }

        // Create phrase for User A
        let phrase = String::from("You are what you eat");
        create_phrase_request(phrase, &mut users[0]).await;

        // Add relationship and degree proofs: A <- B, B <- C
        for i in 0..users.len() - 1 {
            // Remove users from vector to reference
            let mut preceding = users.remove(i);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i);

            add_relationship_request(&mut preceding, &mut proceeding).await;
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();
            create_degree_proof_request(&proofs[0], &mut proceeding).await;

            // Add users back to vector
            users.insert(i, preceding);
            users.insert(i + 1, proceeding);
        }
    }

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

        let msg = create_user_request(&context, &request).await;
        assert!(
            msg.contains("Could not verify user creation signature"),
            "Request should fail due to mismatched msg"
        );
    }

    #[rocket::async_test]
    async fn test_username_exceeding_character_limit() {
        let context = GrapevineTestContext::init().await;

        let account = GrapevineAccount::new(String::from("userA1"));

        let mut request = account.create_user_request();

        let username = "fake_username_1234567890_abcdef";

        request.username = username.to_string();

        let msg = create_user_request(&context, &request).await;

        let condition = msg.contains("UsernameTooLong") && msg.contains(username);

        assert!(
            condition,
            "Username should be marked as exceeding 30 characters"
        );
    }

    #[rocket::async_test]
    async fn test_username_with_non_ascii_characters() {
        let context = GrapevineTestContext::init().await;

        let username = "😍";

        let account = GrapevineAccount::new(String::from(username));

        let request = account.create_user_request();

        let msg = create_user_request(&context, &request).await;

        let condition = msg.contains("UsernameNotAscii") && msg.contains(username);

        assert!(condition, "User should be created");
    }

    #[rocket::async_test]
    async fn test_successful_user_creation() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let username = String::from("username_successful_creation");

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
    #[ignore]
    async fn test_nonce_guard_missing_auth_headers() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        // Test no authorization header
        let res = context.client.get("/nonce-guard-test").dispatch().await;
        let message = res.into_json::<GrapevineServerError>().await;
        println!("Message: {:?}", message);
        // assert_eq!("Missing X-Username header", message);
    }

    #[rocket::async_test]
    #[ignore]
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

    #[rocket::async_test]
    async fn test_create_phrase_with_invalid_request_body() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let user = GrapevineAccount::new(String::from("user_phrase_test_2"));

        let user_request = user.create_user_request();

        // Create user in db
        create_user_request(&context, &user_request).await;

        let signature = user.sign_nonce();
        let encoded = hex::encode(signature.compress());

        // @TODO: Change phrase request function to set up request body to be tweaked?
        let msg = context
            .client
            .post("/proof/phrase/create")
            .header(Header::new("X-Authorization", encoded))
            .header(Header::new("X-Username", user.username().clone()))
            .body(vec![])
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();

        let condition = msg.contains("SerdeError") && msg.contains("NewPhraseRequest");

        assert!(condition, "Empty request body shouldn't be parseable");
    }

    #[rocket::async_test]
    #[ignore]
    async fn test_create_phrase_with_request_body_in_excess_of_2mb() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let user = GrapevineAccount::new(String::from("user_phrase_test_2"));

        let user_request = user.create_user_request();

        // Create user in db
        create_user_request(&context, &user_request).await;

        let signature = user.sign_nonce();
        let encoded = hex::encode(signature.compress());

        let body: Vec<u8> = vec![10; 5 * 1024 * 1024];

        // @TODO: Change phrase request function to set up request body to be tweaked?
        let msg = context
            .client
            .post("/proof/phrase/create")
            .header(Header::new("X-Authorization", encoded))
            .header(Header::new("X-Username", user.username().clone()))
            .body(body)
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();

        println!("MSG: {}", msg);
    }

    #[rocket::async_test]
    async fn test_successful_phrase_creation() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let mut user = GrapevineAccount::new(String::from("user_phrase_test_3"));

        let phrase = String::from("She'll be coming around the mountain when she comes");

        let user_request = user.create_user_request();

        // Create user in db
        create_user_request(&context, &user_request).await;

        let (code, _) = create_phrase_request(phrase, &mut user).await;
        assert_eq!(
            code,
            Status::Created.code,
            "Phrase should have been successfully created"
        );
    }

    #[rocket::async_test]
    async fn test_relationship_creation_with_empty_request_body() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let user_a = GrapevineAccount::new(String::from("user_relationship_1_a"));
        let user_b = GrapevineAccount::new(String::from("user_relationship_1_b"));

        // Create users
        let user_a_request = user_a.create_user_request();
        let user_b_request = user_b.create_user_request();
        create_user_request(&context, &user_a_request).await;
        create_user_request(&context, &user_b_request).await;

        let signature = user_a.sign_nonce();
        let encoded = hex::encode(signature.compress());

        let res = context
            .client
            .post("/user/relationship")
            .header(Header::new("X-Authorization", encoded))
            .header(Header::new("X-Username", user_a.username().clone()))
            .json::<Vec<u8>>(&vec![])
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();

        println!("Message: {}", res);

        // assert_eq!(
        //     "User cannot have a relationship with themself", res,
        //     "User should not be able to have a relationsip with themselves."
        // );
    }

    #[rocket::async_test]
    async fn test_relationship_creation_with_nonexistent_recipient() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let mut user_a = GrapevineAccount::new(String::from("user_relationship_2_a"));
        let mut user_b = GrapevineAccount::new(String::from("user_relationship_2_b"));

        // Create user
        let user_a_request = user_a.create_user_request();
        create_user_request(&context, &user_a_request).await;

        let (_, msg) = add_relationship_request(&mut user_a, &mut user_b).await;

        assert_eq!(
            msg.unwrap(),
            "Recipient does not exist.",
            "Recipient shouldn't exist"
        );
    }

    #[rocket::async_test]
    async fn test_successful_relationship_creation() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let mut user_a = GrapevineAccount::new(String::from("user_relationship_3_a"));
        let mut user_b = GrapevineAccount::new(String::from("user_relationship_3_b"));

        // Create user
        let user_a_request = user_a.create_user_request();
        let user_b_request = user_b.create_user_request();
        create_user_request(&context, &user_a_request).await;
        create_user_request(&context, &user_b_request).await;

        let (code, _) = add_relationship_request(&mut user_a, &mut user_b).await;

        assert_eq!(
            code,
            Status::Created.code,
            "Relationship should be successfully created"
        )
    }

    #[rocket::async_test]
    async fn test_create_degree_proof_with_invalid_request_body() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let user = GrapevineAccount::new(String::from("user_degree_proof_1"));
        let request = user.create_user_request();

        create_user_request(&context, &request).await;

        let signature = user.sign_nonce();
        let encoded = hex::encode(signature.compress());

        let msg = context
            .client
            .post("/proof/phrase/continue")
            .header(Header::new("X-Authorization", encoded))
            .header(Header::new("X-Username", user.username().clone()))
            .body(vec![])
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();

        let condition = msg.contains("SerdeError") && msg.contains("DegreeProofRequest");
        assert!(
            condition,
            "Degree proof continuation should fail with invalid body"
        )
    }

    #[rocket::async_test]
    async fn test_successful_degree_proof_creation() {
        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        let context = GrapevineTestContext::init().await;

        let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_2_a"));
        let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_2_b"));

        // Create user
        let user_a_request = user_a.create_user_request();
        let user_b_request = user_b.create_user_request();
        create_user_request(&context, &user_a_request).await;
        create_user_request(&context, &user_b_request).await;

        add_relationship_request(&mut user_a, &mut user_b).await;

        // User A creates phrase
        let phrase = String::from("The night has come to a close");
        create_phrase_request(phrase, &mut user_a).await;

        let proofs = get_available_degrees_request(&mut user_b).await.unwrap();

        let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;

        assert_eq!(
            code,
            Status::Created.code,
            "Degree proof should have been created"
        );
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
}
