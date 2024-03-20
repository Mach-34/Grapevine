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
        .mount("/test", routes![health])
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
        crypto::phrase_hash,
        errors::GrapevineServerError,
        http::{
            requests::{
                CreateUserRequest, Degree1ProofRequest, DegreeNProofRequest, NewPhraseRequest,
                NewRelationshipRequest,
            },
            responses::DegreeData,
        },
        models::{DegreeProof, ProvingData, User},
        utils::random_fr,
    };
    use lazy_static::lazy_static;
    use rocket::{
        form::validate::Contains,
        http::{hyper::server::conn, ContentType, Header, HeaderMap, Status},
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
                .mount("/", routes![health])
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

    async fn get_account_details_request(user: &mut GrapevineAccount) -> Option<(u64, u64, u64)> {
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        let res = context
            .client
            .get("/user/details")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await
            .into_json::<(u64, u64, u64)>()
            .await;

        let _ = user.increment_nonce(None);
        res
    }

    async fn get_all_degrees(user: &GrapevineAccount) -> Option<Vec<DegreeData>> {
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        context
            .client
            .get("/user/degrees")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await
            .into_json::<Vec<DegreeData>>()
            .await
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

    async fn get_phrase_connection_request(
        user: &mut GrapevineAccount,
        phrase_hash: &str,
    ) -> Option<(u64, Vec<u64>)> {
        let context = GrapevineTestContext::init().await;

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        let res = context
            .client
            .get(format!("/proof/connections/{}", phrase_hash))
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .dispatch()
            .await
            .into_json::<(u64, Vec<u64>)>()
            .await;
        let _ = user.increment_nonce(None);
        res
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
            .get(format!("/proof/params/{}", prev_id))
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

        let body = DegreeNProofRequest {
            proof: compressed,
            previous: String::from(prev_id),
            degree: preceding.degree + 1,
        };
        let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

        let signature_continue = generate_nonce_signature(user);

        let res = context
            .client
            .post("/proof/degree")
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

    /**
     * Create a new phrase
     *
     * @param phrase - the phrase being added
     * @param description - the description of the phrase
     * @param user - the user adding the phrase
     * @return
     *   - status code
     *   - index of the phrase
     */
    async fn create_phrase_request(
        phrase: &String,
        description: String,
        user: &mut GrapevineAccount,
    ) -> (u16, u32) {
        // hash the phrase
        // DEV: THIS HASH DOESN'T LINE UP FOR SOME REASON. RELYING ON CIRCUIT EXECUTION FOR NOW
        // let hash = phrase_hash(&phrase);

        /// BAD
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
        let res = verify_nova_proof(&proof, &params, 2);
        let hash = res.unwrap().0[1].to_bytes();

        let context: GrapevineTestContext = GrapevineTestContext::init().await;

        // Test http request
        let body = NewPhraseRequest { hash, description };
        let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
        let username = user.username().clone();
        let signature = generate_nonce_signature(user);
        let res = context
            .client
            .post("/proof/phrase")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .body(serialized)
            .dispatch()
            .await;

        let code = res.status().code;
        let msg = res.into_json::<u32>().await.unwrap();

        // Increment nonce after request
        let _ = user.increment_nonce(None);
        (code, msg)
    }

    /**
     * Prove knowledge of a phrase and create a degree 1 proof
     *
     * @param index - the index of the phrase
     * @param phrase - the phrase being proved
     * @param user - the user proving knowledge of the phrase
     * @return
     *  - status code
     *  - message
     */
    async fn knowledge_proof_req(
        index: u32,
        phrase: &String,
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
        let ciphertext = user.encrypt_phrase(&phrase);

        let body = Degree1ProofRequest {
            proof: compressed,
            ciphertext,
            index,
        };

        let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

        let username = user.username().clone();
        let signature = generate_nonce_signature(user);

        let res = context
            .client
            .post("/proof/knowledge")
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

    #[rocket::async_test]
    async fn test_proof_reordering_with_3_proof_chain() {
        let context = GrapevineTestContext::init().await;

        // Reset db with clean state
        GrapevineDB::drop("grapevine_mocked").await;

        // Create test users
        let mut users = vec![
            GrapevineAccount::new(String::from("User_A")),
            GrapevineAccount::new(String::from("User_B")),
            GrapevineAccount::new(String::from("User_C")),
        ];

        for i in 0..users.len() {
            let request = users[i].create_user_request();
            create_user_request(&context, &request).await;
        }

        // Create phrase a phrase as User A
        let phrase = String::from("The sheep waited patiently in the field");
        let description = String::from("Sheep have no patience");
        let (code, index) = create_phrase_request(&phrase, description, &mut users[0]).await;

        // Prove knowledge of the phrase as User A
        knowledge_proof_req(index, &phrase, &mut users[0]).await;

        // Add relationship between User A and User B, B and C
        for i in 0..users.len() - 1 {
            // Remove users from vector to reference
            let mut preceding = users.remove(i);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i);
            add_relationship_request(&mut preceding, &mut proceeding).await;

            // Create degree proofs: A <- B <- C
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();

            // create_degree_proof_request(&proofs[0], &mut proceeding).await;

            // Add users back to vector
            users.insert(i, preceding);
            users.insert(i + 1, proceeding);
        }

        let mut user_a = users.remove(0);
        // User C is now an index below after removal
        let mut user_c = users.remove(1);

        // Establish relationship between A and C now
        add_relationship_request(&mut user_a, &mut user_c).await;

        // Check that C now has an available degree request
        let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();

        // Create new degree proof between A and C
        create_degree_proof_request(&proofs_c[0], &mut user_c).await;
    }

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

    //     // Create phrase a phrase as User A
    //     let phrase = String::from("And that's the waaaayyyy the news goes");
    //     let description = String::from("Wubalubadubdub!");
    //     let (code, index) = create_phrase_request(&phrase, description, &mut users[0]).await;

    //     // // Prove knowledge of the phrase as User A
    //     knowledge_proof_req(index, &phrase, &mut users[0]).await;

    //     // Create relationships and degree proofs: A <- B <- C <- D
    //     for i in 0..users.len() - 1 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }

    //     let mut user_a = users.remove(0);
    //     let mut user_c = users.remove(1);
    //     // Establish relationship between A and C now
    //     add_relationship_request(&mut user_a, &mut user_c).await;
    //     // Check that C now has an available degree request
    //     let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();
    //     // Create new deree proof between A and C
    //     create_degree_proof_request(&proofs_c[0], &mut user_c).await;

    //     users.insert(0, user_a);
    //     users.insert(2, user_c);

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

    //     // Create phrase a phrase as User A
    //     let phrase = String::from("You are what you eat");
    //     let description = String::from("Mediocre cryptographer");
    //     let (code, index) = create_phrase_request(&phrase, description, &mut users[0]).await;

    //     // Prove knowledge of the phrase as User A
    //     knowledge_proof_req(index, &phrase, &mut users[0]).await;

    //     // Add relationship and degree proofs: A <- B, B <- C
    //     for i in 0..2 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }

    //     // Add relationship and degree proofs: C <- D, C <- E
    //     for i in 0..2 {
    //         let mut preceding = users.remove(2);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i + 2);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         users.insert(2, preceding);
    //         users.insert(i + 3, proceeding);
    //     }

    //     // Set every proof to degree 2
    //     for i in 0..3 {
    //         let mut preceding = users.remove(0);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i + 1);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         users.insert(0, preceding);
    //         users.insert(i + 2, proceeding);
    //     }
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_get_degrees_refactor() {
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
    //     let phrase = String::from("You are what you eat");
    //     create_phrase_request(phrase, &mut users[0]).await;

    //     // Add relationship and degree proofs: A <- B, B <- C, C <- D
    //     for i in 0..3 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }

    //     // Get degree proofs for user C
    //     let degrees = get_all_degrees(&users[2]).await;
    //     println!("Degrees: {:?}", degrees);
    //     let degrees = get_all_degrees(&users[1]).await;
    //     println!("Degrees B: {:?}", degrees);
    //     let degrees = get_all_degrees(&users[0]).await;
    //     println!("Degrees A: {:?}", degrees);
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_proof_reordering_with_20_proof_chain() {
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let mut users: Vec<GrapevineAccount> = vec![];

    //     // Create test users
    //     for i in 0..20 {
    //         let user = GrapevineAccount::new(String::from(format!("User_{}", i)));
    //         let request = user.create_user_request();
    //         create_user_request(&context, &request).await;
    //         users.push(user);
    //     }

    //     // Create phrase for User A
    //     let phrase = String::from("You are what you eat");
    //     create_phrase_request(phrase, &mut users[0]).await;

    //     // Add relationship and degree proofs
    //     for i in 0..users.len() - 1 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
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
    //     create_phrase_request(phrase, &mut users[0]).await;

    //     // Create relationships and degree 2 proofs
    //     for i in 0..2 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(0);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //         // Add users back to vector
    //         users.insert(0, preceding);
    //         users.insert(i + 1, proceeding);
    //     }

    //     // Create relationships and degree 3 proofs
    //     for i in 0..6 {
    //         let preceding_index = 1 + i / 3;

    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(preceding_index);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i + 2);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //         // Add users back to vector
    //         users.insert(preceding_index, preceding);
    //         users.insert(i + 2, proceeding);
    //     }

    //     // Create relationships and degree 4 proofs
    //     for i in 0..18 {
    //         let preceding_index = 3 + i / 3;

    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(preceding_index);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i + 8);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(preceding_index, preceding);
    //         users.insert(i + 9, proceeding);
    //     }

    //     // Bring all proofs to degree 2
    //     for i in 0..24 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(0);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i + 2);
    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(0, preceding);
    //         users.insert(i + 3, proceeding);
    //     }
    // }

    #[rocket::async_test]
    async fn test_inactive_relationshionships_hidden_in_degree_return() {
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
            GrapevineAccount::new(String::from("User_F")),
        ];

        for i in 0..users.len() {
            let request = users[i].create_user_request();
            create_user_request(&context, &request).await;
        }

        // Create phrase a phrase as User A
        let phrase = String::from("The sheep waited patiently in the field");
        let description = String::from("Sheep have no patience");
        let (code, index) = create_phrase_request(&phrase, description, &mut users[0]).await;

        // Prove knowledge of the phrase as User A
        knowledge_proof_req(index, &phrase, &mut users[0]).await;

        // Add relationship and degree proofs
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

        // Link 3 middle users to A
        for i in 0..3 {
            // Remove users from vector to reference
            let mut preceding = users.remove(0);
            // Proceeding is now an index below after removal
            let mut proceeding = users.remove(i + 1);

            add_relationship_request(&mut preceding, &mut proceeding).await;
            let proofs = get_available_degrees_request(&mut proceeding)
                .await
                .unwrap();
            create_degree_proof_request(&proofs[0], &mut proceeding).await;

            // Add users back to vector
            users.insert(0, preceding);
            users.insert(i + 2, proceeding);
        }

        // Get degrees
        let degrees = get_all_degrees(&mut users[3]).await;
        assert_eq!(
            degrees.unwrap().len(),
            1,
            "Inactive degrees should have gotten removed from user's list of degree proofs"
        )
    }

    // #[rocket::async_test]
    // async fn test_create_user_wrong_signature() {
    //     // todo: CTOR for running beforeAll
    //     // initiate context
    //     let context = GrapevineTestContext::init().await;
    //     // generate two accounts
    //     let account_1 = GrapevineAccount::new(String::from("userA1"));
    //     let account_2 = GrapevineAccount::new(String::from("userA2"));
    //     // generate a signature from account 2
    //     let bad_sig = account_2.sign_username().compress();
    //     // generate a "Create User" http request from account 1
    //     let mut request = account_1.create_user_request();
    //     // set the signature for creating account 1 to be the signature of account 2
    //     request.signature = bad_sig;
    //     // check response failure

    //     let msg = create_user_request(&context, &request).await;
    //     assert!(
    //         msg.contains("Could not verify user creation signature"),
    //         "Request should fail due to mismatched msg"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_username_exceeding_character_limit() {
    //     let context = GrapevineTestContext::init().await;

    //     let account = GrapevineAccount::new(String::from("userA1"));

    //     let mut request = account.create_user_request();

    //     let username = "fake_username_1234567890_abcdef";

    //     request.username = username.to_string();

    //     let msg = create_user_request(&context, &request).await;

    //     let condition = msg.contains("UsernameTooLong") && msg.contains(username);

    //     assert!(
    //         condition,
    //         "Username should be marked as exceeding 30 characters"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_username_with_non_ascii_characters() {
    //     let context = GrapevineTestContext::init().await;

    //     let username = "😍";

    //     let account = GrapevineAccount::new(String::from(username));

    //     let request = account.create_user_request();

    //     let msg = create_user_request(&context, &request).await;

    //     let condition = msg.contains("UsernameNotAscii") && msg.contains(username);

    //     assert!(condition, "User should be created");
    // }

    // #[rocket::async_test]
    // async fn test_successful_user_creation() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let username = String::from("username_successful_creation");

    //     let context = GrapevineTestContext::init().await;

    //     let account = GrapevineAccount::new(username.clone());

    //     let request = account.create_user_request();

    //     assert_eq!(
    //         create_user_request(&context, &request).await,
    //         "User succefully created",
    //         "User should be created"
    //     );

    //     // Check that user was stored in DB
    //     let user = get_user_request(&context, username).await;
    //     assert!(user.is_some(), "User should be stored inside of MongoDB");
    // }

    // #[rocket::async_test]
    // async fn test_duplicate_user() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let username = String::from("username_duplicate_user");

    //     let context = GrapevineTestContext::init().await;

    //     let account = GrapevineAccount::new(username.clone());

    //     let request = account.create_user_request();

    //     create_user_request(&context, &request).await;
    //     let msg = create_user_request(&context, &request).await;

    //     let condition = msg.contains("UserExists") && msg.contains("username_duplicate_user");

    //     assert!(condition, "Users should be enforced to be unique.")
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_nonce_guard_missing_auth_headers() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     // Test no authorization header
    //     let res = context.client.get("/nonce-guard-test").dispatch().await;
    //     let message = res.into_json::<GrapevineServerError>().await;
    //     println!("Message: {:?}", message);
    //     // assert_eq!("Missing X-Username header", message);
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_nonce_guard_missing_authorization_header() {
    //     let context = GrapevineTestContext::init().await;

    //     let username = String::from("user_missing_auth_header");

    //     let username_header = Header::new("X-Username", username);
    //     let res = context
    //         .client
    //         .get("/nonce-guard-test")
    //         .header(username_header)
    //         .dispatch()
    //         .await;
    //     let message = res.into_string().await.unwrap();
    //     assert_eq!("Missing X-Authorization header", message);
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_nonce_guard_invalid_authorization_header() {
    //     let context = GrapevineTestContext::init().await;

    //     let username = String::from("user_invalid_auth_header");

    //     let auth_header = Header::new("X-Authorization", "00000000000");
    //     let username_header = Header::new("X-Username", username);

    //     let res = context
    //         .client
    //         .get("/nonce-guard-test")
    //         .header(auth_header)
    //         .header(username_header)
    //         .dispatch()
    //         .await;
    //     let message = res.into_string().await.unwrap();
    //     println!("Message: {}", message);
    //     // assert_eq!("User charlie not found", message);
    // }

    // #[rocket::async_test]
    // async fn test_create_phrase_with_invalid_request_body() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let user = GrapevineAccount::new(String::from("user_phrase_test_2"));

    //     let user_request = user.create_user_request();

    //     // Create user in db
    //     create_user_request(&context, &user_request).await;

    //     let signature = user.sign_nonce();
    //     let encoded = hex::encode(signature.compress());

    //     // @TODO: Change phrase request function to set up request body to be tweaked?
    //     let msg = context
    //         .client
    //         .post("/proof/create")
    //         .header(Header::new("X-Authorization", encoded))
    //         .header(Header::new("X-Username", user.username().clone()))
    //         .body(vec![])
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     let condition = msg.contains("SerdeError") && msg.contains("NewPhraseRequest");

    //     assert!(condition, "Empty request body shouldn't be parseable");
    // }

    // #[rocket::async_test]
    // #[ignore]
    // async fn test_create_phrase_with_request_body_in_excess_of_2mb() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let user = GrapevineAccount::new(String::from("user_phrase_test_2"));

    //     let user_request = user.create_user_request();

    //     // Create user in db
    //     create_user_request(&context, &user_request).await;

    //     let signature = user.sign_nonce();
    //     let encoded = hex::encode(signature.compress());

    //     let body: Vec<u8> = vec![10; 5 * 1024 * 1024];

    //     // @TODO: Change phrase request function to set up request body to be tweaked?
    //     let msg = context
    //         .client
    //         .post("/proof/create")
    //         .header(Header::new("X-Authorization", encoded))
    //         .header(Header::new("X-Username", user.username().clone()))
    //         .body(body)
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     println!("MSG: {}", msg);
    // }

    // #[rocket::async_test]
    // async fn test_successful_phrase_creation() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user = GrapevineAccount::new(String::from("user_phrase_test_3"));

    //     let phrase = String::from("She'll be coming around the mountain when she comes");

    //     let user_request = user.create_user_request();

    //     // Create user in db
    //     create_user_request(&context, &user_request).await;

    //     let (code, _) = create_phrase_request(phrase, &mut user).await;
    //     assert_eq!(
    //         code,
    //         Status::Created.code,
    //         "Phrase should have been successfully created"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_reused_phrase() {
    //     let mut user = GrapevineAccount::new(String::from("user_phrase_test_4"));

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let phrase = String::from("There is no plan B, plan A can never fail");

    //     let user_request = user.create_user_request();

    //     // Create user in db
    //     create_user_request(&context, &user_request).await;

    //     create_phrase_request(phrase.clone(), &mut user).await;

    //     let (_, msg) = create_phrase_request(phrase, &mut user).await;

    //     assert!(
    //         msg.unwrap().contains("PhraseExists"),
    //         "Duplicate phrase should be prevented from being added",
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_relationship_creation_with_empty_request_body() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let user_a = GrapevineAccount::new(String::from("user_relationship_1_a"));
    //     let user_b = GrapevineAccount::new(String::from("user_relationship_1_b"));

    //     // Create users
    //     let user_a_request = user_a.create_user_request();
    //     let user_b_request = user_b.create_user_request();
    //     create_user_request(&context, &user_a_request).await;
    //     create_user_request(&context, &user_b_request).await;

    //     let signature = user_a.sign_nonce();
    //     let encoded = hex::encode(signature.compress());

    //     let res = context
    //         .client
    //         .post("/user/relationship")
    //         .header(Header::new("X-Authorization", encoded))
    //         .header(Header::new("X-Username", user_a.username().clone()))
    //         .json::<Vec<u8>>(&vec![])
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     println!("Message: {}", res);

    //     // assert_eq!(
    //     //     "User cannot have a relationship with themself", res,
    //     //     "User should not be able to have a relationsip with themselves."
    //     // );
    // }

    // #[rocket::async_test]
    // async fn test_relationship_creation_with_nonexistent_recipient() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_relationship_2_a"));
    //     let mut user_b = GrapevineAccount::new(String::from("user_relationship_2_b"));

    //     // Create user
    //     let user_a_request = user_a.create_user_request();
    //     create_user_request(&context, &user_a_request).await;

    //     let (_, msg) = add_relationship_request(&mut user_a, &mut user_b).await;

    //     assert_eq!(
    //         msg.unwrap(),
    //         "Recipient does not exist.",
    //         "Recipient shouldn't exist"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_relationship_where_to_is_also_from() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_relationship_3_a"));
    //     let mut clone_a = user_a.clone();

    //     // Create user
    //     let user_a_request = user_a.create_user_request();
    //     create_user_request(&context, &user_a_request).await;

    //     let (_, msg) = add_relationship_request(&mut user_a, &mut clone_a).await;

    //     assert!(
    //         msg.unwrap().contains("RelationshipSenderIsTarget"),
    //         "Relationship cannot be made with your own account"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_successful_relationship_creation() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_relationship_4_a"));
    //     let mut user_b = GrapevineAccount::new(String::from("user_relationship_4_b"));

    //     // Create user
    //     let user_a_request = user_a.create_user_request();
    //     let user_b_request = user_b.create_user_request();
    //     create_user_request(&context, &user_a_request).await;
    //     create_user_request(&context, &user_b_request).await;

    //     let (code, _) = add_relationship_request(&mut user_a, &mut user_b).await;

    //     assert_eq!(
    //         code,
    //         Status::Created.code,
    //         "Relationship should be successfully created"
    //     )
    // }

    // #[rocket::async_test]
    // async fn test_duplicate_relationship() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_relationship_5_a"));
    //     let mut user_b = GrapevineAccount::new(String::from("user_relationship_5_b"));

    //     // Create user
    //     let user_a_request = user_a.create_user_request();
    //     let user_b_request = user_b.create_user_request();
    //     create_user_request(&context, &user_a_request).await;
    //     create_user_request(&context, &user_b_request).await;

    //     add_relationship_request(&mut user_a, &mut user_b).await;
    //     let (_, msg_res) = add_relationship_request(&mut user_a, &mut user_b).await;
    //     let msg = msg_res.unwrap();
    //     let condition = msg.contains("RelationshipExists")
    //         && msg.contains("user_relationship_5_a")
    //         && msg.contains("user_relationship_5_b");

    //     assert!(condition, "Duplicate relationships cannot exist.");
    // }

    // #[rocket::async_test]
    // async fn test_create_degree_proof_with_invalid_request_body() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let user = GrapevineAccount::new(String::from("user_degree_proof_1"));
    //     let request = user.create_user_request();

    //     create_user_request(&context, &request).await;

    //     let signature = user.sign_nonce();
    //     let encoded = hex::encode(signature.compress());

    //     let msg = context
    //         .client
    //         .post("/proof/continue")
    //         .header(Header::new("X-Authorization", encoded))
    //         .header(Header::new("X-Username", user.username().clone()))
    //         .body(vec![])
    //         .dispatch()
    //         .await
    //         .into_string()
    //         .await
    //         .unwrap();

    //     let condition = msg.contains("SerdeError") && msg.contains("DegreeProofRequest");
    //     assert!(
    //         condition,
    //         "Degree proof continuation should fail with invalid body"
    //     )
    // }

    // #[rocket::async_test]
    // async fn test_successful_degree_proof_creation() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_2_a"));
    //     let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_2_b"));

    //     // Create users
    //     let user_a_request = user_a.create_user_request();
    //     let user_b_request = user_b.create_user_request();
    //     create_user_request(&context, &user_a_request).await;
    //     create_user_request(&context, &user_b_request).await;

    //     add_relationship_request(&mut user_a, &mut user_b).await;

    //     // User A creates phrase
    //     let phrase = String::from("The night has come to a close");
    //     create_phrase_request(phrase, &mut user_a).await;

    //     let proofs = get_available_degrees_request(&mut user_b).await.unwrap();

    //     let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;

    //     assert_eq!(
    //         code,
    //         Status::Created.code,
    //         "Degree proof should have been created"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_duplicate_degree_proof() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_3_a"));
    //     let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_3_b"));

    //     // Create users
    //     let user_a_request = user_a.create_user_request();
    //     let user_b_request = user_b.create_user_request();
    //     create_user_request(&context, &user_a_request).await;
    //     create_user_request(&context, &user_b_request).await;

    //     add_relationship_request(&mut user_a, &mut user_b).await;

    //     // User A creates phrase
    //     let phrase = String::from("The night has come to a close");
    //     create_phrase_request(phrase, &mut user_a).await;

    //     let proofs = get_available_degrees_request(&mut user_b).await.unwrap();

    //     create_degree_proof_request(&proofs[0], &mut user_b).await;
    //     let (_, msg) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //     assert!(
    //         msg.unwrap().contains("DegreeProofExists"),
    //         "Cannot create a second degree proof between same accounts for same phrase"
    //     );
    // }

    // #[rocket::async_test]
    // async fn test_get_account_details() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     // Create test users
    //     let mut users = vec![
    //         GrapevineAccount::new(String::from("user_account_details_1")),
    //         GrapevineAccount::new(String::from("user_account_details_2")),
    //         GrapevineAccount::new(String::from("user_account_details_3")),
    //         GrapevineAccount::new(String::from("user_account_details_4")),
    //         GrapevineAccount::new(String::from("user_account_details_5")),
    //         GrapevineAccount::new(String::from("user_account_details_6")),
    //         GrapevineAccount::new(String::from("user_account_details_7")),
    //         GrapevineAccount::new(String::from("user_account_details_8")),
    //         GrapevineAccount::new(String::from("user_account_details_9")),
    //     ];

    //     for i in 0..users.len() {
    //         let request = users[i].create_user_request();
    //         create_user_request(&context, &request).await;
    //     }

    //     let mut user_a = users.remove(0);
    //     let mut user_b = users.remove(0);
    //     let mut user_c = users.remove(0);
    //     let mut user_d = users.remove(0);
    //     let mut user_e = users.remove(0);
    //     let mut user_f = users.remove(0);
    //     let mut user_g = users.remove(0);
    //     let mut user_h = users.remove(0);
    //     let mut user_i = users.remove(0);

    //     let phrase = String::from("The first phrase to end them all");

    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 0, "Phrase count should be 0");
    //     assert_eq!(details.1, 0, "First degree count should be 0");
    //     assert_eq!(details.2, 0, "Second degree count should be 0");

    //     create_phrase_request(phrase, &mut user_a).await;

    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 0, "First degree count should be 0");
    //     assert_eq!(details.2, 0, "Second degree count should be 0");

    //     // Add first degree connection and second degree connection

    //     add_relationship_request(&mut user_b, &mut user_a).await;
    //     add_relationship_request(&mut user_c, &mut user_b).await;

    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 1, "First degree count should be 1");
    //     assert_eq!(details.2, 1, "Second degree count should be 1");

    //     // Relationships with calling account should be excluded
    //     add_relationship_request(&mut user_a, &mut user_b).await;
    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 1, "First degree count should be 1");
    //     assert_eq!(details.2, 1, "Second degree count should be 1");

    //     // Second degree connections that becomes a first degree connection should no longer be treated as second degree
    //     add_relationship_request(&mut user_d, &mut user_b).await;
    //     add_relationship_request(&mut user_e, &mut user_b).await;
    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 1, "First degree count should be 1");
    //     assert_eq!(details.2, 3, "Second degree count should be 3");

    //     add_relationship_request(&mut user_d, &mut user_a).await;
    //     add_relationship_request(&mut user_e, &mut user_a).await;
    //     add_relationship_request(&mut user_a, &mut user_d).await;
    //     add_relationship_request(&mut user_a, &mut user_e).await;
    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 3, "First degree count should be 3");
    //     assert_eq!(details.2, 1, "Second degree count should be 1");

    //     // Test where 3 new degree 2 connections added at once
    //     add_relationship_request(&mut user_g, &mut user_f).await;
    //     add_relationship_request(&mut user_h, &mut user_f).await;
    //     add_relationship_request(&mut user_i, &mut user_f).await;
    //     add_relationship_request(&mut user_f, &mut user_a).await;
    //     let details = get_account_details_request(&mut user_a).await.unwrap();
    //     assert_eq!(details.0, 1, "Phrase count should be 1");
    //     assert_eq!(details.1, 4, "First degree count should be 3");
    //     assert_eq!(details.2, 4, "Second degree count should be 1");
    // }

    // #[rocket::async_test]
    // async fn test_get_phrase_connections() {
    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     let context = GrapevineTestContext::init().await;

    //     let mut users: Vec<GrapevineAccount> = vec![];

    //     for i in 0..7 {
    //         let user =
    //             GrapevineAccount::new(String::from(format!("user_account_details_{}", i + 1)));
    //         let request = user.create_user_request();
    //         create_user_request(&context, &request).await;
    //         users.push(user);
    //     }
    //     let phrase = String::from("Where there's smoke there's fire");
    //     let phrase_hash: [u8; 32] = [
    //         38, 142, 14, 29, 140, 161, 88, 94, 151, 208, 90, 144, 196, 174, 91, 34, 117, 129, 237,
    //         34, 15, 213, 97, 118, 247, 237, 16, 178, 98, 20, 194, 8,
    //     ];
    //     create_phrase_request(phrase, &mut users[0]).await;

    //     let connections = get_phrase_connection_request(&mut users[0], &hex::encode(phrase_hash))
    //         .await
    //         .unwrap();
    //     assert_eq!(connections.0, 0);
    //     assert_eq!(connections.1.len(), 0);
    //     // Create degree proofs and relationships
    //     for i in 0..users.len() - 3 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);

    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();
    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }

    //     let mut user_a = users.remove(0);
    //     let mut user_b = users.remove(0);
    //     let mut user_c = users.remove(0);
    //     let mut user_d = users.remove(0);
    //     let mut user_f = users.remove(1);
    //     let mut user_g = users.remove(1);

    //     let connections = get_phrase_connection_request(&mut user_c, &hex::encode(phrase_hash))
    //         .await
    //         .unwrap();

    //     assert_eq!(connections.0, 1);
    //     assert_eq!(*connections.1.get(1).unwrap(), 1);

    //     add_relationship_request(&mut user_a, &mut user_f).await;
    //     let proofs = get_available_degrees_request(&mut user_f).await.unwrap();
    //     // User F has proof of degree 2
    //     create_degree_proof_request(&proofs[0], &mut user_f).await;
    //     // User G has degree proof 3
    //     add_relationship_request(&mut user_b, &mut user_g).await;
    //     let proofs = get_available_degrees_request(&mut user_g).await.unwrap();
    //     create_degree_proof_request(&proofs[0], &mut user_g).await;

    //     add_relationship_request(&mut user_a, &mut user_c).await;
    //     add_relationship_request(&mut user_d, &mut user_c).await;
    //     add_relationship_request(&mut user_f, &mut user_c).await;
    //     add_relationship_request(&mut user_g, &mut user_c).await;

    //     // User C should have:
    //     // * Connection to User A with proof of degree 1
    //     // * Connection to User B with proof of degree 2
    //     // * Connection to User D with proof of degree 4
    //     // * Connection to User F with proof of degree 2
    //     // * Connection to User G with proof of degree 3
    //     let connections = get_phrase_connection_request(&mut user_c, &hex::encode(phrase_hash))
    //         .await
    //         .unwrap();

    //     assert_eq!(connections.0, 5);
    //     assert_eq!(*connections.1.get(0).unwrap(), 1);
    //     assert_eq!(*connections.1.get(1).unwrap(), 2);
    //     assert_eq!(*connections.1.get(2).unwrap(), 1);
    //     assert_eq!(*connections.1.get(3).unwrap(), 1);

    //     // Different phrase should have no connections returned
    //     let phrase_2 = String::from("Raindrops are falling on my head");
    //     let phrase_hash_2: [u8; 32] = [
    //         38, 142, 14, 29, 140, 161, 88, 94, 151, 208, 90, 144, 196, 174, 91, 34, 117, 129, 237,
    //         34, 15, 213, 97, 118, 247, 237, 16, 178, 98, 20, 194, 8,
    //     ];
    //     create_phrase_request(phrase_2, &mut users[0]).await;
    //     let connections = get_phrase_connection_request(&mut user_c, &hex::encode(phrase_hash))
    //         .await
    //         .unwrap();

    //     assert_eq!(connections.0, 0);
    //     assert_eq!(connections.1.len(), 0);
    // }
}
