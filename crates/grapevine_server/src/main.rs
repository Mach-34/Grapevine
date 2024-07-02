#[macro_use]
extern crate rocket;
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
    let mongo = GrapevineDB::init(&*DATABASE_NAME, &*MONGODB_URI).await;
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

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}

#[cfg(test)]
mod test_rocket {
    use self::utils::{use_public_params, use_r1cs, use_wasm};

    use super::*;
    use grapevine_circuits::{
        nova::{continue_nova_proof, nova_proof, verify_nova_proof},
        utils::{compress_proof, decompress_proof},
    };
    use grapevine_common::{
        account::GrapevineAccount,
        auth_signature::AuthSignatureEncrypted,
        http::{
            requests::{
                CreateUserRequest, DegreeProofRequest, NewRelationshipRequest, PhraseRequest,
            },
            responses::{DegreeData, PhraseCreationResponse},
        },
        models::{DegreeProof, ProvingData, User},
        utils::random_fr,
    };
    use lazy_static::lazy_static;
    use rocket::{
        form::validate::Contains,
        http::{ContentType, Header, Status},
        local::asynchronous::Client,
    };
    use std::sync::Mutex;
    use test_helper::{build_create_user_request, http_create_user};

    lazy_static! {
        static ref USERS: Mutex<Vec<GrapevineAccount>> = Mutex::new(vec![]);
        static ref ARTIFACTS: GrapevineArtifacts = GrapevineArtifacts {
            params: use_public_params(),
            r1cs: use_r1cs(),
            wasm_path: use_wasm()
        };
    }

    struct GrapevineTestContext {
        client: Client,
    }

    impl GrapevineTestContext {
        async fn init() -> Self {
            let database_name = String::from("grapevine_mocked");
            let mongo = GrapevineDB::init(&database_name, &*MONGODB_URI).await;
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

    mod test_helper {
        use super::ARTIFACTS;
        use grapevine_circuits::utils::compress_proof;
        use grapevine_common::{http::requests::CreateUserRequest, NovaProof};

        /**
         * Build a grapevine identity proof (degree 0) given a grapevine account
         *
         * @return the grapevine proof
         */
        pub fn build_identity_proof(from: &GrapevineAccount) -> NovaProof {
            // get inputs
            let private_key = &from.private_key();
            let identity_inputs = GrapevineInputs::identity_step(private_key);
            let proof =
                grapevine_circuits::nova::identity_proof(&ARTIFACTS, &identity_inputs).unwrap();
        }

        /**
         * Construct the request body for a user creation request
         *
         * @return - the body for a user creation http request
         */
        pub fn build_create_user_request(from: &GrapevineAccount) -> CreateUserRequest {
            let proof = build_identity_proof(from);
            let compressed = compress_proof(&proof);
            from.create_user_request(compressed)
        }

        /**
         * Mock http request to create a new user
         *
         * @param context - the mocked rocket http server context
         * @param payload - the body of the request
         * @return - (http status code, returned message)
         */
        pub async fn http_create_user(
            context: &GrapevineTestContext,
            payload: CreateUserRequest,
        ) -> (u16, String) {
            // serialze the payload
            let serialized = bincode::serialize(&payload).unwrap();
            // mock transmit the request
            let res = context
                .post("/proof/identity")
                .body(serialized)
                .dispatch()
                .await;
            let code = res.status().code;
            let message = res.into_string().await.unwrap();
            (code, message)
        }
    }

    #[rocket::async_test]
    pub async fn test_add_user() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a new Grapevine Account
        let user = GrapevineAccount::new("User_A".into());
        // Build body for create_user_request, including constructing grapevine proof of identity
        let payload = build_create_user_request(&user);
        // transmit request to the server
        let (code, message) = http_create_user(&context, payload).await;
        println!("Status code: {}", code);
        println!("Response message: {}", message);
    }

    //     // @TODO: Change eventually because to doesn't need to be mutable?
    //     async fn add_relationship_request(
    //         from: &mut GrapevineAccount,
    //         to: &mut GrapevineAccount,
    //     ) -> (u16, Option<String>) {
    //         let pubkey = to.pubkey();
    //         let encrypted_auth_signature = from.generate_auth_signature(pubkey);

    //         let body = NewRelationshipRequest {
    //             to: to.username().clone(),
    //             ephemeral_key: encrypted_auth_signature.ephemeral_key,
    //             ciphertext: encrypted_auth_signature.ciphertext,
    //         };

    //         let context = GrapevineTestContext::init().await;

    //         let username = from.username().clone();
    //         let signature = generate_nonce_signature(from);

    //         let res = context
    //             .client
    //             .post("/user/relationship/add")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .json(&body)
    //             .dispatch()
    //             .await;

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         let _ = from.increment_nonce(None);

    //         (code, msg)
    //     }

    //     fn generate_nonce_signature(user: &GrapevineAccount) -> String {
    //         let nonce_signature = user.sign_nonce();
    //         hex::encode(nonce_signature.compress())
    //     }

    //     async fn get_account_details_request(user: &mut GrapevineAccount) -> Option<(u64, u64, u64)> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .get("/user/details")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<(u64, u64, u64)>()
    //             .await;

    //         let _ = user.increment_nonce(None);
    //         res
    //     }

    //     async fn get_all_degrees(user: &GrapevineAccount) -> Option<Vec<DegreeData>> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         context
    //             .client
    //             .get("/user/degrees")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<Vec<DegreeData>>()
    //             .await
    //     }

    //     async fn get_available_degrees_request(user: &mut GrapevineAccount) -> Option<Vec<String>> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let degrees = context
    //             .client
    //             .get(format!("/proof/available"))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<Vec<String>>()
    //             .await;

    //         // Increment nonce after request
    //         let _ = user.increment_nonce(None);
    //         degrees
    //     }

    //     async fn get_phrase_connection_request(
    //         user: &mut GrapevineAccount,
    //         phrase_index: u32,
    //     ) -> Option<(u64, Vec<u64>)> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .get(format!("/proof/connections/{}", phrase_index))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<(u64, Vec<u64>)>()
    //             .await;
    //         let _ = user.increment_nonce(None);
    //         res
    //     }

    //     async fn create_degree_proof_request(
    //         prev_id: &str,
    //         user: &mut GrapevineAccount,
    //     ) -> (u16, Option<String>) {
    //         let public_params = use_public_params().unwrap();
    //         let r1cs = use_r1cs().unwrap();
    //         let wc_path = use_wasm().unwrap();
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature_params = generate_nonce_signature(user);

    //         let preceding = context
    //             .client
    //             .get(format!("/proof/params/{}", prev_id))
    //             .header(Header::new("X-Authorization", signature_params))
    //             .header(Header::new("X-Username", username.clone()))
    //             .dispatch()
    //             .await
    //             .into_json::<ProvingData>()
    //             .await
    //             .unwrap();

    //         // Increment nonce after request
    //         let _ = user.increment_nonce(None);

    //         let auth_signature_encrypted = AuthSignatureEncrypted {
    //             ephemeral_key: preceding.ephemeral_key,
    //             ciphertext: preceding.ciphertext,
    //             username: preceding.username,
    //             recipient: user.pubkey().compress(),
    //         };
    //         let auth_signature = user.decrypt_auth_signature(auth_signature_encrypted);

    //         // decompress proof
    //         let mut proof = decompress_proof(&preceding.proof);
    //         // verify proof
    //         let previous_output =
    //             verify_nova_proof(&proof, &public_params, 1 + (preceding.degree * 2) as usize)
    //                 .unwrap()
    //                 .0;

    //         continue_nova_proof(
    //             &user.pubkey(),
    //             &auth_signature.fmt_circom(),
    //             &mut proof,
    //             previous_output,
    //             wc_path,
    //             &r1cs,
    //             &public_params,
    //         );

    //         let compressed = compress_proof(&proof);

    //         let body = DegreeProofRequest {
    //             proof: compressed,
    //             previous: String::from(prev_id),
    //             degree: preceding.degree + 1,
    //         };
    //         let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

    //         let signature_continue = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .post("/proof/degree")
    //             .header(Header::new("X-Authorization", signature_continue))
    //             .header(Header::new("X-Username", username))
    //             .body(serialized)
    //             .dispatch()
    //             .await;

    //         println!("Res: {:?}", res);

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         user.increment_nonce(None);

    //         (code, msg)
    //     }

    // /**
    //  * Create a new phrase
    //  *
    //  * @param phrase - the phrase being added
    //  * @param description - the description of the phrase
    //  * @param user - the user adding the phrase
    //  * @return
    //  *   - status code
    //  *   - index of the phrase
    //  */
    // async fn phrase_request(
    //     phrase: &String,
    //     description: String,
    //     user: &mut GrapevineAccount,
    // ) -> (u16, String) {
    //     // init context
    //     let context: GrapevineTestContext = GrapevineTestContext::init().await;

    //     // create the phrase proof
    //     let pubkey_vec = vec![user.pubkey().clone()];
    //     let auth_signature_vec = vec![[random_fr(), random_fr(), random_fr()]];

    //     let params = use_public_params().unwrap();
    //     let r1cs = use_r1cs().unwrap();
    //     let wc_path = use_wasm().unwrap();

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &params,
    //         &phrase,
    //         &pubkey_vec,
    //         &auth_signature_vec,
    //     )
    //     .unwrap();

    //     // compress proof
    //     let compressed = compress_proof(&proof);
    //     // encrypt phrase
    //     let ciphertext = user.encrypt_phrase(&phrase);

    //     // Mock http request
    //     let body = PhraseRequest {
    //         proof: compressed,
    //         ciphertext,
    //         description,
    //     };
    //     let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    //     let username = user.username().clone();
    //     let signature = generate_nonce_signature(user);
    //     let res = context
    //         .client
    //         .post("/proof/phrase")
    //         .header(Header::new("X-Authorization", signature))
    //         .header(Header::new("X-Username", username))
    //         .body(serialized)
    //         .dispatch()
    //         .await;

    //     // parse code and msg
    //     let code = res.status().code;
    //     // if successful, can be parsed into u32 index of phrase. Otherwise is error msg
    //     let msg = res.into_string().await.unwrap();

    //     // Increment nonce after request
    //     let _ = user.increment_nonce(None);
    //     (code, msg)
    // }

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

    //     async fn get_relationships_request(
    //         context: &GrapevineTestContext,
    //         user: &mut GrapevineAccount,
    //         active: bool,
    //     ) -> Option<Vec<String>> {
    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);
    //         let route = if active { "active" } else { "pending" };
    //         let res = context
    //             .client
    //             .get(format!("/user/relationship/{}", route))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<Vec<String>>()
    //             .await;

    //         // Increment nonce after request
    //         let _ = user.increment_nonce(None);
    //         res
    //     }

    //     async fn reject_relationship_request(
    //         context: &GrapevineTestContext,
    //         from: &mut GrapevineAccount,
    //         to: &String,
    //     ) -> (u16, Option<String>) {
    //         let username = from.username().clone();
    //         let signature = generate_nonce_signature(from);

    //         let res = context
    //             .client
    //             .post(format!("/user/relationship/reject/{}", to))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await;

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         let _ = from.increment_nonce(None);

    //         (code, msg)
    //     }

    // #[rocket::async_test]
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

    //     // Create phrase a phrase as User A
    //     let phrase = String::from("The sheep waited patiently in the field");
    //     let description = String::from("Sheep have no patience");
    //     _ = phrase_request(&phrase, description, &mut users[0]).await;

    //     // Add relationship between User A and User B, B and C
    //     for i in 0..users.len() - 1 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);
    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         add_relationship_request(&mut proceeding, &mut preceding).await;

    //         // Create degree proofs: A <- B <- C
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }
    //     println!("8====================================D");

    //     let mut user_a = users.remove(0);
    //     // User C is now an index below after removal
    //     let mut user_c = users.remove(1);

    //     // Establish relationship between A and C now
    //     add_relationship_request(&mut user_a, &mut user_c).await;
    //     add_relationship_request(&mut user_c, &mut user_a).await;

    //     // Check that C now has an available degree request
    //     let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();

    //     // Create new degree proof between A and C
    //     create_degree_proof_request(&proofs_c[0], &mut user_c).await;
    // }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_4_proof_chain() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("And that's the waaaayyyy the news goes");
    //         let description = String::from("Wubalubadubdub!");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Create relationships and degree proofs: A <- B <- C <- D
    //         for i in 0..users.len() - 1 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_c = users.remove(1);
    //         // Establish relationship between A and C now
    //         add_relationship_request(&mut user_a, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_a).await;

    //         // Check that C now has an available degree request
    //         let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();
    //         // Create new deree proof between A and C
    //         create_degree_proof_request(&proofs_c[0], &mut user_c).await;

    //         users.insert(0, user_a);
    //         users.insert(2, user_c);

    //         // Check avaiable degree with D and perform necessary update
    //         let proofs_d = get_available_degrees_request(&mut users[3]).await.unwrap();
    //         // Create new degree proof between C and D
    //         create_degree_proof_request(&proofs_d[0], &mut users[3]).await;
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_5_proof_chain() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //             GrapevineAccount::new(String::from("User_E")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("You are what you eat");
    //         let description = String::from("Mediocre cryptographer");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs: A <- B, B <- C
    //         for i in 0..2 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Add relationship and degree proofs: C <- D, C <- E
    //         for i in 0..2 {
    //             let mut preceding = users.remove(2);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             users.insert(2, preceding);
    //             users.insert(i + 3, proceeding);
    //         }

    //         // Set every proof to degree 2
    //         for i in 0..3 {
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 1);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             users.insert(0, preceding);
    //             users.insert(i + 2, proceeding);
    //         }
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_27_proof_chain() {
    //         // should this test pass?
    //         // Start with tree structure and eventually have each user connect directly to A
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let mut users: Vec<GrapevineAccount> = vec![];
    //         // Create test users
    //         for i in 0..27 {
    //             let usersname = format!("User_{}", i);
    //             let user = GrapevineAccount::new(usersname);
    //             let creation_request = user.create_user_request();
    //             create_user_request(&context, &creation_request).await;
    //             users.push(user);
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase =
    //             String::from("They're bureaucrats. I don't respect them. Just keep shooting Morty.");
    //         let description = String::from("It's a figure if speech Morty.");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         println!("Started");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 2 proofs
    //         for i in 0..2 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 1, proceeding);
    //         }
    //         println!("Degree 2");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 3 proofs
    //         for i in 0..6 {
    //             let preceding_index = 1 + i / 3;

    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(preceding_index);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //             // Add users back to vector
    //             users.insert(preceding_index, preceding);
    //             users.insert(i + 2, proceeding);
    //         }
    //         println!("Degree 3");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 4 proofs
    //         for i in 0..18 {
    //             let preceding_index = 3 + i / 3;
    //             println!("Index: {}", preceding_index);
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(preceding_index);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 8);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(preceding_index, preceding);
    //             users.insert(i + 9, proceeding);
    //         }

    //         println!("Degree 4");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Bring all proofs to degree 2
    //         for i in 0..24 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);
    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 3, proceeding);
    //         }
    //         println!("Done");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_degrees_refactor() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("You are what you eat");
    //         let description = String::from("Mediocre cryptographer");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs: A <- B, B <- C, C <- D
    //         for i in 0..3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Get degree proofs for user C
    //         let degrees = get_all_degrees(&users[2]).await;
    //         println!("Degrees: {:?}", degrees);
    //         let degrees = get_all_degrees(&users[1]).await;
    //         println!("Degrees B: {:?}", degrees);
    //         let degrees = get_all_degrees(&users[0]).await;
    //         println!("Degrees A: {:?}", degrees);
    //     }

    //     #[rocket::async_test]
    //     async fn test_inactive_relationships_hidden_in_degree_return() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //             GrapevineAccount::new(String::from("User_E")),
    //             GrapevineAccount::new(String::from("User_F")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The sheep waited patiently in the field");
    //         let description = String::from("Sheep have no patience");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs
    //         for i in 0..users.len() - 1 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Link 3 middle users to A
    //         for i in 0..3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 1);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 2, proceeding);
    //         }

    //         // Get degrees
    //         let degrees = get_all_degrees(&mut users[3]).await;
    //         assert_eq!(
    //             degrees.unwrap().len(),
    //             1,
    //             "Inactive degrees should have gotten removed from user's list of degree proofs"
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_create_user_wrong_signature() {
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
    //         let msg = create_user_request(&context, &request).await;
    //         assert!(
    //             msg.contains("Could not verify user creation signature"),
    //             "Request should fail due to mismatched msg"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_username_exceeding_character_limit() {
    //         let context = GrapevineTestContext::init().await;

    //         let account = GrapevineAccount::new(String::from("userA1"));

    //         let mut request = account.create_user_request();

    //         let username = "fake_username_1234567890_abcdef";

    //         request.username = username.to_string();

    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UsernameTooLong") && msg.contains(username);

    //         assert!(
    //             condition,
    //             "Username should be marked as exceeding 30 characters"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_username_with_non_ascii_characters() {
    //         let context = GrapevineTestContext::init().await;

    //         let username = "😍";

    //         let account = GrapevineAccount::new(String::from(username));

    //         let request = account.create_user_request();

    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UsernameNotAscii") && msg.contains(username);

    //         assert!(condition, "User should be created");
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_user_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let username = String::from("username_successful_creation");

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
    //     async fn test_duplicate_user() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let username = String::from("username_duplicate_user");

    //         let context = GrapevineTestContext::init().await;

    //         let account = GrapevineAccount::new(username.clone());

    //         let request = account.create_user_request();

    //         create_user_request(&context, &request).await;
    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UserExists") && msg.contains("username_duplicate_user");

    //         assert!(condition, "Users should be enforced to be unique.")
    //     }

    //     #[rocket::async_test]
    //     async fn test_missing_authorization_headers() {
    //         let context = GrapevineTestContext::init().await;

    //         // test without X-Username or X-Authorization header
    //         let res = context.client.get("/user/degrees").dispatch().await;
    //         assert_eq!(res.status(), Status::BadRequest);

    //         // make user
    //         let user = GrapevineAccount::new(String::from("user_missing_auth_header"));
    //         // test without X-Authorization header
    //         let username = user.username().clone();
    //         let username_header = Header::new("X-Username", username);
    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(username_header)
    //             .dispatch()
    //             .await;
    //         assert_eq!(res.status(), Status::BadRequest);

    //         // test without X-Username header
    //         let signature_header = Header::new("X-Authorization", generate_nonce_signature(&user));
    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(signature_header)
    //             .dispatch()
    //             .await;
    //         assert_eq!(res.status(), Status::BadRequest);
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_invalid_authorization_header() {
    //         let context = GrapevineTestContext::init().await;

    //         let username = String::from("user_invalid_auth_header");

    //         let auth_header = Header::new("X-Authorization", "00000000000");
    //         let username_header = Header::new("X-Username", username);

    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(auth_header)
    //             .header(username_header)
    //             .dispatch()
    //             .await;
    //         let message = res.into_string().await.unwrap();
    //         println!("Message: {}", message);
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_relationship_creation_with_empty_request_body() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let user_a = GrapevineAccount::new(String::from("user_relationship_1_a"));
    //         let user_b = GrapevineAccount::new(String::from("user_relationship_1_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         let signature = user_a.sign_nonce();
    //         let encoded = hex::encode(signature.compress());

    //         let res = context
    //             .client
    //             .post("/user/relationship")
    //             .header(Header::new("X-Authorization", encoded))
    //             .header(Header::new("X-Username", user_a.username().clone()))
    //             .json::<Vec<u8>>(&vec![])
    //             .dispatch()
    //             .await
    //             .into_string()
    //             .await
    //             .unwrap();

    //         println!("Message: {}", res);

    //         assert_eq!(
    //             "User cannot have a relationship with themself", res,
    //             "User should not be able to have a relationsip with themselves."
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_relationship_creation_with_nonexistent_recipient() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_2_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_2_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         create_user_request(&context, &user_a_request).await;

    //         let (_, msg) = add_relationship_request(&mut user_a, &mut user_b).await;

    //         assert_eq!(
    //             msg.unwrap(),
    //             "Recipient does not exist.",
    //             "Recipient shouldn't exist"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_relationship_where_to_is_also_from() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_3_a"));
    //         let mut clone_a = user_a.clone();

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         create_user_request(&context, &user_a_request).await;

    //         let (_, msg) = add_relationship_request(&mut user_a, &mut clone_a).await;

    //         assert!(
    //             msg.unwrap().contains("RelationshipSenderIsTarget"),
    //             "Relationship cannot be made with your own account"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_relationship_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_4_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_4_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         // Check add pending relationship request
    //         let (code, msg) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Relationship add code should be 201"
    //         );
    //         assert_eq!(
    //             msg.unwrap(),
    //             "Relationship from user_relationship_4_a to user_relationship_4_b pending!",
    //             "Relationship should be pending"
    //         );

    //         // Check activate relationship request
    //         let (code, msg) = add_relationship_request(&mut user_b, &mut user_a).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Relationship add code should be 201"
    //         );
    //         assert_eq!(
    //             msg.unwrap(),
    //             "Relationship from user_relationship_4_b to user_relationship_4_a activated!",
    //             "Relationship should be activated"
    //         );

    //         // Check no pending relationships
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             0,
    //             "User A should have no pending relationships"
    //         );

    //         // Check a and b have pending requests
    //         let active_relationships = get_relationships_request(&context, &mut user_a, true)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             active_relationships.len(),
    //             1,
    //             "User A should have one active relationship"
    //         );
    //         assert_eq!(
    //             active_relationships.get(0).unwrap(),
    //             user_b.username(),
    //             "User B should be active relationship"
    //         );
    //         let active_relationships = get_relationships_request(&context, &mut user_b, true)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             active_relationships.len(),
    //             1,
    //             "User B should have one active relationship"
    //         );
    //         assert_eq!(
    //             active_relationships.get(0).unwrap(),
    //             user_a.username(),
    //             "User A should be active relationship"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_only_prove_with_active_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         // Add relationship from a to b
    //         _ = add_relationship_request(&mut user_a, &mut user_b).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The sheep waited patiently in the field");
    //         let description = String::from("Sheep have no patience");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // Get available proofs as b and check 0 returned
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         assert_eq!(proofs.len(), 0, "No proofs should be available");

    //         // Add relationship from b to a
    //         _ = add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Get available proofs as b and check can prove
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         assert_eq!(proofs.len(), 1, "Proof should be available");
    //         let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert_eq!(code, Status::Created.code, "Proof should be created");
    //     }

    //     #[rocket::async_test]
    //     async fn test_reject_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // create users
    //         let mut user_a = GrapevineAccount::new(String::from("user_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_b"));
    //         _ = create_user_request(&context, &user_a.create_user_request()).await;
    //         _ = create_user_request(&context, &user_b.create_user_request()).await;

    //         // send pending relationship request from a to b
    //         _ = add_relationship_request(&mut user_a, &mut user_b).await;
    //         // retrieve pending relationships as b
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             1,
    //             "User B should have one pending relationship"
    //         );
    //         assert_eq!(
    //             pending_relationships.get(0).unwrap(),
    //             user_a.username(),
    //             "User A should be pending relationship"
    //         );
    //         // reject relationship from b to a
    //         let (code, _) = reject_relationship_request(&context, &mut user_b, user_a.username()).await;
    //         assert_eq!(code, Status::Ok.code, "Relationship should be rejected");
    //         // show request was removed from pending relationship
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             0,
    //             "User B should have one pending relationship"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_pending_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_5_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_5_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;

    //         let (code, msg_res) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Conflict.code,
    //             "Relationship should be a conflict"
    //         );
    //         let msg = msg_res.unwrap();
    //         let condition = msg.contains("PendingRelationshipExists")
    //             && msg.contains("user_relationship_5_a")
    //             && msg.contains("user_relationship_5_b");
    //         assert!(condition, "Duplicate pending relationships cannot exist.");
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_active_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_5_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_5_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         let (code, msg_res) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Conflict.code,
    //             "Relationship should be a conflict"
    //         );
    //         let msg = msg_res.unwrap();
    //         let condition = msg.contains("ActiveRelationshipExists")
    //             && msg.contains("user_relationship_5_a")
    //             && msg.contains("user_relationship_5_b");
    //         assert!(condition, "Duplicate active relationships cannot exist.");
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_phrase() {
    //         // initialize context
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // add user
    //         let mut user = GrapevineAccount::new(String::from("user"));
    //         create_user_request(&context, &user.create_user_request()).await;

    //         // create & prove phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a description");
    //         _ = phrase_request(&phrase, description.clone(), &mut user).await;

    //         // attempt to create & prove a duplicate phrase
    //         let (code, msg) = phrase_request(&phrase, description, &mut user).await;
    //         assert!(
    //             msg.contains("DegreeProofExists"),
    //             "Duplicate phrase should be prevented from being added",
    //         );
    //         assert!(
    //             code == Status::Conflict.code,
    //             "Duplicate phrase should return a 409 status code",
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_multiple_degree_1() {
    //         // initialize context
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // add users
    //         let mut user1 = GrapevineAccount::new(String::from("user1"));
    //         let mut user2 = GrapevineAccount::new(String::from("user2"));
    //         create_user_request(&context, &user1.create_user_request()).await;
    //         create_user_request(&context, &user2.create_user_request()).await;

    //         // create phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a description");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut user1).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         // check that new phrase was created at index 1
    //         assert_eq!(data.phrase_index, 1);
    //         assert_eq!(data.new_phrase, true);

    //         // create phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a different description");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut user2).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         // check that existing phrase was proven at index 1
    //         assert_eq!(data.phrase_index, 1);
    //         assert_eq!(data.new_phrase, false);
    //     }

    //     #[rocket::async_test]
    //     async fn test_create_degree_proof_with_invalid_request_body() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let user = GrapevineAccount::new(String::from("user_degree_proof_1"));
    //         let request = user.create_user_request();

    //         create_user_request(&context, &request).await;

    //         let signature = user.sign_nonce();
    //         let encoded = hex::encode(signature.compress());

    //         let msg = context
    //             .client
    //             .post("/proof/degree")
    //             .header(Header::new("X-Authorization", encoded))
    //             .header(Header::new("X-Username", user.username().clone()))
    //             .body(vec![])
    //             .dispatch()
    //             .await
    //             .into_string()
    //             .await
    //             .unwrap();

    //         let condition = msg.contains("SerdeError") && msg.contains("DegreeProofRequest");
    //         assert!(
    //             condition,
    //             "Degree proof continuation should fail with invalid body"
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_degree_proof_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_2_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_2_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // prove 2nd degree separation as user b
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Degree proof should have been created"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_degree_proof() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_3_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_3_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // get proofs as user b
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();

    //         // prove degree 2 separation of phrase as user b
    //         create_degree_proof_request(&proofs[0], &mut user_b).await;

    //         // attempt to prove degree 2 separation of phrase as user b again
    //         let (_, msg) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert!(
    //             msg.unwrap().contains("DegreeProofExists"),
    //             "Cannot create a second degree proof between same accounts for same phrase"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_account_details() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context: GrapevineTestContext = GrapevineTestContext::init().await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("user_account_details_1")),
    //             GrapevineAccount::new(String::from("user_account_details_2")),
    //             GrapevineAccount::new(String::from("user_account_details_3")),
    //             GrapevineAccount::new(String::from("user_account_details_4")),
    //             GrapevineAccount::new(String::from("user_account_details_5")),
    //             GrapevineAccount::new(String::from("user_account_details_6")),
    //             GrapevineAccount::new(String::from("user_account_details_7")),
    //             GrapevineAccount::new(String::from("user_account_details_8")),
    //             GrapevineAccount::new(String::from("user_account_details_9")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_b = users.remove(0);
    //         let mut user_c = users.remove(0);
    //         let mut user_d = users.remove(0);
    //         let mut user_e = users.remove(0);
    //         let mut user_f = users.remove(0);
    //         let mut user_g = users.remove(0);
    //         let mut user_h = users.remove(0);
    //         let mut user_i = users.remove(0);

    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 0, "Phrase count should be 0");
    //         assert_eq!(details.1, 0, "First degree count should be 0");
    //         assert_eq!(details.2, 0, "Second degree count should be 0");

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 0, "First degree count should be 0");
    //         assert_eq!(details.2, 0, "Second degree count should be 0");

    //         // Add first degree connection and second degree connection
    //         add_relationship_request(&mut user_b, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_c, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_c).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 1, "First degree count should be 1");
    //         assert_eq!(details.2, 1, "Second degree count should be 1");

    //         // Add more second degree connections
    //         add_relationship_request(&mut user_d, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_d).await;
    //         add_relationship_request(&mut user_e, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_e).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 1, "First degree count should be 1");
    //         assert_eq!(details.2, 3, "Second degree count should be 3");

    //         // Second degree connections become first degree connections
    //         add_relationship_request(&mut user_d, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_d).await;
    //         add_relationship_request(&mut user_e, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_e).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 3, "First degree count should be 3");
    //         assert_eq!(details.2, 1, "Second degree count should be 1");

    //         // Test where 3 new degree 2 connections added at once
    //         add_relationship_request(&mut user_f, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_h).await;
    //         add_relationship_request(&mut user_h, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_i).await;
    //         add_relationship_request(&mut user_i, &mut user_f).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 4, "First degree count should be 3");
    //         assert_eq!(details.2, 4, "Second degree count should be 1");
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_phrase_connections() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut users: Vec<GrapevineAccount> = vec![];

    //         for i in 0..7 {
    //             let user =
    //                 GrapevineAccount::new(String::from(format!("user_account_details_{}", i + 1)));
    //             let request = user.create_user_request();
    //             create_user_request(&context, &request).await;
    //             users.push(user);
    //         }

    //         // create phrase 1
    //         let phrase = String::from("Where there's smoke there's fire");
    //         let description = String::from("5 alarm");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut users[0]).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         let connections = get_phrase_connection_request(&mut users[0], data.phrase_index)
    //             .await
    //             .unwrap();
    //         assert_eq!(connections.0, 0);
    //         assert_eq!(connections.1.len(), 0);
    //         // Create degree proofs and relationships
    //         for i in 0..users.len() - 3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_b = users.remove(0);
    //         let mut user_c = users.remove(0);
    //         let mut user_d = users.remove(0);
    //         let mut user_f = users.remove(1);
    //         let mut user_g = users.remove(1);

    //         // user_b <- user_c -> user_d
    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();
    //         // has 2 total connections
    //         assert_eq!(connections.0, 2);
    //         // not connected to user_a at 1st degree spot
    //         assert_eq!(*connections.1.get(0).unwrap(), 0);
    //         // user_b is is at 2nd degree spot, showing 1 2nd degree connection
    //         assert_eq!(*connections.1.get(1).unwrap(), 1);
    //         // user_c is not connected to themselves and no other 3rd degree connections
    //         assert_eq!(*connections.1.get(2).unwrap(), 0);
    //         // user d is at 4th degree spot, showing 1 4th degree connection
    //         assert_eq!(*connections.1.get(3).unwrap(), 1);
    //         // connection vector is length 4, implying no connections past degree 4
    //         assert_eq!(connections.1.len(), 4);

    //         add_relationship_request(&mut user_a, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_a).await;

    //         let proofs = get_available_degrees_request(&mut user_f).await.unwrap();
    //         // User F has proof of degree 2
    //         create_degree_proof_request(&proofs[0], &mut user_f).await;
    //         // User G has degree proof 3
    //         add_relationship_request(&mut user_b, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_b).await;

    //         let proofs = get_available_degrees_request(&mut user_g).await.unwrap();
    //         create_degree_proof_request(&proofs[0], &mut user_g).await;

    //         add_relationship_request(&mut user_c, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_d).await;
    //         add_relationship_request(&mut user_d, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_c).await;

    //         // User C should have:
    //         // * Connection to User A with proof of degree 1
    //         // * Connection to User B with proof of degree 2
    //         // * Connection to User D with proof of degree 4
    //         // * Connection to User F with proof of degree 2
    //         // * Connection to User G with proof of degree 3
    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();

    //         assert_eq!(connections.0, 5);
    //         assert_eq!(*connections.1.get(0).unwrap(), 1);
    //         assert_eq!(*connections.1.get(1).unwrap(), 2);
    //         assert_eq!(*connections.1.get(2).unwrap(), 1);
    //         assert_eq!(*connections.1.get(3).unwrap(), 1);
    //         assert_eq!(connections.1.len(), 4);

    //         // create phrase 2
    //         let phrase = String::from("Raindrops are falling on my head");
    //         let description = String::from("Get an umbrella ig");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut users[0]).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();

    //         assert_eq!(connections.0, 0);
    //         assert_eq!(connections.1.len(), 0);
    //     }
}
