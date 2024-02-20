use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use babyjubjub_rs::{decompress_point, decompress_signature};
use grapevine_common::crypto::nonce_hash;
use num_bigint::{BigInt, Sign};
use rocket::{
    http::Status,
    outcome::Outcome::{Error, Success},
    request::{FromRequest, Outcome, Request},
    response::status::BadRequest,
    State,
};
use serde_json::json;

/** A username passed through header that passes the signed nonce check */
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(String);

// #[rocket::async_trait]
// impl<'r> FromRequest<'r> for AuthenticatedUser {
//     type Error = ();

//     async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
//         // Connect to mongodb
//         let mongo = match request.guard::<&State<GrapevineDB>>().await {
//             Success(db) => db,
//             Error(_) => {
//                 request.local_cache(|| {
//                     ErrorMessage(Some(String::from("Error connecting to database")))
//                 });
//                 return Error((Status::InternalServerError, ()));
//             }
//         };
//         // Check for X-Username header
//         let username = match request.headers().get_one("X-Username") {
//             Some(username) => String::from(username),
//             None => {
//                 request
//                     .local_cache(|| ErrorMessage(Some(String::from("Missing X-Username header"))));
//                 return Error((Status::BadRequest, ()));
//             }
//         };
//         // Check for X-Authorization header (signature over nonce)
//         let signature = match request.headers().get_one("X-Authorization") {
//             Some(data) => {
//                 // attempt to parse the signature
//                 let bytes: [u8; 64] = hex::decode(data).unwrap().try_into(); // todo: handle error
//                                                                              // parse into bjj signature
//                 match decompress_signature(&bytes) {
//                     Ok(signature) => signature,
//                     Err(_) => {
//                         request.local_cache(|| {
//                             ErrorMessage(Some(String::from(
//                                 "Error parsing signature from X-Authorization",
//                             )))
//                         });
//                         return Error((Status::BadRequest, ()));
//                     }
//                 }
//             }
//             None => {
//                 request.local_cache(|| {
//                     ErrorMessage(Some(String::from("Missing X-Authorization header")))
//                 });
//                 return Error((Status::BadRequest, ()));
//             }
//         };
//         // Retrieve nonce from database
//         let (nonce, pubkey) = match mongo.get_nonce(&username).await {
//             Some(data) => data,
//             None => {
//                 request.local_cache(|| ErrorMessage(Some(format!("User {} not found", username))));
//                 return Error((Status::NotFound, ()));
//             }
//         };
//         // convert pubkey to bjj point (assumes won't fail due to other checks)
//         let pubkey = decompress_point(&pubkey).unwrap();
//         // Take the sha256 hash of the nonce and username, and convert to bjj message format
//         let message = BigInt::from_bytes_le(Sign::Plus, &nonce_hash(nonce, username[..]));
//         // Check that signature matches expected nonce/ username hash
//         let outcome = match signature.verify(pubkey, message) {
//             true => Success(AuthenticatedUser(username)),
//             false => {
//                 request.local_cache(|| {
//                     ErrorMessage(Some(format!(
//                         "Signature does not match nonce and username. Expected nonce '{}'",
//                         nonce
//                     )))
//                 });
//                 return Error((Status::Unauthorized, ()))
//             }
//         };
//         // Increment nonce in database
//     }

// async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
//     let mongo_request = request.guard::<&State<GrapevineDB>>().await;
//     let mongo = mongo_request.unwrap();
//     let auth_string: Option<&str> = request.headers().get_one("X-Authorization");
//     if auth_string.is_some() {
//         let split_auth: Vec<&str> = auth_string.unwrap().split("-").collect();
//         if split_auth.len() == 2 {
//             let username = split_auth[0];
//             // #### TODO: Switch nonce to signature ####
//             let nonce: u64 = split_auth[1].parse().expect("Not a valid number.");
//             let mongo_nonce = mongo.get_nonce(username).await;

//             // #### TODO: Put signature verifiaction here ####

//             if mongo_nonce.is_none() {
//                 // User does not exist
//                 let err_msg = format!("User {} not found", username);
//                 request.local_cache(|| ErrorMessage(Some(err_msg)));
//                 Failure((Status::NotFound, ()))
//             } else {
//                 let stored_nonce = mongo_nonce.unwrap();
//                 // #### TODO: Switch with verified signature ####
//                 match stored_nonce == nonce {
//                     true => {
//                         // Increment nonce
//                         mongo.increment_nonce(username).await;
//                         return Success(NonceGuard { nonce });
//                     }

//                     // Incorrect nonce
//                     false => {
//                         let err_msg = format!(
//                             "Incorrect nonce provided. Expected {} and received {}",
//                             stored_nonce, nonce
//                         );
//                         request.local_cache(|| ErrorMessage(Some(err_msg)));
//                         return Failure((Status::BadRequest, ()));
//                     }
//                 }
//             }
//         } else {
//             // Improperly formatted authorization header
//             let err_msg = String::from("Malformed authorization header");
//             request.local_cache(|| ErrorMessage(Some(err_msg)));
//             Failure((Status::BadRequest, ()))
//         }
//     } else {
//         // Authorization header is missing
//         let err_msg = String::from("Missing authorization header");
//         request.local_cache(|| ErrorMessage(Some(err_msg)));
//         Failure((Status::Unauthorized, ()))
//     }
// }
// }
