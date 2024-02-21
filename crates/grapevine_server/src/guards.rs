use crate::catchers::ErrorMessage;
use grapevine_common::errors::GrapevineServerError;
use crate::mongo::GrapevineDB;
use babyjubjub_rs::{decompress_point, decompress_signature, verify};
use grapevine_common::crypto::nonce_hash;
use num_bigint::{BigInt, Sign};
use rocket::{
    http::Status,
    outcome::Outcome::{Error as Failure, Success},
    request::{FromRequest, Outcome, Request},
    State,
};

/** A username passed through header that passes the signed nonce check */
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ErrorMessage;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Connect to mongodb
        let mongo = match request.guard::<&State<GrapevineDB>>().await {
            Success(db) => db,
            _ => {
                return Failure((
                    Status::InternalServerError,
                    ErrorMessage(
                        Some(GrapevineServerError::MongoError(String::from(
                            "Error connecting to database",
                        ))),
                        None,
                    ),
                ));
            }
        };
        // Check for X-Username header
        let username = match request.headers().get_one("X-Username") {
            Some(username) => String::from(username),
            None => {
                return Failure((
                    Status::BadRequest,
                    ErrorMessage(
                        Some(GrapevineServerError::HeaderError(String::from(
                            "couldn't find X-Username",
                        ))),
                        None,
                    ),
                ));
            }
        };
        // Check for X-Authorization header (signature over nonce)
        let signature = match request.headers().get_one("X-Authorization") {
            Some(data) => {
                // attempt to parse the signature
                let bytes: [u8; 64] = hex::decode(data).unwrap().try_into().unwrap();
                match decompress_signature(&bytes) {
                    Ok(signature) => signature,
                    Err(_) => {
                        return Failure((
                            Status::BadRequest,
                            ErrorMessage(
                                Some(GrapevineServerError::HeaderError(String::from(
                                    "couldn't parse X-Authorization",
                                ))),
                                None,
                            ),
                        ));
                    }
                }
            }
            None => {
                return Failure((
                    Status::BadRequest,
                    ErrorMessage(
                        Some(GrapevineServerError::HeaderError(String::from(
                            "couldn't find X-Authorization",
                        ))),
                        None,
                    ),
                ));
            }
        };
        // Retrieve nonce from database
        let (nonce, pubkey) = match mongo.get_nonce(&username).await {
            Some(data) => data,
            None => {
                return Failure((
                    Status::NotFound,
                    ErrorMessage(Some(GrapevineServerError::UserNotFound(username)), None),
                ));
            }
        };
        // convert pubkey to bjj point (assumes won't fail due to other checks)
        let pubkey = decompress_point(pubkey).unwrap();
        // Take the sha256 hash of the nonce and username, and convert to bjj message format
        let message = BigInt::from_bytes_le(Sign::Plus, &nonce_hash(&username, nonce));
        // Check that signature matches expected nonce/ username hash
        match verify(pubkey, signature, message) {
            true => (),
            false => {
                return Failure((
                    Status::Unauthorized,
                    ErrorMessage(
                        Some(GrapevineServerError::Signature(String::from(
                            "Failed to verify nonce signature",
                        ))),
                        Some(nonce),
                    ),
                ));
            }
        };
        // Increment nonce in database
        match mongo.increment_nonce(&username).await {
            Ok(_) => Success(AuthenticatedUser(username)),
            Err(_) => Failure((
                Status::InternalServerError,
                ErrorMessage(
                    Some(GrapevineServerError::MongoError(String::from(
                        "Error incrementing nonce",
                    ))),
                    None,
                ),
            )),
        }
    }
}
