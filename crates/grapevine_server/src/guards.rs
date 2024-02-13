use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use rocket::{
    http::Status,
    outcome::Outcome::{Error as Failure, Success},
    request::{FromRequest, Outcome, Request},
    response::status::BadRequest,
    State,
};
use serde_json::json;

pub struct NonceGuard {
    // pubkey: String,
    // TODO: Replace with signature
    nonce: u64,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NonceGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mongo_request = request.guard::<&State<GrapevineDB>>().await;
        let mongo = mongo_request.unwrap();
        let auth_string = request.headers().get_one("Authorization");
        if auth_string.is_some() {
            let split_auth: Vec<&str> = auth_string.unwrap().split("-").collect();
            if split_auth.len() == 2 {
                let username = split_auth[0];
                // #### TODO: Switch nonce to signature ####
                let nonce: u64 = split_auth[1].parse().expect("Not a valid number.");
                let mongo_nonce = mongo.get_nonce(username).await;

                // #### TODO: Put signature verifiaction here ####

                if mongo_nonce.is_none() {
                    // User does not exist
                    let err_msg = format!("User {} not found", username);
                    request.local_cache(|| ErrorMessage(Some(err_msg)));
                    Failure((Status::NotFound, ()))
                } else {
                    let stored_nonce = mongo_nonce.unwrap();
                    // #### TODO: Switch with verified signature ####
                    match stored_nonce == nonce {
                        true => {
                            // Increment nonce
                            mongo.increment_nonce(username).await;
                            return Success(NonceGuard { nonce });
                        }

                        // Incorrect nonce
                        false => {
                            let err_msg = format!(
                                "Incorrect nonce provided. Expected {} and received {}",
                                stored_nonce, nonce
                            );
                            request.local_cache(|| ErrorMessage(Some(err_msg)));
                            return Failure((Status::BadRequest, ()));
                        }
                    }
                }
            } else {
                // Improperly formatted authorization header
                let err_msg = String::from("Malformed authorization header");
                request.local_cache(|| ErrorMessage(Some(err_msg)));
                Failure((Status::BadRequest, ()))
            }
        } else {
            // Authorization header is missing
            let err_msg = String::from("Missing authorization header");
            request.local_cache(|| ErrorMessage(Some(err_msg)));
            Failure((Status::Unauthorized, ()))
        }
    }
}
