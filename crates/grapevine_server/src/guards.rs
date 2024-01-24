use crate::mongo::GrapvineMongo;
use rocket::{
    http::Status,
    outcome::Outcome::{Error as Failure, Success},
    request::{FromRequest, Outcome, Request},
    State,
};

pub struct NonceGuard {
    // pubkey: String,
    // TODO: Replace with signature
    nonce: u64,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NonceGuard {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let mongo_request = request.guard::<&State<GrapvineMongo>>().await;
        let mongo = mongo_request.unwrap();
        let auth_string = request.headers().get_one("Authorization");
        if auth_string.is_some() {
            let split: Vec<&str> = auth_string.unwrap().split("-").collect();
            if split.len() == 2 {
                let username = split[0];
                // #### TODO: Switch nonce to signature ####
                let nonce: u64 = split[1].parse().expect("Not a valid number.");
                let mongo_nonce = mongo.get_nonce(username).await;

                // #### TODO: Put signature verifiaction here ####

                if mongo_nonce == 0 {
                    // User does not exist
                    Failure((Status::NotFound, ()))
                } else {
                    // #### TODO: Switch with verified signature ####
                    match mongo_nonce as u64 == nonce {
                        true => {
                            // Increment nonce
                            mongo.increment_nonce(username).await;
                            return Success(NonceGuard { nonce });
                        }
                        // Mismatched nonce or public key
                        false => Failure((Status::BadRequest, ())),
                    }
                }
            } else {
                // Improperly formatted authorization header
                Failure((Status::BadRequest, ()))
            }
        } else {
            // Authorization header is missing
            // TODO: Add verbose messaging
            Failure((Status::BadRequest, ()))
        }
    }
}
