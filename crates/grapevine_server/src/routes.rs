use crate::models::user::User;
use crate::mongo::MongoDB;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::requests::CreateUserRequest;
use grapevine_common::utils::convert_username_to_fr;
use grapevine_common::MAX_USERNAME_CHARS;
use mongodb::bson::oid::ObjectId;
use num_bigint::{BigInt, Sign};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::State;

#[post("/user/create", data = "<user_req>")]
pub async fn create_user(
    db: &State<MongoDB>,
    user_req: Json<CreateUserRequest>,
) -> Result<Json<ObjectId>, Status> {
    // check the username is not too long
    let username = user_req.0.username;
    match &username.len() <= &MAX_USERNAME_CHARS {
        true => (),
        false => {
            return Err((
                GrapevineServerError::UsernameTooLong(username.clone()),
                Status::BadRequest,
            ))
        }
    };
    // check the username is ascii
    match username.is_ascii() {
        true => (),
        false => {
            return Err((
                GrapevineServerError::UsernameNotAscii(username.clone()),
                Status::BadRequest,
            ))
        }
    };
    // deserialize the pubkey and signature & convert username to verifiable message format
    let pubkey = babyjubjub_rs::decompress_point(user_req.0.pubkey).unwrap();
    let signature = babyjubjub_rs::decompress_signature(&user_req.0.signature).unwrap();
    let msg = BigInt::from_bytes_le(Sign::Plus, &convert_username_to_fr(&username).unwrap()[..]);

    // verify the signature over the username by the pubkey
    match babyjubjub_rs::verify(pubkey, signature, msg) {
        true => (),
        false => {
            return Err(status::Custom(
                Status::BadRequest,
                GrapevineServerError::Signature(
                    "Could not create new user: error verifying signature by pubkey over username"
                        .to_string(),
                ),
            ))
        }
    };

    // attempt to create a new user in the db
    let user = User {
        id: None,
        username: username.clone(),
        pubkey: user_req.0.pubkey.clone(),
        auth_secret: user_req.0.auth_secret.clone(),
    };
    let res = db.create_user(user).await;
    match res {
        Ok(id) => Ok(Json(id)),
        Err(e) => Err((e, Status::BadRequest)),
    }
}


// /**
//  * Issues a new session key for a given username
//  * @notice - authed requests must produce a signature over the returned SessionData
//  *
//  * @param username - the username to issue a session key for
//  * @param pubkey - the public key associated with the username
//  * @param signature - the signature over the username by pubkey
//  * @param sessions - the in-memory session map
//  * @returns - the new session key if creation succeeded, or an error otherwise
//  */
// fn new_session(
//     username: String,
//     pubkey: [u8; 32],
//     signature: Signature,
//     sessions: &State<SessionMap>,
// ) -> Result<SessionKey, GrapevineServerError> {
//     match SessionKey::new(username.clone(), pubkey, signature) {
//         Ok(session) => {
//             let mut sessions = sessions.0.lock().unwrap();
//             // attempt to remove session if exists in map and discard error if not
//             sessions.remove(&username);
//             // insert the new session key (map username => session key)
//             sessions.insert(username, session.clone());
//             // return the session key to transmit to the client
//             Ok(session)
//         }
//         Err(e) => Err(e),
//     }
// }

// fn end_session(username: String, sessions: &State<SessionMap>) -> Result<(), GrapevineServerError> {

// }

// /**
//  * Authenticate a request by checking the signature over the session key
//  *
//  * @param username - the username of the user to authenticate a request for
//  * @param signature - the signature over the session key
//  */
// fn auth(username: String, signature: Signature) -> Result<(), GrapevineServerError> {
//     // get the session key for the given
// }
