use crate::mongo::GrapevineDB;
use crate::utils::use_public_params;
use babyjubjub_rs::{decompress_point, decompress_signature, verify};
use grapevine_circuits::{nova::verify_nova_proof, utils::decompress_proof};
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::{
    requests::{CreateUserRequest, DegreeProofRequest},
    responses::DegreeData,
};
use grapevine_common::utils::convert_username_to_fr;
use grapevine_common::MAX_USERNAME_CHARS;
use grapevine_common::{
    http::requests::{NewPhraseRequest, NewRelationshipRequest},
    models::{
        proof::{DegreeProof, ProvingData},
        relationship::Relationship,
        user::User,
    },
};
use mongodb::bson::oid::ObjectId;
use num_bigint::{BigInt, Sign};
use rocket::data::{FromData, ToByteUnit};
use rocket::http::Status;
use rocket::response::status::{self, NotFound};
use rocket::serde::json::Json;
use rocket::tokio::io::AsyncReadExt;
use rocket::{request, response, Data, Request, State};
use std::io::{self, Write};
use std::ops::Not;
use std::str::FromStr;

/**
 * Attempts to create a new user
 *
 * @param username - the username for the new user
 * @param pubkey - the public key used to authenticate API access for the user
 * @param signature - the signature over the username by pubkey
 * @param auth_secret - the encrypted auth secret used by this user (encrypted with given pubkey)
 */
#[post("/user/create", format = "json", data = "<request>")]
pub async fn create_user(
    request: Json<CreateUserRequest>,
    db: &State<GrapevineDB>,
) -> Result<Status, Status> {
    // check the validity of the signature over the username
    let message = BigInt::from_bytes_le(
        Sign::Plus,
        &convert_username_to_fr(&request.username).unwrap()[..],
    );
    let pubkey_decompressed = decompress_point(request.pubkey).unwrap();
    let signature_decompressed = decompress_signature(&request.signature).unwrap();
    match verify(pubkey_decompressed, signature_decompressed, message) {
        true => (),
        false => {
            // return Err(GrapevineServerError::Signature(
            //     "Signature by pubkey does not match given message".to_string(),
            // ))
            return Err(Status::Unauthorized);
        }
    };
    // check username length is valid
    if !request.username.len() <= MAX_USERNAME_CHARS {
        return Err(Status::BadRequest);
        // return Err(GrapevineServerError::UsernameTooLong(
        //     request.username.clone(),
        // ));
    };
    // check the username is ascii
    if !request.username.is_ascii() {
        return Err(Status::BadRequest);
        // return Err(GrapevineServerError::UsernameNotAscii(
        //     request.username.clone(),
        // ));
    };
    // check that the username or pubkey are not already used
    match db
        .check_creation_params(&request.username, &request.pubkey)
        .await
    {
        Ok(found) => {
            let error_msg = match found {
                [true, true] => "Both Username and Pubkey already exist",
                [true, false] => "Username already exists",
                [false, true] => "Pubkey already exists",
                _ => "",
            };
            if found[0] || found[1] {
                // return Err(GrapevineServerError::UserExists(String::from(error_msg)));
                return Err(Status::Conflict);
            }
        }
        Err(e) => return Err(Status::NotImplemented),
    };
    // create the new user in the database
    let user = User {
        id: None,
        nonce: Some(0),
        username: Some(request.username.clone()),
        pubkey: Some(request.pubkey.clone()),
        relationships: Some(vec![]),
        degree_proofs: Some(vec![]),
    };
    match db.create_user(user).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => Err(Status::NotImplemented),
    }
}

#[post("/phrase/create", data = "<data>")]
pub async fn create_phrase(data: Data<'_>, db: &State<GrapevineDB>) -> Result<Status, Status> {
    // stream in data
    // todo: implement FromData trait on NewPhraseRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        return Err(Status::BadRequest);
    }
    let request = match bincode::deserialize::<NewPhraseRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => return Err(Status::BadRequest),
    };
    let decompressed_proof = decompress_proof(&request.proof);
    // verify the proof
    let public_params = use_public_params().unwrap();
    println!("Try Verify");
    let verify_res = verify_nova_proof(&decompressed_proof, &public_params, 2);
    let (phrase_hash, auth_hash) = match verify_res {
        Ok(res) => {
            let phrase_hash = res.0[1];
            let auth_hash = res.0[2];
            // todo: use request guard to check username against proven username
            (phrase_hash.to_bytes(), auth_hash.to_bytes())
        }
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(Status::BadRequest);
        }
    };
    // get user doc
    let user = db.get_user(request.username.clone()).await.unwrap();
    println!("User: {:?}", user);
    // @TODO: handle user does not exist
    // build DegreeProof model
    let proof_doc = DegreeProof {
        id: None,
        phrase_hash: Some(phrase_hash),
        auth_hash: Some(auth_hash),
        user: Some(user.id.unwrap()),
        degree: Some(1),
        proof: Some(request.proof.clone()),
        preceding: None,
        proceeding: Some(vec![]),
    };

    match db.add_proof(&user.id.unwrap(), &proof_doc).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => Err(Status::NotImplemented),
    }
}

#[post("/phrase/continue", data = "<data>")]
pub async fn degree_proof(data: Data<'_>, db: &State<GrapevineDB>) -> Result<Status, Status> {
    // stream in data
    // todo: implement FromData trait on NewPhraseRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        return Err(Status::BadRequest);
    }
    let request = match bincode::deserialize::<DegreeProofRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => return Err(Status::BadRequest),
    };
    let decompressed_proof = decompress_proof(&request.proof);
    // verify the proof
    let public_params = use_public_params().unwrap();
    let verify_res = verify_nova_proof(
        &decompressed_proof,
        &public_params,
        (request.degree * 2) as usize,
    );
    let (phrase_hash, auth_hash) = match verify_res {
        Ok(res) => {
            let phrase_hash = res.0[1];
            let auth_hash = res.0[2];
            (phrase_hash.to_bytes(), auth_hash.to_bytes())
        }
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(Status::BadRequest);
        }
    };
    // get user doc
    let user = db.get_user(request.username.clone()).await.unwrap();
    // @TODO: needs to delete a previous proof by same user on same phrase hash if exists, including removing from last proof's previous field
    // build DegreeProof model
    let proof_doc = DegreeProof {
        id: None,
        phrase_hash: Some(phrase_hash),
        auth_hash: Some(auth_hash),
        user: Some(user.id.unwrap()),
        degree: Some(request.degree),
        proof: Some(request.proof.clone()),
        preceding: Some(ObjectId::from_str(&request.previous).unwrap()),
        proceeding: Some(vec![]),
    };

    // add proof to db and update references
    match db.add_proof(&user.id.unwrap(), &proof_doc).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => Err(Status::NotImplemented),
    }
}

#[post("/user/relationship", format = "json", data = "<request>")]
pub async fn add_relationship(
    request: Json<NewRelationshipRequest>,
    db: &State<GrapevineDB>,
) -> Result<Status, Status> {
    // ensure from != to
    if &request.from == &request.to {
        return Err(Status::BadRequest);
    }
    // ensure user exists
    let sender = match db.get_user(request.from.clone()).await {
        Some(user) => user.id.unwrap(),
        None => return Err(Status::NotFound),
    };
    // would be nice to have a zk proof of correct encryption to recipient...
    let recipient = match db.get_user(request.to.clone()).await {
        Some(user) => user.id.unwrap(),
        None => return Err(Status::NotFound),
    };
    // add relationship doc and push to recipient array
    let relationship_doc = Relationship {
        id: None,
        sender: Some(sender),
        recipient: Some(recipient),
        ephemeral_key: Some(request.ephemeral_key.clone()),
        ciphertext: Some(request.ciphertext.clone()),
    };

    match db.add_relationship(&relationship_doc).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => Err(Status::NotImplemented),
    }
}

#[get("/user/<username>")]
pub async fn get_user(
    username: String,
    db: &State<GrapevineDB>,
) -> Result<Json<User>, NotFound<String>> {
    match db.get_user(username).await {
        Some(user) => Ok(Json(user)),
        None => Err(NotFound("User not does not exist.".to_string())),
    }
}

#[get("/user/<username>/pubkey")]
pub async fn get_pubkey(
    username: String,
    db: &State<GrapevineDB>,
) -> Result<String, NotFound<String>> {
    match db.get_pubkey(username).await {
        Some(pubkey) => Ok(hex::encode(pubkey)),
        None => Err(NotFound("User not does not exist.".to_string())),
    }
}

// #[get("/proof/username/<oid>")]
// pub async fn get_proof(oid: String, db: &State<GrapevineDB>) -> Result<Json<DegreeProof>, Status> {
//     let oid = ObjectId::from_str(&oid).unwrap();
//     match db.get_proof(&oid).await {
//         Some(proof) => Ok(Json(proof)),
//         None => Err(Status::NotFound),
//     }
// }

#[get("/proof/<username>/available")]
pub async fn get_available_proofs(
    username: String,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, Status> {
    Ok(Json(db.find_available_degrees(username).await))
}

#[get("/user/<username>/degrees")]
pub async fn get_all_degrees(
    username: String,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<DegreeData>>, Status> {
    match db.get_all_degrees(username).await {
        Some(proofs) => Ok(Json(proofs)),
        None => Err(Status::NotFound),
    }
}

// returns auth secret and proof data
#[get("/proof/<oid>/params/<username>")]
pub async fn get_proof_with_params(
    oid: String,
    username: String,
    db: &State<GrapevineDB>,
) -> Result<Json<ProvingData>, Status> {
    let oid = ObjectId::from_str(&oid).unwrap();
    match db.get_proof_and_data(username, oid).await {
        Some(data) => Ok(Json(data)),
        None => Err(Status::NotFound),
    }
}
