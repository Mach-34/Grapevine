use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use crate::utils::PUBLIC_PARAMS;
use crate::{catchers::GrapevineResponse, guards::AuthenticatedUser};
use grapevine_circuits::{nova::verify_nova_proof, utils::decompress_proof};
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::{
    http::requests::{DegreeProofRequest, NewPhraseRequest},
    models::proof::{DegreeProof, ProvingData},
};
use mongodb::bson::oid::ObjectId;
use rocket::{
    data::ToByteUnit, http::Status, serde::json::Json, tokio::io::AsyncReadExt, Data, State,
};
use std::str::FromStr;

// /// POST REQUESTS ///

/**
 * Create a new phrase and (a degree 1 proof) and add it to the database
 *
 * @param data - binary serialized NewPhraseRequest containing:
 *             * username: the username of the user creating the phrase
 *             * proof: the gzip-compressed fold proof
 *        
 * @return status:
 *             * 201 if success
 *             * 400 if proof verification failed, deserialization fails, or proof decompression
 *               fails
 *             * 401 if signature mismatch or nonce mismatch
 *             * 404 if user not found
 *             * 500 if db fails or other unknown issue
 */
#[post("/create", data = "<data>")]
pub async fn create_phrase(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<Status, GrapevineResponse> {
    // stream in data
    // todo: implement FromData trait on NewPhraseRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
                                               // @TODO: Stream in excess of 2 megabytes not actually throwing error
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        println!("Error reading request body: {:?}", e);
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<NewPhraseRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to NewPhraseRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineServerError::SerdeError(String::from(
                    "NewPhraseRequest",
                ))),
                None,
            )));
        }
    };
    // @TODO: No decompression error set up in case invalid
    let decompressed_proof = decompress_proof(&request.proof);
    // verify the proof
    let verify_res = verify_nova_proof(&decompressed_proof, &*PUBLIC_PARAMS, 2);
    let (phrase_hash, auth_hash) = match verify_res {
        Ok(res) => {
            let phrase_hash = res.0[1];
            let auth_hash = res.0[2];
            // todo: use request guard to check username against proven username
            (phrase_hash.to_bytes(), auth_hash.to_bytes())
        }
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineServerError::DegreeProofVerificationFailed),
                None,
            )));
        }
    };

    // check if phrase already exists in db
    match db.check_phrase_exists(phrase_hash).await {
        Ok(exists) => match exists {
            true => {
                return Err(GrapevineResponse::BadRequest(ErrorMessage(
                    Some(GrapevineServerError::PhraseExists),
                    None,
                )))
            }
            false => (),
        },
        Err(e) => {
            return Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(e),
                None,
            )));
        }
    }

    // get user doc
    let user = db.get_user(&user.0).await.unwrap();
    // build DegreeProof model
    let proof_doc = DegreeProof {
        id: None,
        inactive: Some(false),
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
        Err(e) => {
            println!("Error adding proof: {:?}", e);
            Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(GrapevineServerError::MongoError(String::from(
                    "Failed to add proof to db",
                ))),
                None,
            )))
        }
    }
}

/**
 * Build from a previous degree of connection proof and add it to the database
 *
 * @param data - binary serialized DegreeProofRequest containing:
 *             * username: the username of the user adding a proof of degree of connection
 *             * proof: the gzip-compressed fold proof
 *             * previous: the stringified OID of the previous proof to continue IVC from
 *             * degree: the separation degree of the given proof
 * @return status:
 *             * 201 if successful proof update
 *             * 400 if proof verification failed, deserialization fails, or proof decompression
 *               fails
 *             * 401 if signature mismatch or nonce mismatch
 *             * 404 if user or previous proof not found not found
 *             * 500 if db fails or other unknown issue
 */
#[post("/continue", data = "<data>")]
pub async fn degree_proof(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<Status, GrapevineResponse> {
    // stream in data
    // todo: implement FromData trait on DegreeProofRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(_) = stream.read_to_end(&mut buffer).await {
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<DegreeProofRequest>(&buffer) {
        Ok(req) => req,
        Err(_) => {
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineServerError::SerdeError(String::from(
                    "DegreeProofRequest",
                ))),
                None,
            )))
        }
    };
    let decompressed_proof = decompress_proof(&request.proof);
    // verify the proof
    let verify_res = verify_nova_proof(
        &decompressed_proof,
        &*PUBLIC_PARAMS,
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
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineServerError::DegreeProofVerificationFailed),
                None,
            )));
        }
    };
    // get user doc
    let user = db.get_user(&user.0).await.unwrap();
    // @TODO: needs to delete a previous proof by same user on same phrase hash if exists, including removing from last proof's previous field
    // build DegreeProof struct
    let proof_doc = DegreeProof {
        id: None,
        inactive: Some(false),
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
        Err(e) => {
            println!("Error adding proof: {:?}", e);
            Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(GrapevineServerError::MongoError(String::from(
                    "Failed to add proof to db",
                ))),
                None,
            )))
        }
    }
}

/// GET REQUESTS ///

/**
 * Return a list of all available (new) degree proofs from existing connections that a user can
 * build from
 *
 * @param username - the username to look up the available proofs for
 * @return - a vector of stringified OIDs of available proofs to use with get_proof_with_params
 *           route (empty if none)
 * @return status:
 *         - 200 if successful retrieval
 *         - 401 if signature mismatch or nonce mismatch
 *         - 404 if user not found
 *         - 500 if db fails or other unknown issue
 */
#[get("/available")]
pub async fn get_available_proofs(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, Status> {
    Ok(Json(db.find_available_degrees(user.0).await))
}

/**
 * Returns all the information needed to construct a proof of degree of separation from a given user
 *
 * @param oid - the ObjectID of the proof to retrieve
 * @param username - the username to retrieve encrypted auth secret for when proving relationship
 * @return - a ProvingData struct containing:
 *         * degree: the separation degree of the returned proof
 *         * proof: the gzip-compressed fold proof
 *         * username: the username of the proof creator
 *         * ephemeral_key: the ephemeral pubkey that can be combined with the requesting user's
 *           private key to derive returned proof creator's auth secret decryption key
 *         * ciphertext: the encrypted auth secret
 * @return status:
 *         - 200 if successful retrieval
 *         - 401 if signature mismatch or nonce mismatch
 *         - 404 if username or proof not found
 *         - 500 if db fails or other unknown issue
 */

#[get("/params/<oid>")]
pub async fn get_proof_with_params(
    user: AuthenticatedUser,
    oid: String,
    db: &State<GrapevineDB>,
) -> Result<Json<ProvingData>, GrapevineResponse> {
    let oid = ObjectId::from_str(&oid).unwrap();
    match db.get_proof_and_data(user.0, oid).await {
        Some(data) => Ok(Json(data)),
        None => Err(GrapevineResponse::NotFound(format!(
            "No proof found with oid {}",
            oid
        ))),
    }
}

/**
 * Return a list of all proofs linked to a given phrase hash
 *
 *
 * @param phrase hash - the hash of the phrase creating the proof chain
 * @return - a vector of stringified OIDs of proofs within the given chain
 * @return status:
 *         - 200 if successful retrieval
 *         - 401 if signature mismatch or nonce mismatch
 *         - 404 if user not found
 *         - 500 if db fails or other unknown issue
 */
#[get("/chain/<phrase_hash>")]
pub async fn get_proof_chain(
    phrase_hash: String,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<DegreeProof>>, Status> {
    Ok(Json(db.get_proof_chain(&phrase_hash).await))
}

// /**
//  * Returns all the information needed to construct a proof of degree of separation from a given user
//  */
// #[get("/proofs")]
// pub async fn get_proof_ids(db: &State<GrapevineDB>) -> Result<Json<ProvingData>, Response> {
//     let oid = ObjectId::from_str(&oid).unwrap();
//     match db.get_proof_and_data(username, oid).await {
//         Some(data) => Ok(Json(data)),
//         None => Err(Response::NotFound(format!(
//             "No proof found with oid {}",
//             oid
//         ))),
//     }
// }
