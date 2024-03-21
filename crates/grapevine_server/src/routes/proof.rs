use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use crate::utils::PUBLIC_PARAMS;
use crate::{catchers::GrapevineResponse, guards::AuthenticatedUser};
use grapevine_circuits::{nova::verify_nova_proof, utils::decompress_proof};
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::responses::DegreeData;
use grapevine_common::{
    http::requests::{Degree1ProofRequest, DegreeNProofRequest, NewPhraseRequest},
    models::{DegreeProof, Phrase, ProvingData},
};
use mongodb::bson::oid::ObjectId;
use rocket::{
    data::ToByteUnit, http::Status, serde::json::Json, tokio::io::AsyncReadExt, Data, State,
};
use std::str::FromStr;

// /// POST REQUESTS ///

/**
 * Create a degree 1 proof (knowledge of phrase) for a phrase. Create new proof doc if exists
 *
 * @param data - binary serialized NewPhraseRequest containing:
 *             * hash: the hash of the phrase
 *             * ciphertext: the encrypted phrase
 *             * description: the description of the phrase
 *        
 * @return status:
 *             * 201 if success
 *             * 400 if deserialization fails
 *             * 401 if signature mismatch or nonce mismatch
 *             * 404 if user not found
 *             * 409 if phrase already exists
 *             * 500 if db fails or other unknown issue
 */
#[post("/phrase", data = "<data>")]
pub async fn create_phrase(
    _user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<Json<u32>, GrapevineResponse> {
    // stream in data
    // todo: implement FromData trait on NewPhraseRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
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

    // check if phrase already exists in db
    match db.get_phrase_by_hash(&request.hash).await {
        Ok(_) => {
            return Err(GrapevineResponse::Conflict(ErrorMessage(
                Some(GrapevineServerError::PhraseExists),
                None,
            )))
        }
        Err(e) => match e {
            GrapevineServerError::PhraseNotFound => (),
            _ => {
                return Err(GrapevineResponse::InternalError(ErrorMessage(
                    Some(e),
                    None,
                )))
            }
        },
    };

    // create the new phrase
    match db.create_phrase(request.hash, request.description).await {
        Ok(res) => Ok(Json(res)),
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
 * Prove knowledge of an existing phrase and create a 1st degree proof
 */
#[post("/knowledge", data = "<data>")]
pub async fn knowledge_proof(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<Status, GrapevineResponse> {
    // stream in data
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(_) = stream.read_to_end(&mut buffer).await {
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<Degree1ProofRequest>(&buffer) {
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

    // check that the phrase exists for the given ID
    let phrase_oid = match db.get_phrase_by_index(request.index).await {
        Ok(phrase) => phrase,
        Err(_) => {
            return Err(GrapevineResponse::NotFound(format!(
                "No phrase found with id {}",
                request.index
            )))
        }
    };

    // verify the proof
    let decompressed_proof = decompress_proof(&request.proof);
    let verify_res = verify_nova_proof(
        &decompressed_proof,
        &*PUBLIC_PARAMS,
        2, // always 2 on first degree proof
    );
    let auth_hash = match verify_res {
        Ok(res) => res.0[2].to_bytes(),
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
    // build DegreeProof model
    let proof_doc = DegreeProof {
        id: None,
        inactive: Some(false),
        phrase: Some(phrase_oid),
        auth_hash: Some(auth_hash),
        user: Some(user.id.unwrap()),
        degree: Some(1),
        ciphertext: Some(request.ciphertext),
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
#[post("/degree", data = "<data>")]
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
    let request = match bincode::deserialize::<DegreeNProofRequest>(&buffer) {
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

    // verify the proof
    let decompressed_proof = decompress_proof(&request.proof);
    let verify_res = verify_nova_proof(
        &decompressed_proof,
        &*PUBLIC_PARAMS,
        (request.degree * 2) as usize,
    );
    let (phrase_hash, auth_hash) = match verify_res {
        Ok(res) => (res.0[1].to_bytes(), res.0[2].to_bytes()),
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineServerError::DegreeProofVerificationFailed),
                None,
            )));
        }
    };

    // get the phrase oid from the hash
    let phrase_oid = match db.get_phrase_by_hash(&phrase_hash).await {
        Ok(phrase) => phrase,
        Err(_) => {
            return Err(GrapevineResponse::NotFound(format!(
                "No phrase found with hash {:?}",
                &phrase_hash
            )))
        }
    };

    // get user doc
    let user = db.get_user(&user.0).await.unwrap();
    // @TODO: needs to delete a previous proof by same user on same phrase hash if exists, including removing from last proof's previous field
    // build DegreeProof struct
    let proof_doc = DegreeProof {
        id: None,
        inactive: Some(false),
        phrase: Some(phrase_oid),
        auth_hash: Some(auth_hash),
        user: Some(user.id.unwrap()),
        degree: Some(request.degree),
        ciphertext: None,
        proof: Some(request.proof.clone()),
        preceding: Some(ObjectId::from_str(&request.previous).unwrap()),
        proceeding: Some(vec![]),
    };

    // check to see that degree proof doesn't already exist between two accounts
    match db.check_degree_exists(&proof_doc).await {
        Ok(exists) => match exists {
            true => {
                return Err(GrapevineResponse::Conflict(ErrorMessage(
                    Some(GrapevineServerError::DegreeProofExists),
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

/**
 * Get all created phrases
 */
#[get("/created")]
pub async fn get_created_phrases(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<DegreeData>>, GrapevineResponse> {
    match db.get_created(user.0).await {
        Some(proofs) => Ok(Json(proofs)),
        None => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(GrapevineServerError::MongoError(String::from(
                "Error retrieving degrees in db",
            ))),
            None,
        ))),
    }
}

/**
 * Get total number of connections and
 */
#[get("/connections/<phrase_index>")]
pub async fn get_phrase_connections(
    user: AuthenticatedUser,
    phrase_index: u32,
    db: &State<GrapevineDB>,
) -> Result<Json<(u64, Vec<u64>)>, GrapevineResponse> {
    // check if phrase exists in db
    match db.get_phrase_by_index(phrase_index).await {
        Ok(_) => (),
        Err(e) => match e {
            GrapevineServerError::PhraseNotFound => {
                return Err(GrapevineResponse::NotFound(format!(
                    "No phrase found with id {}",
                    phrase_index
                )));
            }
            _ => {
                return Err(GrapevineResponse::InternalError(ErrorMessage(
                    Some(e),
                    None,
                )))
            }
        },
    }

    // retrieve all connections for the given phrase
    match db.get_phrase_connections(user.0, phrase_index).await {
        Some(connection_data) => Ok(Json(connection_data)),
        None => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(GrapevineServerError::MongoError(String::from(
                "Error retrieving degrees in db",
            ))),
            None,
        ))),
    }
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
