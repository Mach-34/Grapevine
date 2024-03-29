use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use crate::utils::PUBLIC_PARAMS;
use crate::{catchers::GrapevineResponse, guards::AuthenticatedUser};
use grapevine_circuits::{nova::verify_nova_proof, utils::decompress_proof};
use grapevine_common::errors::GrapevineError;
use grapevine_common::{
    http::{
        requests::{DegreeProofRequest, PhraseRequest},
        responses::{DegreeData, PhraseCreationResponse},
    },
    models::{DegreeProof, ProvingData},
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
pub async fn prove_phrase(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<GrapevineResponse, GrapevineResponse> {
    // stream in data
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        println!("Error reading request body: {:?}", e);
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<PhraseRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to PhraseRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
                    "NewPhraseRequest",
                ))),
                None,
            )));
        }
    };

    // verify the proof
    let decompressed_proof = decompress_proof(&request.proof);
    let verify_res = verify_nova_proof(&decompressed_proof, &*PUBLIC_PARAMS, 2);
    let (phrase_hash, auth_hash) = match verify_res {
        Ok(res) => (res.0[1].to_bytes(), res.0[2].to_bytes()),
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::DegreeProofVerificationFailed),
                None,
            )));
        }
    };

    // check if phrase exists in db
    let mut phrase_oid: Option<ObjectId> = match db.get_phrase_by_hash(&phrase_hash).await {
        Ok(oid) => Some(oid),
        Err(e) => match e {
            GrapevineError::PhraseNotFound => None,
            _ => {
                return Err(GrapevineResponse::InternalError(ErrorMessage(
                    Some(e),
                    None,
                )))
            }
        },
    };
    let exists = phrase_oid.is_some();

    // handle whether phrase exists or not
    let phrase_index = match exists {
        true => {
            // if phrase exists:
            // get the phrase index
            let index = match db.get_phrase_index(&phrase_oid.unwrap()).await {
                Ok(index) => index,
                Err(e) => {
                    println!("Error getting phrase index: {:?}", e);
                    return Err(GrapevineResponse::InternalError(ErrorMessage(
                        Some(e),
                        None,
                    )));
                }
            };
            // check that there is not a degree conflict
            match db.check_degree_conflict(&user.0, index, 1).await {
                Ok(conflict) => match conflict {
                    true => {
                        return Err(GrapevineResponse::Conflict(ErrorMessage(
                            Some(GrapevineError::DegreeProofExists),
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
            };
            index
        }
        false => {
            // if phrase does not exist, create it
            let (oid, index) = match db.create_phrase(phrase_hash, request.description).await {
                Ok(res) => res,
                Err(e) => {
                    println!("Error adding proof: {:?}", e);
                    return Err(GrapevineResponse::InternalError(ErrorMessage(
                        Some(e),
                        None,
                    )));
                }
            };
            phrase_oid = Some(oid);
            index
        }
    };

    // get user doc
    let user = db.get_user(&user.0).await.unwrap();
    // build DegreeProof model
    let proof_doc = DegreeProof {
        id: None,
        inactive: Some(false),
        phrase: phrase_oid,
        auth_hash: Some(auth_hash),
        user: Some(user.id.unwrap()),
        degree: Some(1),
        ciphertext: Some(request.ciphertext),
        proof: Some(request.proof.clone()),
        preceding: None,
        proceeding: Some(vec![]),
    };

    // Add the proof to the db
    match db.add_proof(&user.id.unwrap(), &proof_doc).await {
        Ok(_) => {
            let response_data = PhraseCreationResponse {
                phrase_index,
                new_phrase: !exists,
            };
            Ok(GrapevineResponse::Created(
                serde_json::to_string(&response_data).unwrap(),
            ))
        }
        Err(e) => {
            println!("Error adding proof: {:?}", e);
            Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(GrapevineError::MongoError(String::from(
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
    let request = match bincode::deserialize::<DegreeProofRequest>(&buffer) {
        Ok(req) => req,
        Err(_) => {
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
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
                Some(GrapevineError::DegreeProofVerificationFailed),
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
                    Some(GrapevineError::DegreeProofExists),
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
                Some(GrapevineError::MongoError(String::from(
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
 * Get all created phrases
 */
#[get("/known")]
pub async fn get_known_phrases(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<DegreeData>>, GrapevineResponse> {
    match db.get_known(user.0).await {
        Some(proofs) => Ok(Json(proofs)),
        None => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(GrapevineError::MongoError(String::from(
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
            GrapevineError::PhraseNotFound => {
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
            Some(GrapevineError::MongoError(String::from(
                "Error retrieving degrees in db",
            ))),
            None,
        ))),
    }
}

/**
 * Get all info about a phrase
 */
#[get("/phrase/<phrase_index>")]
pub async fn get_phrase(
    user: AuthenticatedUser,
    phrase_index: u32,
    db: &State<GrapevineDB>,
) -> Result<Json<DegreeData>, GrapevineResponse> {
    // check if phrase exists in db
    match db.get_phrase_by_index(phrase_index).await {
        Ok(_) => (),
        Err(e) => match e {
            GrapevineError::PhraseNotFound => {
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
    println!("2");
    // get degree data for this phrase
    match db.get_phrase_info(&user.0, phrase_index).await {
        Ok(phrase_data) => Ok(Json(phrase_data)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(e),
            None,
        ))),
    }
}
