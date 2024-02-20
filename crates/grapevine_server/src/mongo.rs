use std::f32::consts::E;

use crate::{DATABASE_NAME, MONGODB_URI};
use futures::stream::StreamExt;
use futures::TryStreamExt;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::proof::ProvingData;
use grapevine_common::models::{proof::DegreeProof, relationship::Relationship, user::User};
use mongodb::bson::document;
use mongodb::bson::{self, doc, oid::ObjectId, Binary};
use mongodb::options::{
    AggregateOptions, ClientOptions, DeleteOptions, FindOneAndDeleteOptions,
    FindOneAndUpdateOptions, FindOneOptions, FindOptions, ServerApi, ServerApiVersion,
};
use mongodb::{Client, Collection};

pub struct GrapevineDB {
    users: Collection<User>,
    relationships: Collection<Relationship>,
    degree_proofs: Collection<DegreeProof>,
}

impl GrapevineDB {
    pub async fn init() -> Self {
        let mut client_options = ClientOptions::parse(&**MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();
        let db = client.database(&**DATABASE_NAME);
        let users = db.collection("users");
        let relationships = db.collection("relationships");
        let degree_proofs = db.collection("degree_proofs");
        Self {
            users,
            relationships,
            degree_proofs,
        }
    }

    /**
     * Drops the entire database to start off with clean state for testing
     */
    pub async fn drop(database_name: &str) {
        let mut client_options = ClientOptions::parse(&**MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();

        client.database(database_name).drop(None).await.unwrap();
    }

    /// USER FUNCTIONS ///

    pub async fn increment_nonce(&self, username: &str) {
        let filter = doc! { "username": username };
        let update = doc! { "$inc": { "nonce": 1 } };
        self.users
            .update_one(filter, update, None)
            .await
            .expect("Error incrementing nonce");
    }

    pub async fn get_nonce(&self, username: &str) -> Option<(u64, [u8; 32])> {
        // Verify user existence
        let filter = doc! { "username": username };
        // TODO: Projection doesn't work without pubkey due to BSON deserialization error
        let projection = doc! { "nonce": 1, "pubkey": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let user = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap();
        match user {
            Some(user) => Some((user.nonce.unwrap(), user.pubkey.unwrap())),
            None => None,
        }
    }

    /**
     * Queries the DB for documents where username OR pubkey matches an existing document
     * @dev used in user creation. If true, then fail to create the user
     *
     * @param username - the username to check for existence
     * @param pubkey - the pubkey to check
     * @returns - true or false if [username, pubkey] exists in d
     */
    pub async fn check_creation_params(
        &self,
        username: &String,
        pubkey: &[u8; 32],
    ) -> Result<[bool; 2], GrapevineServerError> {
        // Verify user existence
        let pubkey_binary = Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: pubkey.to_vec(),
        };
        let query = doc! {
            "$or": [
                { "username": username },
                { "pubkey": pubkey_binary }
            ]
        };
        let projection = doc! { "username": 1 };
        let find_options = FindOptions::builder().projection(projection).build();
        let mut cursor = self.users.find(query, Some(find_options)).await.unwrap();
        let mut found = [false; 2];
        while let Some(result) = cursor.next().await {
            match result {
                Ok(user) => {
                    // Check if the username matches
                    if &user.username.unwrap() == username {
                        found[0] = true;
                    }
                    // Check if the pubkey matches
                    if &user.pubkey.unwrap() == pubkey {
                        found[1] = true;
                    }
                }
                Err(e) => return Err(GrapevineServerError::MongoError(String::from("todo"))),
            }
        }

        Ok(found)
    }

    /**
     * Insert a new user into the database
     * @notice - assumes username and pubkey auth checks were already performed
     *
     * @param user - the user to insert into the database
     * @param auth_secret - the encrypted auth secret used by this user
     * @returns - an error if the user already exists, or Ok otherwise
     */
    pub async fn create_user(&self, user: User) -> Result<ObjectId, GrapevineServerError> {
        // check if the username exists already in the database
        let query = doc! { "username": &user.username };
        let options = FindOneOptions::builder()
            .projection(doc! {"_id": 1})
            .build();
        match self.users.find_one(query, options).await.unwrap() {
            Some(_) => {
                return Err(GrapevineServerError::UserExists(
                    user.username.clone().unwrap(),
                ))
            }
            None => (),
        };

        // insert the user into the collection
        match self.users.insert_one(&user, None).await {
            Ok(result) => Ok(result.inserted_id.as_object_id().unwrap()),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
    }

    pub async fn get_user(&self, username: &String) -> Option<User> {
        let filter = doc! { "username": username };
        let projection = doc! { "degree_proofs": 0 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        self.users
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
    }

    pub async fn get_pubkey(&self, username: String) -> Option<[u8; 32]> {
        let filter = doc! { "username": username };
        let projection = doc! { "pubkey": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let user = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap();
        match user {
            Some(user) => {
                println!("User: {:?}", user);
                println!("user: {:?}", user.pubkey.unwrap());
                Some(user.pubkey.unwrap())
            }
            None => None,
        }
    }

    pub async fn add_relationship(
        &self,
        relationship: &Relationship,
    ) -> Result<ObjectId, GrapevineServerError> {
        // create new relationship document
        let relationship_oid = self
            .relationships
            .insert_one(relationship, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();
        // push the relationship to the user's list of relationships
        let query = doc! { "_id": relationship.recipient };
        let update =
            doc! { "$push": { "relationships": bson::to_bson(&relationship_oid).unwrap()} };
        self.users.update_one(query, update, None).await.unwrap();
        Ok(relationship_oid)
    }

    pub async fn add_proof(
        &self,
        user: &ObjectId,
        proof: &DegreeProof,
    ) -> Result<ObjectId, GrapevineServerError> {
        // check if an existing proof in this chain exists for the user
        // todo: make this not ugly
        let phrase_hash_bson: Vec<i32> = proof
            .phrase_hash
            .unwrap()
            .to_vec()
            .iter()
            .map(|x| *x as i32)
            .collect();

        // let query = doc! { "user": user, "phrase_hash":  phrase_hash_bson.clone() };
        // let update = doc! { "$set": { "inactive": true } };
        // let projection = doc! { "_id": 1 };
        // let options = FindOneAndUpdateOptions::builder()
        //     .projection(projection)
        //     .build();

        // // If old degree proof exists it will be removed if it is the lowest in the chain, this will then
        // // be repeated up the chain as long as a proof has no proofs that proceed it. If a proof has proceeding
        // // proofs then it will simply be marked as inactive
        // let oid = match self
        //     .degree_proofs
        //     .find_one_and_update(query, update, Some(options))
        //     .await
        //     .unwrap()
        // {
        //     Some(document) => document.id,
        //     None => None,
        // };

        let mut proof_chain: Vec<DegreeProof> = vec![];
        // fetch all proofs preceding this one
        let mut cursor = self
            .degree_proofs
            .aggregate(
                vec![
                    doc! {
                      "$match": {
                        "user": user,
                        "phrase_hash": phrase_hash_bson.clone()
                      }
                    },
                    doc! {
                      "$graphLookup": {
                        "from": "degree_proofs",
                        "startWith": "$preceding", // Assuming 'preceding' is a field that points to the parent document
                        "connectFromField": "preceding",
                        "connectToField": "_id",
                        "as": "preceding_chain",
                      }
                    },
                    doc! {
                        "$project": {
                            "_id": 1,
                            "degree": 1,
                            "inactive": 1,
                            "preceding": 1,
                            "proceeding": 1,
                            "preceding_chain": {
                                "$map": {
                                    "input": "$preceding_chain",
                                    "as": "chain",
                                    "in": {
                                        "_id": "$$chain._id",
                                        "degree": "$$chain.degree",
                                        "inactive": "$$chain.inactive",
                                        "preceding": "$$chain.preceding",
                                        "proceeding": "$$chain.proceeding",
                                    }
                                }
                            }
                        }
                    },
                ],
                None,
            )
            .await
            .unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let preceding_chain = document.get("preceding_chain");
                    let mut parsed: Vec<DegreeProof> = vec![];
                    if preceding_chain.is_some() {
                        parsed =
                            bson::from_bson::<Vec<DegreeProof>>(preceding_chain.unwrap().clone())
                                .unwrap();
                    }
                    let base_proof = bson::from_document::<DegreeProof>(document).unwrap();
                    proof_chain.push(base_proof);
                    proof_chain.append(&mut parsed);
                }
                Err(e) => println!("Error: {}", e),
            }
        }

        // Sort by degrees
        proof_chain.sort_by(|a, b| b.degree.cmp(&a.degree));

        let mut delete_entities: Vec<ObjectId> = vec![];
        // Tuple containing object id, inactive status, updated proceeding array
        let mut update_entitity: (ObjectId, bool, ObjectId) =
            (ObjectId::new(), false, ObjectId::new());

        // There may be multiple delete values but there will always be one update
        let mut index = 0;

        while index < proof_chain.len() {
            let proof = proof_chain.get(index).unwrap();
            let empty_proceeding =
                proof.proceeding.is_none() || proof.proceeding.clone().unwrap().is_empty();

            // If proceeding isn't empty on base proof we simply flag it as inactive and exit
            if index == 0 && !empty_proceeding {
                update_entitity.0 = proof.id.unwrap();
                update_entitity.1 = true;

                // Make loop exit
                index = proof_chain.len();
            } else {
                if empty_proceeding && (index == 0 || proof.inactive.unwrap()) {
                    delete_entities.push(proof.id.unwrap());
                    // Remove from preceding proof's proceeding vec
                    let next_proof = proof_chain.get(index + 1).unwrap();
                    let mut next_proceeding = next_proof.proceeding.clone().unwrap();
                    let pos = next_proceeding
                        .iter()
                        .position(|&x| x == proof.id.unwrap())
                        .unwrap();

                    update_entitity.0 = next_proof.id.unwrap();
                    update_entitity.2 = next_proceeding.remove(pos);

                    proof_chain[index + 1].proceeding = Some(next_proceeding);
                    index += 1;
                // When we reach the last inactive proof we can end the loop
                } else {
                    index = proof_chain.len();
                }
            }
        }

        // let oid = proof_chain[0].id;

        // Delete documents if not empty
        if !delete_entities.is_empty() {
            let filter = doc! {
                "_id": {"$in": delete_entities} // Match documents whose IDs are in the provided list
            };
            self.degree_proofs
                .delete_many(filter, None)
                .await
                .expect("Error deleting degree proofs");
        }

        // Update document
        let update_filter = doc! {"_id": update_entitity.0};
        let mut update = doc! {};
        if update_entitity.1 {
            update = doc! {"$set": { "inactive": true }};
        } else {
            update = doc! {"$pull": { "proceeding": update_entitity.2 }};
        }
        self.degree_proofs
            .update_one(update_filter, update, None)
            .await
            .expect("Error updating degree proof");
        // for i in 0..proof_chain.len() - 1 {
        //     // Base proof will always be marked as inactive
        //     let inactive = proof_chain[i].inactive.unwrap() || i == 0;

        //     let proceeding = proof_chain[i].proceeding.clone();

        //     // Check if proof can be deleted
        //     let can_delete =
        //         (!proceeding.is_some() || proceeding.clone().unwrap().is_empty()) && inactive;

        //     if can_delete {
        //         delete_entities.push(proof_chain[i].id.unwrap());
        //         // If proof is deleted then remove it from proceeding array in next proof
        //         let pos = proo
        //             .iter()
        //             .position(|&doc| doc == proof_chain[i].id.unwrap());
        //         update_entities.push((Some(inactive), proceeding));
        //         proof_chain[i].id.unwrap()
        //     } else {
        //         // @todo: Can we tweak this? update entities will always be inactive except in first case
        //         update_entities.push((Some(inactive), proceeding));
        //     }
        // }

        // create new proof document
        let proof_oid = self
            .degree_proofs
            .insert_one(proof, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();

        // reference this proof in previous proof if not first proof in chain
        if proof.preceding.is_some() {
            let query = doc! { "_id": proof.preceding.unwrap() };
            let update = doc! { "$push": { "proceeding": bson::to_bson(&proof_oid).unwrap()} };
            self.degree_proofs
                .update_one(query, update, None)
                .await
                .unwrap();
        }

        // push the proof to the user's list of proofs
        let query = doc! { "_id": user };
        let update = doc! {"$push": { "degree_proofs": bson::to_bson(&proof_oid).unwrap()}};
        self.users
            .update_one(query.clone(), update, None)
            .await
            .unwrap();

        // If a proof is marked inactive
        // if oid.is_some() {
        //     let update = doc! { "$pull": { "degree_proofs": oid.unwrap() } };
        //     self.users.update_one(query, update, None).await.unwrap();
        // }
        Ok(proof_oid)
    }

    pub async fn get_proof(&self, proof_oid: &ObjectId) -> Option<DegreeProof> {
        self.degree_proofs
            .find_one(doc! { "_id": proof_oid }, None)
            .await
            .unwrap()
    }

    pub async fn remove_user(&self, user: &ObjectId) {
        self.users
            .delete_one(doc! { "_id": user }, None)
            .await
            .expect("Failed to remove user");
    }

    /**
     * Given a user, find available degrees of separation proofs they can build from
     *   - find degree chains they are not a part of
     *   - find lower degree proofs they can build from
     */
    pub async fn find_available_degrees(&self, username: String) -> Vec<String> {
        // find degree chains they are not a part of
        let pipeline = vec![
            // find the user to find available proofs for
            doc! { "$match": { "username": username } },
            doc! { "$project": { "relationships": 1, "degree_proofs": 1, "_id": 0 } },
            // look up the degree proofs made by this user
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "degree_proofs",
                    "foreignField": "_id",
                    "as": "userDegreeProofs",
                    "pipeline": [doc! { "$project": { "degree": 1, "phrase_hash": 1 } }]
                }
            },
            // look up the relationships made by this user
            doc! {
                "$lookup": {
                    "from": "relationships",
                    "localField": "relationships",
                    "foreignField": "_id",
                    "as": "userRelationships",
                    "pipeline": [doc! { "$project": { "sender": 1 } }]
                }
            },
            // look up the degree proofs made by relationships
            // @todo: allow limitation of degrees of separation here
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "userRelationships.sender",
                    "foreignField": "user",
                    "as": "relationshipDegreeProofs",
                    "pipeline": [
                        doc! { "$match": { "inactive": { "$ne": true } } },
                        doc! { "$project": { "degree": 1, "phrase_hash": 1 } }
                    ]
                }
            },
            // unwind the results
            doc! { "$project": { "userDegreeProofs": 1, "relationshipDegreeProofs": 1 } },
            doc! { "$unwind": "$relationshipDegreeProofs" },
            // find the lowest degree proof in each chain from relationship proofs and reference user proofs in this chain if exists
            doc! {
                "$group": {
                    "_id": "$relationshipDegreeProofs.phrase_hash",
                    "originalId": { "$first": "$relationshipDegreeProofs._id" },
                    "degree": { "$min": "$relationshipDegreeProofs.degree" },
                    "userProof": {
                        "$first": {
                            "$arrayElemAt": [{
                                "$filter": {
                                    "input": "$userDegreeProofs",
                                    "as": "userProof",
                                    "cond": { "$eq": ["$$userProof.phrase_hash", "$relationshipDegreeProofs.phrase_hash"] }
                                }
                            }, 0]
                        }
                    }
                }
            },
            // remove the proofs that do not offer improved degrees of separation from existing user proofs
            doc! {
                "$match": {
                    "$expr": {
                        "$or": [
                            { "$gte": ["$userProof.degree", { "$add": ["$degree", 2] }] },
                            { "$eq": ["$userProof", null] }
                        ]
                    }
                }
            },
            // project only the ids of the proofs the user can build from
            doc! { "$project": { "_id": "$originalId" } },
        ];
        // get the OID's of degree proofs the user can build from
        let mut proofs: Vec<String> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let oid = document
                        .get("_id")
                        .and_then(|id| id.as_object_id())
                        .unwrap();
                    proofs.push(oid.to_string());
                }
                Err(e) => println!("Error: {}", e),
            }
        }

        proofs
    }

    pub async fn pipeline_test(&self, username: String) -> Vec<String> {
        // find degree chains they are not a part of
        let pipeline = vec![
            // find the user to find available proofs for
            doc! { "$match": { "username": username } },
            doc! { "$project": { "relationships": 1, "degree_proofs": 1, "_id": 0 } },
            // look up the degree proofs made by this user
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "degree_proofs",
                    "foreignField": "_id",
                    "as": "userDegreeProofs",
                    "pipeline": [doc! { "$project": { "degree": 1, "phrase_hash": 1 } }]
                }
            },
            // look up the relationships made by this user
            doc! {
                "$lookup": {
                    "from": "relationships",
                    "localField": "relationships",
                    "foreignField": "_id",
                    "as": "userRelationships",
                    "pipeline": [doc! { "$project": { "sender": 1 } }]
                }
            },
            // look up the degree proofs made by relationships
            // @todo: allow limitation of degrees of separation here
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "userRelationships.sender",
                    "foreignField": "user",
                    "as": "relationshipDegreeProofs",
                    "pipeline": [
                        doc! { "$match": { "inactive": { "$ne": true } } },
                        doc! { "$project": { "degree": 1, "phrase_hash": 1 } }
                    ]
                }
            },
            // unwind the results
            doc! { "$project": { "userDegreeProofs": 1, "relationshipDegreeProofs": 1 } },
            doc! { "$unwind": "$relationshipDegreeProofs" },
            // find the lowest degree proof in each chain from relationship proofs and reference user proofs in this chain if exists
            doc! {
                "$group": {
                    "_id": "$relationshipDegreeProofs.phrase_hash",
                    "originalId": { "$first": "$relationshipDegreeProofs._id" },
                    "degree": { "$min": "$relationshipDegreeProofs.degree" },
                    "userProof": {
                        "$first": {
                            "$arrayElemAt": [{
                                "$filter": {
                                    "input": "$userDegreeProofs",
                                    "as": "userProof",
                                    "cond": { "$eq": ["$$userProof.phrase_hash", "$relationshipDegreeProofs.phrase_hash"] }
                                }
                            }, 0]
                        }
                    }
                }
            },
        ];
        // get the OID's of degree proofs the user can build from
        let mut proofs: Vec<String> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        // let count = cursor.count().await;
        // println!("Count: {}", count);
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    for key in document.keys() {
                        println!("{}", key);
                    }
                    // let oid = document
                    //     .get("_id")
                    //     .and_then(|id| id.as_object_id())
                    //     .unwrap();
                    // proofs.push(oid.to_string());
                    println!("Document: {:?}\n\n", document);
                    // println!("ID: {:?}", oid);
                }
                Err(e) => println!("Error: {}", e),
            }
        }

        proofs
    }

    // @todo: ask chatgpt for better name
    pub async fn get_all_degrees(&self, username: String) -> Option<Vec<DegreeData>> {
        let pipeline = vec![
            // get the user to find the proofs of degrees of separation for the user
            doc! { "$match": { "username": username } },
            doc! { "$project": { "_id": 1, "degree_proofs": 1 } },
            // look up the degree proof documents
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "degree_proofs",
                    "foreignField": "_id",
                    "as": "proofs",
                    "pipeline": [doc! { "$project": { "degree": 1, "preceding": 1, "phrase_hash": 1 } }]
                }
            },
            doc! { "$unwind": "$proofs" },
            doc! {
                "$project": {
                    "degree": "$proofs.degree",
                    "preceding": "$proofs.preceding",
                    "phrase_hash": "$proofs.phrase_hash",
                    "_id": 0
                }
            },
            // get the preceding proof if it exists, then get the user who made it to show the connection
            doc! {
                "$lookup": {
                    "from": "degree_proofs",
                    "localField": "preceding",
                    "foreignField": "_id",
                    "as": "relation",
                    "pipeline": [doc! { "$project": { "user": 1, "_id": 0 } }]
                }
            },
            doc! {
                "$project": {
                    "degree": 1,
                    "preceding": 1,
                    "phrase_hash": 1,
                    "relation": { "$arrayElemAt": ["$relation.user", 0] },
                    "_id": 0
                }
            },
            doc! {
                "$lookup": {
                    "from": "users",
                    "localField": "relation",
                    "foreignField": "_id",
                    "as": "relation",
                    "pipeline": [doc! { "$project": { "_id": 0, "username": 1 } }]
                }
            },
            doc! {
                "$project": {
                    "degree": 1,
                    "phrase_hash": 1,
                    "relation": { "$arrayElemAt": ["$relation.username", 0] },
                    "_id": 0
                }
            },
            doc! { "$sort": { "degree": 1 }},
        ];
        // get the OID's of degree proofs the user can build from
        let mut degrees: Vec<DegreeData> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let degree = document.get_i32("degree").unwrap() as u8;
                    let relation = match document.get("relation") {
                        Some(relation) => Some(relation.as_str().unwrap().to_string()),
                        None => None,
                    };
                    // @todo: can this be retrieved better?
                    let phrase_hash: [u8; 32] = document
                        .get("phrase_hash")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_i32().unwrap() as u8)
                        .collect::<Vec<u8>>()
                        .try_into()
                        .unwrap();
                    let originator = document.get_str("originator").unwrap();
                    degrees.push(DegreeData {
                        degree,
                        relation,
                        phrase_hash,
                    });
                }
                Err(e) => return None,
            }
        }
        Some(degrees)
    }

    // used by passing args hash to check if existing phrase hash exists and deletes it
    // pub async fn delete_proof(&self, user: oid: ObjectId) -> Result<(), GrapevineServerError> {
    //     // delete the proof document
    //     let query = doc! { "_id": oid };
    //     let res = self.degree_proofs.delete_one(query, None).await.unwrap();
    //     match res.deleted_count {
    //         1 => Ok(()),
    //         _ => Err(GrapevineServerError::MongoError(String::from("todo"))),
    //     }
    //     // @todo: removing the proof will break downstream proof chains. This must be handled. Potentially we just delete downstream proofs and make them reprove?
    //     // remove the reference to the proof in the user's list of proofs
    //     let
    // }

    /**
     * Get a proof from the server with all info needed to prove a degree of separation as a given user
     *
     * @param username - the username of the user proving a degree of separation
     * @param oid - the id of the proof to get
     */
    pub async fn get_proof_and_data(
        &self,
        username: String,
        proof: ObjectId,
    ) -> Option<ProvingData> {
        // @todo: aggregation pipeline
        // get the proof
        let filter = doc! { "_id": proof };
        let projection = doc! { "user": 1, "degree": 1, "proof": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        println!("getting proof {:?}", proof);
        let proof = self
            .degree_proofs
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
            .unwrap();
        // get the username of the user who made the proof
        let proof_creator = proof.user.unwrap();
        let filter = doc! { "_id": proof_creator };
        let projection = doc! { "username": 1, "pubkey": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        println!("proof creator: {:?}", proof_creator);
        let proof_creator_username = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
            .unwrap()
            .username
            .unwrap();
        println!("got proof creator");
        // get the oid of message sender
        let filter = doc! { "username": username };
        let projection = doc! { "_id": 1, "pubkey": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let caller = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
            .unwrap()
            .id
            .unwrap();
        println!("got caller");
        // look up relationship with sender and recipient
        let filter = doc! { "sender": proof_creator, "recipient": caller };
        let projection = doc! { "ephemeral_key": 1, "ciphertext": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let relationship = self
            .relationships
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
            .unwrap();
        println!("got relationship");
        // return the proof data
        Some(ProvingData {
            degree: proof.degree.unwrap(),
            proof: proof.proof.unwrap(),
            username: proof_creator_username,
            ephemeral_key: relationship.ephemeral_key.unwrap(),
            ciphertext: relationship.ciphertext.unwrap(),
        })
    }

    /**
     * Get chain of degree proofs linked to a phrase
     *
     * @param phrase_hash - hash of the phrase linking the proof chain together
     */
    pub async fn get_proof_chain(&self, phrase_hash: &str) -> Vec<DegreeProof> {
        let mut proofs: Vec<DegreeProof> = vec![];
        let query = doc! { "phrase_hash": phrase_hash };
        let projection = doc! { "_id":1, "degree": 1 };
        let find_options = FindOptions::builder().projection(projection).build();
        let mut cursor = self.degree_proofs.find(query, find_options).await.unwrap();

        while let Some(result) = cursor.next().await {
            match result {
                Ok(proof) => {
                    proofs.push(proof);
                }
                Err(e) => println!("Error: {:?}", e),
            }
        }
        proofs
    }
}
