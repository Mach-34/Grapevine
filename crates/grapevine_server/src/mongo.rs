use crate::{DATABASE_NAME, MONGODB_URI};
use futures::stream::StreamExt;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::proof::ProvingData;
use grapevine_common::models::{proof::DegreeProof, relationship::Relationship, user::User};
use mongodb::bson::Bson;
use mongodb::bson::{self, doc, oid::ObjectId, Binary};
use mongodb::options::{ClientOptions, FindOneOptions, FindOptions, ServerApi, ServerApiVersion};
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

    pub async fn increment_nonce(&self, username: &str) -> Result<(), GrapevineServerError> {
        let filter = doc! { "username": username };
        let update = doc! { "$inc": { "nonce": 1 } };
        match self.users.update_one(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
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
        let projection = doc! { "username": 1, "pubkey": 1 };
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
                Err(e) => return Err(GrapevineServerError::MongoError(e.to_string())),
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
        // @TODO: check to see whether relation already exists between the two users

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
        match self.users.update_one(query, update, None).await {
            Ok(_) => Ok(relationship_oid),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
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

        // If a proof is marked inactive then remove from user's list of degree proofs
        if update_entitity.1 {
            let update = doc! { "$pull": { "degree_proofs": update_entitity.0 } };
            self.users.update_one(query, update, None).await.unwrap();
        }
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

    /**
     * Get all degree proofs created by a specific user
     */
    pub async fn get_created(&self, username: String) -> Option<Vec<DegreeData>> {
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
                    "pipeline": [doc! { "$project": { "degree": 1, "secret_phrase": 1, "phrase_hash": 1 } }]
                }
            },
            doc! {
                "$project": {
                    "proofs": {
                        "$filter": {
                          "input": "$proofs",
                          "as": "proof",
                          "cond": { "$eq": ["$$proof.degree", 1] }
                        }
                    },
                }
            },
            doc! { "$unwind": "$proofs" },
            doc! {
                "$project": {
                    "degree": "$proofs.degree",
                    "secret_phrase": "$proofs.secret_phrase",
                    "phrase_hash": "$proofs.phrase_hash",
                    "_id": 0
                }
            },
        ];
        // get the OID's of degree proofs the user can build from
        let mut degrees: Vec<DegreeData> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
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
                    // get secret phrase is included
                    let mut secret_phrase: Option<[u8; 192]> = None;
                    if let Some(Bson::Binary(binary)) = document.get("secret_phrase") {
                        secret_phrase = Some(binary.bytes.clone().try_into().unwrap());
                    }
                    degrees.push(DegreeData {
                        degree: 1,
                        relation: None,
                        preceding_relation: None,
                        phrase_hash,
                        secret_phrase,
                    });
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return None;
                }
            }
        }
        Some(degrees)
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
            doc! {
                "$project": {
                    "proofs": {
                        "$filter": {
                          "input": "$proofs",
                          "as": "proof",
                          "cond": { "$gt": ["$$proof.degree", 1] }
                        }
                    },
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
                    "pipeline": [doc! { "$project": { "preceding": 1, "user": 1, "_id": 0 } }]
                }
            },
            doc! {
                "$project": {
                    "degree": 1,
                    "preceding": 1,
                    "phrase_hash": 1,
                    "relation": { "$arrayElemAt": ["$relation.user", 0] },
                    "precedingRelation": { "$arrayElemAt": ["$relation.preceding", 0] },
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
                    "precedingRelation": 1,
                    "_id": 0
                }
            },
            // Lookup preceding relation. Will be none if degree is 2 or less
            doc! {
              "$lookup": {
                "from": "degree_proofs",
                "localField": "precedingRelation",
                "foreignField": "_id",
                "as": "precedingRelation",
                "pipeline": [doc! { "$project": { "user": 1, "_id": 0 } }]
              },
            },
            doc! {
                "$project": {
                    "degree": 1,
                    "phrase_hash": 1,
                    "relation": 1,
                    "precedingRelation": { "$arrayElemAt": ["$precedingRelation.user", 0] },
                }
            },
            doc! {
                "$lookup": {
                    "from": "users",
                    "localField": "precedingRelation",
                    "foreignField": "_id",
                    "as": "precedingRelation",
                    "pipeline": [doc! { "$project": { "_id": 0, "username": 1 } }]
                }
            },
            doc! {
                "$project": {
                    "degree": 1,
                    "phrase_hash": 1,
                    "relation": 1,
                    "precedingRelation": { "$arrayElemAt": ["$precedingRelation.username", 0] },
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
                    println!("Document: {:?}", document);
                    let degree = document.get_i32("degree").unwrap() as u8;
                    let relation = document
                        .get("relation")
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_string();
                    let preceding_relation = match document.get("precedingRelation") {
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
                    degrees.push(DegreeData {
                        degree,
                        relation: Some(relation),
                        preceding_relation,
                        phrase_hash,
                        secret_phrase: None,
                    });
                }
                Err(e) => {
                    println!("Error: {}", e);
                    return None;
                }
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
    * Get details on account:
       - # of first degree connections
       - # of second degree connections
       - # of phrases created
    */
    pub async fn get_account_details(&self, user: &ObjectId) -> Option<(u64, u64, u64)> {
        let mut cursor = self
            .users
            .aggregate(
                vec![
                    doc! {
                      "$match": {
                        "_id": user
                      }
                    },
                    // Lookup to join with the relationships collection
                    doc! {
                        "$lookup": {
                            "from": "relationships",
                            "localField": "relationships",
                            "foreignField": "_id",
                            "as": "relationships_data",
                            "pipeline": [doc! { "$project": { "_id": 0, "sender": 1 } }]
                        }
                    },
                    // Add sender values to first degree connection array
                    doc! {
                        "$addFields": {
                            "first_degree_connections": {
                                "$map": {
                                    "input": "$relationships_data",
                                    "as": "relationship",
                                    "in": "$$relationship.sender"
                                }
                            }
                        }
                    },
                    // Lookup first degree connection senders from users colection
                    doc! {
                        "$lookup": {
                            "from": "users",
                            "localField": "first_degree_connections",
                            "foreignField": "_id",
                            "as": "sender_relationships"
                        }
                    },
                    doc! {
                        "$unwind": {
                            "path": "$sender_relationships",
                            "preserveNullAndEmptyArrays": true
                        }
                    },
                    doc! {
                        "$lookup": {
                            "from": "relationships",
                            "localField": "sender_relationships.relationships",
                            "foreignField": "_id",
                            "as": "sender_relationships.relationships_data"
                        }
                    },
                    doc! {
                        "$group": {
                            "_id": "$_id",
                            "first_degree_connections": { "$first": "$first_degree_connections" },
                            "sender_relationships": { "$push": "$sender_relationships" }
                        }
                    },
                    doc! {
                        "$addFields": {
                            "second_degree_connections": {
                                "$cond": {
                                    "if": { "$eq": [ "$sender_relationships", [] ] },
                                    "then": [],
                                    "else": {
                                        "$reduce": {
                                            "input": "$sender_relationships",
                                            "initialValue": [],
                                            "in": {
                                                "$concatArrays": [
                                                    "$$value",
                                                    {
                                                        "$filter": {
                                                            "input": {
                                                                "$map": {
                                                                    "input": "$$this.relationships_data",
                                                                    "as": "relationship",
                                                                    "in": {
                                                                        "$cond": [
                                                                            {
                                                                                "$and": [
                                                                                    { "$ne": [ "$$relationship.sender", null ] },
                                                                                    { "$ne": [ "$$relationship.sender", user ] },
                                                                                    { "$not": { "$in": [ "$$relationship.sender", "$first_degree_connections" ] } },
                                                                                    { "$not": { "$in": [ "$$relationship.sender", "$$value" ] } }
                                                                                ]
                                                                            },
                                                                            "$$relationship.sender",
                                                                            null
                                                                        ]
                                                                    }
                                                                }
                                                            },
                                                            "cond": { "$ne": [ "$$this", null ] }
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    doc! {
                        "$addFields": {
                            "second_degree_connections": {
                                "$setUnion": ["$second_degree_connections", []]
                            }
                        }
                    },
                    doc! {
                        "$lookup": {
                            "from": "degree_proofs",
                            "localField": "_id",
                            "foreignField": "user",
                            "as": "user_degrees"
                        }
                    },
                    doc! {
                        "$addFields": {
                            "phrase_count": {
                                "$size": {
                                    "$filter": {
                                        "input": "$user_degrees",
                                        "as": "degree",
                                        "cond": { "$eq": ["$$degree.degree", 1] }
                                    }
                                }
                            }
                        }
                    },
                    doc! {
                        "$project": {
                            "phrase_count": 1,
                            "first_degree_connections": { "$size": "$first_degree_connections" },
                            "second_degree_connections": { "$size": "$second_degree_connections" },
                            "second_degree_connections_all":  "$second_degree_connections",
                            "first_degree_connections_all":  "$first_degree_connections"
                        }
                    }
                ],
                None,
            )
            .await
            .unwrap();

        match cursor.next().await.unwrap() {
            Ok(stats) => {
                let phrase_count = stats.get_i32("phrase_count").unwrap();
                let first_degree_connections = stats.get_i32("first_degree_connections").unwrap();
                let second_degree_connections = stats.get_i32("second_degree_connections").unwrap();
                return Some((
                    phrase_count as u64,
                    first_degree_connections as u64,
                    second_degree_connections as u64,
                ));
            }
            Err(e) => {
                println!("Error: {:?}", e);
                return None;
            }
        }
    }

    /**
     * Get chain of degree proofs linked to a phrase
     *
     * @param phrase_hash - hash of the phrase linking the proof chain together
     */
    pub async fn get_phrase_connections(
        &self,
        username: String,
        phrase_hash: [u8; 32],
    ) -> Option<(u64, Vec<u64>)> {
        let phrase_hash_bson: Vec<i32> = phrase_hash.to_vec().iter().map(|x| *x as i32).collect();

        let mut cursor = self
            .users
            .aggregate(
                vec![
                    doc! {
                        "$match": {
                            "username": username
                        }
                    },
                    doc! {
                        "$unwind": "$relationships"
                    },
                    doc! {
                        "$lookup": {
                            "from": "relationships",
                            "localField": "relationships",
                            "foreignField": "_id",
                            "as": "relationship_details"
                        }
                    },
                    doc! {
                        "$unwind": "$relationship_details"
                    },
                    doc! {
                        "$group": {
                            "_id": null,
                            "senders": {
                                "$addToSet": "$relationship_details.sender"
                            }
                        }
                    },
                    doc! {
                        "$project": {
                            "_id": 0,
                            "senders": 1
                        }
                    },
                    doc! {
                        "$lookup": {
                            "from": "degree_proofs",
                            "let": {"senders": "$senders"},
                            "pipeline": [
                                doc! {
                                    "$match": {
                                        "$expr": {
                                            "$in": ["$user", "$$senders"]
                                        },
                                        "phrase_hash": phrase_hash_bson
                                    }
                                },
                                doc! {
                                    "$project": {
                                        "_id": 0,
                                        "degree": 1
                                    }
                                }
                            ],
                            "as": "degree_proofs"
                        }
                    },
                    doc! {
                        "$unwind": "$degree_proofs"
                    },
                    doc! {
                        "$group": {
                            "_id": null,
                            "max_degree": {
                                "$max": "$degree_proofs.degree"
                            },
                            "count": {
                                "$sum": 1
                            },
                            "degrees": {
                                "$push": "$degree_proofs.degree"
                            }
                        }
                    },
                ],
                None,
            )
            .await
            .unwrap();

        let cursor_res = cursor.next().await;

        if cursor_res.is_none() {
            return Some((0, vec![]));
        }

        match cursor_res.unwrap() {
            Ok(connection_data) => {
                let total_count = connection_data.get_i32("count").unwrap();
                let max_degree = connection_data.get_i32("max_degree").unwrap();
                let mut degree_counts: Vec<u64> = vec![0; max_degree as usize];
                let degrees: Vec<i32> = connection_data
                    .get_array("degrees")
                    .unwrap()
                    .iter()
                    .map(|d| d.as_i32().unwrap())
                    .collect();
                for degree in degrees {
                    degree_counts[(degree - 1) as usize] += 1;
                }
                return Some((total_count as u64, degree_counts));
            }
            Err(e) => {
                println!("Error: {:?}", e);
                return None;
            }
        }
    }

    /**
     * Get chain of degree proofs linked to a phrase
     *
     * @param phrase_hash - hash of the phrase linking the proof chain together
     */
    pub async fn get_proof_chain(&self, phrase_hash: &str) -> Vec<DegreeProof> {
        let mut proofs: Vec<DegreeProof> = vec![];
        let query = doc! { "phrase_hash": phrase_hash };
        let projection = doc! { "_id": 1, "degree": 1 };
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

    /**
     * Check to see if degree already exists between two accounts
     *
     * @param proof - Degree proof to be inserted
     */
    pub async fn check_degree_exists(
        &self,
        proof: &DegreeProof,
    ) -> Result<bool, GrapevineServerError> {
        let query = doc! {"preceding": proof.preceding.unwrap(), "user": proof.user.unwrap()};
        let projection = doc! { "_id": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();

        match self.degree_proofs.find_one(query, find_options).await {
            Ok(res) => Ok(res.is_some()),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
    }

    /**
     * Check to see if phrase hash already exists
     *
     * @param phrase_hash - hash of the phrase linking the proof
     */
    pub async fn check_phrase_exists(
        &self,
        phrase_hash: [u8; 32],
    ) -> Result<bool, GrapevineServerError> {
        let phrase_hash_bson: Vec<i32> = phrase_hash.to_vec().iter().map(|x| *x as i32).collect();

        let query = doc! {"phrase_hash": phrase_hash_bson};
        let projection = doc! { "_id": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();

        match self.degree_proofs.find_one(query, find_options).await {
            Ok(res) => Ok(res.is_some()),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
    }

    /**
     * Check to see if a relationship already exists between two users
     *
     * @param relationship - relationship between two users
     */
    pub async fn check_relationship_exists(
        &self,
        relationship: &Relationship,
    ) -> Result<bool, GrapevineServerError> {
        let query = doc! { "recipient": relationship.recipient, "sender": relationship.sender };
        let projection = doc! { "_id": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();

        match self.relationships.find_one(query, find_options).await {
            Ok(res) => Ok(res.is_some()),
            Err(e) => Err(GrapevineServerError::MongoError(e.to_string())),
        }
    }
}
