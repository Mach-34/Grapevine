use crate::{DATABASE, MONGODB_URI};
use futures::stream::StreamExt;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::errors::GrapevineServerError;
use grapevine_common::models::proof::ProvingData;
use grapevine_common::models::{proof::DegreeProof, relationship::Relationship, user::User};
use mongodb::bson::{self, doc, oid::ObjectId, Binary};
use mongodb::options::{
    AggregateOptions, ClientOptions, FindOneOptions, FindOptions, ServerApi, ServerApiVersion,
};
use mongodb::{Client, Collection};

pub struct GrapevineDB {
    users: Collection<User>,
    relationships: Collection<Relationship>,
    degree_proofs: Collection<DegreeProof>,
}

impl GrapevineDB {
    pub async fn init() -> Self {
        let mut client_options = ClientOptions::parse(MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();
        let db = client.database(DATABASE);
        let users = db.collection("users");
        let relationships = db.collection("relationships");
        let degree_proofs = db.collection("degree_proofs");
        Self {
            users,
            relationships,
            degree_proofs,
        }
    }

    pub async fn increment_nonce(&self, username: &str) {
        let filter = doc! { "username": username };
        let update = doc! { "$inc": { "nonce": 1 } };
        self.users
            .update_one(filter, update, None)
            .await
            .expect("Error incrementing nonce");
    }

    pub async fn get_nonce(&self, username: &str) -> u64 {
        // Verify user existence
        let filter = doc! { "username": username };
        let projection = doc! { "nonce": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let user = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap();
        match user {
            Some(user) => user.nonce.unwrap(),
            None => 0,
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

    pub async fn get_user(&self, username: String) -> Option<User> {
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
        let uuid = self
            .users
            .insert_one(&user, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();

        Ok(uuid)
    }

    pub async fn add_proof(
        &self,
        user: &ObjectId,
        proof: &DegreeProof,
    ) -> Result<ObjectId, GrapevineServerError> {
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
        let update = doc! { "$push": { "degree_proofs": bson::to_bson(&proof_oid).unwrap()} };
        self.users.update_one(query, update, None).await.unwrap();
        Ok(proof_oid)
    }

    pub async fn get_proof(&self, proof_oid: &ObjectId) -> Option<DegreeProof> {
        self.degree_proofs
            .find_one(doc! { "_id": proof_oid }, None)
            .await
            .unwrap()
    }

    /**
     * Given a user, find available degrees of separation proofs they can build from
     *   - find degree chains they are not a part of
     *   - find lower degree proofs they can build from
     */
    pub async fn find_available_degrees(&self, username: String) -> Vec<ObjectId> {
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
                    "pipeline": [doc! { "$project": { "degree": 1, "phrase_hash": 1 } }]
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
        let mut proofs: Vec<ObjectId> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let oid = document
                        .get("_id")
                        .and_then(|id| id.as_object_id())
                        .unwrap();
                    proofs.push(oid);
                }
                Err(e) => println!("Error: {}", e),
            }
        }

        proofs
    }

    // (username, ephemeral_key, ciphertext)
    // todo: modify auth secret to work with this

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
        let projection = doc! { "username": 1 };
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
        let projection = doc! { "_id": 1 };
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
}
