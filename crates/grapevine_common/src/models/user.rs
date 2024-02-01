use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

// All fields optional to allow projections
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub nonce: Option<u64>,
    pub username: Option<String>,
    // TODO: Uncomment
    // #[serde(with = "serde_bytes")]
    pub pubkey: Option<[u8; 32]>,
    pub relationships: Option<Vec<ObjectId>>, // references to connections (includes reference to connected user + their auth secret)
    pub degree_proofs: Option<Vec<ObjectId>>, // references to degree proofs by this user
}
