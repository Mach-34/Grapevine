use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DegreeProof {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub inactive: Option<bool>,
    pub phrase_hash: Option<[u8; 32]>, // @todo: maybe track phrases?
    pub auth_hash: Option<[u8; 32]>,
    pub degree: Option<u8>,
    pub user: Option<ObjectId>,
    #[serde(default, with = "serde_bytes")]
    pub secret_phrase: Option<[u8; 192]>, // encrypted phrase
    #[serde(default, with = "serde_bytes")]
    pub proof: Option<Vec<u8>>, // compressed proof
    pub preceding: Option<ObjectId>, // the proof that this proof is built on (null if first)
    pub proceeding: Option<Vec<ObjectId>>, // proofs that are built on top of this proof
}

// all data needed from server to prove a degree of separation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProvingData {
    pub degree: u8, // multiply by 2 to get iterations
    pub proof: Vec<u8>,
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 48],
}
