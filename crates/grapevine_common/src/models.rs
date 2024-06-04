use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DegreeProof {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub phrase: Option<ObjectId>, // the phrase underlying degree 0 proofs in this chain
    pub inactive: Option<bool>,
    pub auth_hash: Option<[u8; 32]>,
    pub degree: Option<u8>,
    pub user: Option<ObjectId>,
    #[serde(default, with = "serde_bytes")]
    pub ciphertext: Option<[u8; 192]>, // encrypted phrase for the given user (only used for degree 1 proofs)
    #[serde(default, with = "serde_bytes")]
    pub proof: Option<Vec<u8>>, // compressed proof
    pub preceding: Option<ObjectId>, // the proof that this proof is built on (null if first)
    pub proceeding: Option<Vec<ObjectId>>, // proofs that are built on top of this proof
}

// all data needed from server to prove a degree of separation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProvingData {
    pub phrase_index: u32,
    #[serde(default, with = "serde_bytes")]
    pub phrase_hash: [u8; 32],
    pub description: String,
    pub degree: u8, // multiply by 2 to get iterations
    pub proof: Vec<u8>,
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 80],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relationship {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub recipient: Option<ObjectId>, // use this privkey to decrypt
    pub sender: Option<ObjectId>,
    #[serde(default, with = "serde_bytes")]
    pub ephemeral_key: Option<[u8; 32]>,
    #[serde(default, with = "serde_bytes")]
    pub ciphertext: Option<[u8; 80]>,
    pub active: Option<bool>, // true if both users have accepted, false if pending
}

// All fields optional to allow projections
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub nonce: Option<u64>,
    pub username: Option<String>,
    #[serde(with = "serde_bytes")]
    pub pubkey: Option<[u8; 32]>,
    pub relationships: Option<Vec<ObjectId>>, // references to connections (includes reference to connected user + their auth signature)
    pub degree_proofs: Option<Vec<ObjectId>>, // references to degree proofs by this user
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Phrase {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub hash: Option<[u8; 32]>,      // hash of phrase
    pub index: Option<u32>,          // separate uid shown to user
    pub description: Option<String>, // text to be shown with the phrase
}
