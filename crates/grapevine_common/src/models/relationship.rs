use crate::auth_secret::AuthSecretEncrypted;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relationship {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub recipient: Option<ObjectId>, // use this privkey to decrypt
    pub sender: Option<ObjectId>,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: Option<[u8; 32]>,
    #[serde(with = "serde_bytes")]
    pub ciphertext: Option<[u8; 48]>,
}