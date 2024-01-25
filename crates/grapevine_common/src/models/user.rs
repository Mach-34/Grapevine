use crate::auth_secret::AuthSecretEncrypted;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub nonce: u64,
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub pubkey: [u8; 32],
    pub connections: Option<Vec<Connection>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Connection {
    pub user: ObjectId,
    pub auth_secret: ObjectId,
}
