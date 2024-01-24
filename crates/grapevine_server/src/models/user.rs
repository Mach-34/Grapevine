use grapevine_common::auth_secret::AuthSecretEncrypted;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub nonce: u64,
    pub username: String,
    pub pubkey: [u8; 32],
    // pub auth_secret: AuthSecretEncrypted,
}
