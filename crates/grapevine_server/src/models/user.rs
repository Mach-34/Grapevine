use mongodb::bson::oid::ObjectId;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub username: String,
    pub pubkey: [u8; 32],
    pub auth_secret: AuthSecretEncrypted,
}