use crate::serde::{deserialize_byte_buf, serialize_byte_buf};
use serde::{Deserialize, Serialize};
use crate::auth_secret::AuthSecretEncrypted;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String,
    pub pubkey: [u8; 32],
    #[serde(
        serialize_with = "serialize_byte_buf",
        deserialize_with = "deserialize_byte_buf"
    )]
    pub signature: [u8; 64],
    pub auth_secret: AuthSecretEncrypted,
}
