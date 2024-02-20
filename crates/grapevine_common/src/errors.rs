use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GrapevineServerError {
    Signature(String),
    UsernameExists(String),
    UserDoesNotExist(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    PubkeyExists(String),
    UserExists(String),
    RelationshipSenderIsTarget,
    MongoError(String),
    HeaderError(String),
    InternalError,
}

impl std::fmt::Display for GrapevineServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineServerError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineServerError::UsernameExists(msg) => write!(f, "Username {} already used by another account", msg),
            GrapevineServerError::UserDoesNotExist(msg) => {
                write!(f, "Username {} does not exist", msg)
            }
            GrapevineServerError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineServerError::UsernameNotAscii(msg) => {
                write!(f, "Username {} is not ascii", msg)
            }
            GrapevineServerError::PubkeyExists(msg) => write!(f, "Pubkey {} already used by another account", msg),
            GrapevineServerError::UserExists(msg) => write!(f, "User {} already exists with the supplied pubkey", msg),
            GrapevineServerError::RelationshipSenderIsTarget => write!(f, "Relationship sender and target are the same"),
            GrapevineServerError::MongoError(msg) => write!(f, "Mongo error: {}", msg),
            GrapevineServerError::HeaderError(msg) => write!(f, "HTTP error: bad header `{}`", msg),
            GrapevineServerError::InternalError => write!(f, "Unknown internal server error"),
        }
    }
}

impl std::error::Error for GrapevineServerError {}
