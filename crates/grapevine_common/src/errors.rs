use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GrapevineServerError {
    Signature(String),
    UsernameExists(String),
    UserNotFound(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    PubkeyExists(String),
    UserExists(String),
    RelationshipExists(String, String),
    RelationshipSenderIsTarget,
    PhraseExists,
    PhraseNotFound,
    InvalidPhraseHash,
    NonceMismatch(u64, u64),
    MongoError(String),
    HeaderError(String),
    InternalError,
    SerdeError(String),
    DegreeProofExists,
    DegreeProofVerificationFailed,
}

impl std::fmt::Display for GrapevineServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineServerError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineServerError::UsernameExists(msg) => {
                write!(f, "Username {} already used by another account", msg)
            }
            GrapevineServerError::UserNotFound(msg) => {
                write!(f, "Username {} does not exist", msg)
            }
            GrapevineServerError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineServerError::UsernameNotAscii(msg) => {
                write!(f, "Username {} is not ascii", msg)
            }
            GrapevineServerError::PubkeyExists(msg) => {
                write!(f, "Pubkey {} already used by another account", msg)
            }
            GrapevineServerError::UserExists(msg) => {
                write!(f, "User {} already exists with the supplied pubkey", msg)
            }
            GrapevineServerError::RelationshipExists(sender, recipient) => {
                write!(
                    f,
                    "Relationship already exists between {} and {}",
                    sender, recipient
                )
            }
            GrapevineServerError::RelationshipSenderIsTarget => {
                write!(f, "Relationship sender and target are the same")
            }
            &GrapevineServerError::NonceMismatch(expected, actual) => write!(
                f,
                "Nonce mismatch: expected {}, got {}. Retry this call",
                expected, actual
            ),
            GrapevineServerError::PhraseExists => {
                write!(f, "This phrase has already added used by another account")
            }
            GrapevineServerError::PhraseNotFound => write!(f, "Phrase not found"),
            GrapevineServerError::MongoError(msg) => write!(f, "Mongo error: {}", msg),
            GrapevineServerError::HeaderError(msg) => write!(f, "Bad http header error: `{}`", msg),
            GrapevineServerError::InvalidPhraseHash => write!(f, "Invalid phrase hash provided"),
            GrapevineServerError::InternalError => write!(f, "Unknown internal server error"),
            GrapevineServerError::SerdeError(msg) => write!(f, "Error deserializing {}", msg),
            GrapevineServerError::DegreeProofExists => {
                write!(
                    f,
                    "Degree proof already exists between these accounts for this phrase"
                )
            }
            GrapevineServerError::DegreeProofVerificationFailed => {
                write!(f, "Failed to verify degree proof")
            }
        }
    }
}

impl std::error::Error for GrapevineServerError {}
