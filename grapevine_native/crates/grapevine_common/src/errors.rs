use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GrapevineError {
    Signature(String),
    UsernameExists(String),
    UserNotFound(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    AuthSecret(String),
    PubkeyExists(String),
    UserExists(String),
    PhraseTooLong,
    NoPendingRelationship(String, String),
    PendingRelationshipExists(String, String),
    ActiveRelationshipExists(String, String),
    RelationshipSenderIsTarget,
    PhraseExists,
    PhraseNotFound,
    PhraseNotAscii,
    InvalidPhraseHash,
    NonceMismatch(u64, u64),
    MongoError(String),
    HeaderError(String),
    InternalError,
    SerdeError(String),
    DegreeProofExists,
    DegreeProofVerificationFailed,
    FsError(String),
    ArtifactError(String)
}

impl std::fmt::Display for GrapevineError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineError::UsernameExists(msg) => {
                write!(f, "Username {} already used by another account", msg)
            }
            GrapevineError::UserNotFound(msg) => {
                write!(f, "Username {} does not exist", msg)
            }
            GrapevineError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineError::UsernameNotAscii(msg) => {
                write!(f, "Username {} is not ascii", msg)
            }
            GrapevineError::AuthSecret(msg) => write!(f, "Could not parse auth secret: {}", msg),
            GrapevineError::PubkeyExists(msg) => {
                write!(f, "Pubkey {} already used by another account", msg)
            }
            GrapevineError::UserExists(msg) => {
                write!(f, "User {} already exists with the supplied pubkey", msg)
            },
            GrapevineError::PhraseTooLong => write!(f, "Phrase is too long"),
            GrapevineError::PhraseNotAscii => write!(f, "Phrase is not ascii"),
            GrapevineError::PendingRelationshipExists(sender, recipient) => {
                write!(
                    f,
                    "A pending relationship from {} to {} exists already",
                    sender, recipient
                )
            }
            GrapevineError::ActiveRelationshipExists(sender, recipient) => {
                write!(
                    f,
                    "Active relationship between {} and {} exists already",
                    sender, recipient
                )
            }
            GrapevineError::NoPendingRelationship(sender, recipient) => {
                write!(
                    f,
                    "No pending relationship exists from {} to {}",
                    sender, recipient
                )
            }
            GrapevineError::RelationshipSenderIsTarget => {
                write!(f, "Relationship sender and target are the same")
            }
            &GrapevineError::NonceMismatch(expected, actual) => write!(
                f,
                "Nonce mismatch: expected {}, got {}. Retry this call",
                expected, actual
            ),
            GrapevineError::PhraseExists => {
                write!(f, "This phrase has already added used by another account")
            }
            GrapevineError::PhraseNotFound => write!(f, "Phrase not found"),
            GrapevineError::MongoError(msg) => write!(f, "Mongo error: {}", msg),
            GrapevineError::HeaderError(msg) => write!(f, "Bad http header error: `{}`", msg),
            GrapevineError::InvalidPhraseHash => write!(f, "Invalid phrase hash provided"),
            GrapevineError::InternalError => write!(f, "Unknown internal server error"),
            GrapevineError::SerdeError(msg) => write!(f, "Error deserializing {}", msg),
            GrapevineError::DegreeProofExists => {
                write!(
                    f,
                    "Degree proof already exists between these accounts for this phrase"
                )
            }
            GrapevineError::DegreeProofVerificationFailed => {
                write!(f, "Failed to verify degree proof")
            },
            GrapevineError::FsError(msg) => write!(f, "Filesystem error: {}", msg),
            GrapevineError::ArtifactError(msg) => write!(f, "Error loading proof artifact: {}", msg),
        }
    }
}

impl std::error::Error for GrapevineError {}
