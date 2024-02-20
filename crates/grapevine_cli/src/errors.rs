use grapevine_common::errors::GrapevineServerError;

#[derive(Debug)]
pub enum GrapevineCLIError {
    NoInput(String),
    Signature(String),
    UserExists(String),
    UsernameExists(String),
    PubkeyExists(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    UserNotFound(String),
    RelationshipSenderIsTarget,
    NonceMismatch(u64, u64),
    PhraseTooLong,
    ServerError(String),
    FsError(String),
    PhraseCreationProofFailed(String),
    DegreeProofFailed,
    DegreeProofVerificationFailed,
    UnknownServerError,
}

impl std::fmt::Display for GrapevineCLIError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineCLIError::NoInput(msg) => write!(f, "No input: {}", msg),
            GrapevineCLIError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineCLIError::UserExists(msg) => write!(f, "User {} already exists with the same username and pubkey", msg),
            GrapevineCLIError::UsernameExists(msg) => write!(f, "Username {} is taken by another user", msg),
            GrapevineCLIError::PubkeyExists(msg) => write!(f, "Pubkey {} is taken by another user", msg),
            GrapevineCLIError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineCLIError::UsernameNotAscii(msg) => write!(f, "Username {} is not ascii", msg),
            GrapevineCLIError::UserNotFound(msg) => write!(f, "User \"{}\" does not exist", msg),
            GrapevineCLIError::RelationshipSenderIsTarget => write!(f, "Relationship sender and target are the same"),
            GrapevineCLIError::NonceMismatch(expected, actual) => write!(f, "Nonce mismatch: expected {}, got {}. Retry this call", expected, actual),
            GrapevineCLIError::ServerError(msg) => write!(f, "Server error: {}", msg),
            GrapevineCLIError::FsError(msg) => write!(f, "Filesystem error: {}", msg),
            GrapevineCLIError::PhraseTooLong => write!(f, "Phrase must be <= 180 characters"),
            GrapevineCLIError::PhraseCreationProofFailed(msg) => write!(f, "Failed to create proof for new phrase {}", msg),
            GrapevineCLIError::DegreeProofFailed => write!(f, "Failed to create degree proof"),
            GrapevineCLIError::DegreeProofVerificationFailed => write!(f, "Failed to verify degree proof"),
            GrapevineCLIError::UnknownServerError => write!(f, "Unknown server error"),
        }
    }
}

impl From<GrapevineServerError> for GrapevineCLIError {
    fn from(err: GrapevineServerError) -> GrapevineCLIError {
        match err {
            GrapevineServerError::Signature(msg) => GrapevineCLIError::Signature(msg),
            GrapevineServerError::UserExists(msg) => GrapevineCLIError::UserExists(msg),
            GrapevineServerError::UsernameExists(msg) => GrapevineCLIError::UsernameExists(msg),
            GrapevineServerError::PubkeyExists(msg) => GrapevineCLIError::PubkeyExists(msg),
            GrapevineServerError::UsernameTooLong(msg) => GrapevineCLIError::UsernameTooLong(msg),
            GrapevineServerError::UsernameNotAscii(msg) => GrapevineCLIError::UsernameNotAscii(msg),
            GrapevineServerError::UserNotFound(msg) => GrapevineCLIError::UserNotFound(msg),
            GrapevineServerError::RelationshipSenderIsTarget => GrapevineCLIError::RelationshipSenderIsTarget,
            GrapevineServerError::NonceMismatch(expected, actual) => GrapevineCLIError::NonceMismatch(expected, actual),
            _ => GrapevineCLIError::UnknownServerError,
        }
    }
}

impl std::error::Error for GrapevineCLIError {}
