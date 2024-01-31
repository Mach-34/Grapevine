#[derive(Debug)]
pub enum GrapevineCLIError {
    Signature(String),
    UserExists(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    UserDoesNotExist(String),
    PhraseTooLong,
    ServerError(String),
    FsError(String),
    PhraseCreationProofFailed(String),
    DegreeProofFailed,
    DegreeProofVerificationFailed,
    // DegreeProofFailed,
}

impl std::fmt::Display for GrapevineCLIError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineCLIError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineCLIError::UserExists(msg) => write!(f, "Username {} already exists", msg),
            GrapevineCLIError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineCLIError::UsernameNotAscii(msg) => write!(f, "Username {} is not ascii", msg),
            GrapevineCLIError::UserDoesNotExist(msg) => write!(f, "User \"{}\" does not exist", msg),
            GrapevineCLIError::ServerError(msg) => write!(f, "Server error: {}", msg),
            GrapevineCLIError::FsError(msg) => write!(f, "Filesystem error: {}", msg),
            GrapevineCLIError::PhraseTooLong => write!(f, "Phrase must be <= 180 characters"),
            GrapevineCLIError::PhraseCreationProofFailed(msg) => write!(f, "Failed to create proof for new phrase {}", msg),
            GrapevineCLIError::DegreeProofFailed => write!(f, "Failed to create degree proof"),
            GrapevineCLIError::DegreeProofVerificationFailed => write!(f, "Failed to verify degree proof"),
        }
    }
}

impl std::error::Error for GrapevineCLIError {}
