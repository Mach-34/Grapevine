#[derive(Debug)]
pub enum GrapevineCLIError {
    Signature(String),
    UserExists(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
    ServerError(String),
    FsError(String),
}

impl std::fmt::Display for GrapevineCLIError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineCLIError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineCLIError::UserExists(msg) => write!(f, "Username {} already exists", msg),
            GrapevineCLIError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineCLIError::UsernameNotAscii(msg) => write!(f, "Username {} is not ascii", msg),
            GrapevineCLIError::ServerError(msg) => write!(f, "Server error: {}", msg),
            GrapevineCLIError::FsError(msg) => write!(f, "Filesystem error: {}", msg),
        }
    }
}

impl std::error::Error for GrapevineCLIError {}
