#[derive(Debug)]
pub enum GrapevineServerError {
    Signature(String),
    UserExists(String),
    UsernameTooLong(String),
    UsernameNotAscii(String),
}

impl std::fmt::Display for GrapevineServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GrapevineServerError::Signature(msg) => write!(f, "Signature error: {}", msg),
            GrapevineServerError::UserExists(msg) => write!(f, "Username {} already exists", msg),
            GrapevineServerError::UsernameTooLong(msg) => write!(f, "Username {} is too long", msg),
            GrapevineServerError::UsernameNotAscii(msg) => write!(f, "Username {} is not ascii", msg),
        }
    }
}

impl std::error::Error for GrapevineServerError {}
